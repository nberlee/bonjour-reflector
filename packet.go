package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type multicastPacket struct {
	packet      gopacket.Packet
	srcMAC      *net.HardwareAddr
	dstMAC      *net.HardwareAddr
	srcIP       *net.IP
	dstIP       *net.IP
	srcPort     *layers.UDPPort
	dstPort     *layers.UDPPort
	isIPv6      bool
	vlanTag     *uint16
	isDNSQuery  bool
	isSSDPQuery bool
}

func parsePacketsLazily(source *gopacket.PacketSource) chan multicastPacket {
	// Process packets, and forward Bonjour traffic to the returned channel

	// Set decoding to Lazy
	source.DecodeOptions = gopacket.DecodeOptions{Lazy: true}

	packetChan := make(chan multicastPacket, 100)

	go func() {
		for packet := range source.Packets() {
			tag := parseVLANTag(packet)

			// Get source and destination mac addresses
			srcMAC, dstMAC := parseEthernetLayer(packet)

			// Check IP protocol version
			isIPv6, srcIP, dstIP := parseIPLayer(packet)

			// Get UDP payload
			payload, srcPort, dstPort := parseUDPLayer(packet)

			isDNSQuery := parseDNSPayload(payload)

			isSSDPQuery := parseSSDPPayload(payload)

			// Pass on the packet for its next adventure
			packetChan <- multicastPacket{
				packet:      packet,
				vlanTag:     tag,
				srcMAC:      srcMAC,
				dstMAC:      dstMAC,
				srcIP:       srcIP,
				dstIP:       dstIP,
				srcPort:     srcPort,
				dstPort:     dstPort,
				isIPv6:      isIPv6,
				isDNSQuery:  isDNSQuery,
				isSSDPQuery: isSSDPQuery,
			}
		}
	}()

	return packetChan
}

func parseEthernetLayer(packet gopacket.Packet) (srcMAC, dstMAC *net.HardwareAddr) {
	if parsedEth := packet.Layer(layers.LayerTypeEthernet); parsedEth != nil {
		srcMAC = &parsedEth.(*layers.Ethernet).SrcMAC
		dstMAC = &parsedEth.(*layers.Ethernet).DstMAC
	}
	return
}

func parseVLANTag(packet gopacket.Packet) (tag *uint16) {
	if parsedTag := packet.Layer(layers.LayerTypeDot1Q); parsedTag != nil {
		tag = &parsedTag.(*layers.Dot1Q).VLANIdentifier
	}
	return
}

func parseIPLayer(packet gopacket.Packet) (isIPv6 bool, srcIP *net.IP, dstIP *net.IP) {
	if parsedIP := packet.Layer(layers.LayerTypeIPv4); parsedIP != nil {
		isIPv6 = false
		srcIP = &parsedIP.(*layers.IPv4).SrcIP
		dstIP = &parsedIP.(*layers.IPv4).DstIP
	}
	if parsedIP := packet.Layer(layers.LayerTypeIPv6); parsedIP != nil {
		isIPv6 = true
		srcIP = &parsedIP.(*layers.IPv6).SrcIP
		dstIP = &parsedIP.(*layers.IPv6).DstIP
	}
	return
}

func parseUDPLayer(packet gopacket.Packet) (payload []byte, srcPort *layers.UDPPort, dstPort *layers.UDPPort) {
	if parsedUDP := packet.Layer(layers.LayerTypeUDP); parsedUDP != nil {
		payload = parsedUDP.(*layers.UDP).Payload
		srcPort = &parsedUDP.(*layers.UDP).SrcPort
		dstPort = &parsedUDP.(*layers.UDP).DstPort
	}
	return
}

func parseDNSPayload(payload []byte) (isDNSQuery bool) {
	packet := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.Default)
	if parsedDNS := packet.Layer(layers.LayerTypeDNS); parsedDNS != nil {
		isDNSQuery = !parsedDNS.(*layers.DNS).QR
	}
	return
}

func parseSSDPPayload(payload []byte) (isSSDPQuery bool) {
	packet := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.Default)
	if ssdp := packet.ApplicationLayer(); ssdp != ssdp {
		isSSDPQuery = strings.HasPrefix(string(ssdp.Payload()), "M-SEARCH ")
	}
	return
}

type packetWriter interface {
	WritePacketData([]byte) error
}

func sendPacket(handle packetWriter, packet *multicastPacket, tag uint16, srcMACAddress net.HardwareAddr, dstMacAddress net.HardwareAddr, srcIP net.IP, dstIP net.IP) {
	*packet.vlanTag = tag
	*packet.srcMAC = srcMACAddress
	*packet.dstMAC = dstMacAddress

	buf := gopacket.NewSerializeBuffer()
	serializeOptions := gopacket.SerializeOptions{}

	if !packet.isIPv6 && (srcIP != nil || dstIP != nil) {
		serializeOptions = gopacket.SerializeOptions{ComputeChecksums: true}

		if srcIP != nil {
			*packet.srcIP = srcIP
		}
		if dstIP != nil {
			*packet.dstIP = dstIP
		}
		// We recalculate the checksum since the IP was modified
		if parsedIP := packet.packet.Layer(layers.LayerTypeIPv4); parsedIP != nil {
			if parsedUDP := packet.packet.Layer(layers.LayerTypeUDP); parsedUDP != nil {
				parsedUDP.(*layers.UDP).SetNetworkLayerForChecksum(parsedIP.(*layers.IPv4))
			}
		}
	}

	gopacket.SerializePacket(buf, serializeOptions, packet.packet)
	handle.WritePacketData(buf.Bytes())

	fmt.Printf("Packet sent:\n%s\n", packet.packet.String())
}
