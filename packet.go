package main

import (
	"bufio"
	"bytes"
	"log/slog"
	"net"
	"net/http"
	"strconv"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
)

type multicastPacket struct {
	packet              gopacket.Packet
	srcMAC              *net.HardwareAddr
	dstMAC              *net.HardwareAddr
	srcIP               *net.IP
	dstIP               *net.IP
	srcPort             *layers.UDPPort
	dstPort             *layers.UDPPort
	isIPv6              bool
	vlanTag             *uint16
	isARP               bool
	isNDP               bool
	isDNSQuery          bool
	isDNSResponse       bool
	isSSDPQuery         bool
	isSSDPAdvertisement bool
	isSSDPResponse      bool
	maxWaitTime         uint8
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

			isARP, isNDP := false, false
			if payload == nil {
				// Check if ARP or NDP
				isARP, isNDP = parseAdressResolutionProtocol(packet)
				isIPv6 = isNDP
			}
			// Check if DNS query
			isDNSQuery, isDNSResponse := false, false
			if dstPort != nil && *dstPort == 5353 {
				isDNSQuery, isDNSResponse = parseDNSPayload(payload)
			}

			// Check if SSDP query
			isSSDPQuery, isSSDPAdvertisement, isSSDPResponse, maxWaitTime := false, false, false, uint8(ssdpSessionDuration)
			if dstPort != nil && *dstPort == 1900 {
				isSSDPQuery, isSSDPAdvertisement, maxWaitTime = parseSSDPQuery(payload)
			} else if !isDNSQuery && !isDNSResponse {
				isSSDPResponse = parseSSDPResponse(payload)
			}
			// Pass on the packet for its next adventure
			packetChan <- multicastPacket{
				packet:              packet,
				vlanTag:             tag,
				srcMAC:              srcMAC,
				dstMAC:              dstMAC,
				srcIP:               srcIP,
				dstIP:               dstIP,
				isARP:               isARP,
				isNDP:               isNDP,
				srcPort:             srcPort,
				dstPort:             dstPort,
				isIPv6:              isIPv6,
				isDNSQuery:          isDNSQuery,
				isDNSResponse:       isDNSResponse,
				isSSDPQuery:         isSSDPQuery,
				isSSDPAdvertisement: isSSDPAdvertisement,
				isSSDPResponse:      isSSDPResponse,
				maxWaitTime:         maxWaitTime,
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

func parseDNSPayload(payload []byte) (isDNSQuery bool, isDNSResponse bool) {
	packet := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.Default)
	if parsedDNS := packet.Layer(layers.LayerTypeDNS); parsedDNS != nil {
		isDNSResponse = parsedDNS.(*layers.DNS).QR
		isDNSQuery = !isDNSResponse
	}
	return
}

func parseAdressResolutionProtocol(packet gopacket.Packet) (isARP bool, isNDP bool) {
	if packet.Layer(layers.LayerTypeARP) != nil {
		isARP = true
		isNDP = false
	}

	if packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation) != nil {
		isARP = false
		isNDP = true
	}
	return
}

func parseSSDPQuery(payload []byte) (isSSDPQuery bool, isSSDPAdvertisement bool, maxWaitTime uint8) {

	// SSDP packets are HTTP-like, so we can parse them as such
	// https://tools.ietf.org/html/draft-cai-ssdp-v1-03

	// Check if the packet is a valid HTTP request

	parsedHTTP, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
	if err != nil {
		return
	}

	isSSDPQuery = parsedHTTP.Method == "M-SEARCH" &&
		parsedHTTP.RequestURI == "*" &&
		parsedHTTP.Header.Get("MAN") == `"ssdp:discover"`

	isSSDPAdvertisement = parsedHTTP.Method == "NOTIFY" &&
		parsedHTTP.RequestURI == "*" &&
		parsedHTTP.Header.Get("NT") != "" &&
		(parsedHTTP.Header.Get("NTS") == "ssdp:alive" || parsedHTTP.Header.Get("NTS") == "ssdp:byebye")

	if isSSDPQuery {
		if mx, err := strconv.Atoi(parsedHTTP.Header.Get("MX")); err == nil {
			if mx >= 1 && mx <= 120 {
				maxWaitTime = uint8(mx)
			} else if mx > 120 {
				maxWaitTime = 120
			}
		} else {
			isSSDPQuery = false
		}
	}

	parsedHTTP.Body.Close()
	return
}

func parseSSDPResponse(payload []byte) (isSSDPResponse bool) {

	// SSDP packets are HTTP-like, so we can parse them as such
	// https://tools.ietf.org/html/draft-cai-ssdp-v1-03

	// Check if the packet is a valid HTTP response

	parsedHTTP, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(payload)), nil)
	if err != nil {
		return
	}

	isSSDPResponse = parsedHTTP.Header.Get("CACHE-CONTROL") != "" &&
		parsedHTTP.Header.Get("LOCATION") != "" &&
		parsedHTTP.Header.Get("ST") != "" &&
		parsedHTTP.Header.Get("USN") != ""

	parsedHTTP.Body.Close()
	return
}

func sendPacket(handle *afpacket.TPacket, packet *multicastPacket, tag uint16, srcMACAddress net.HardwareAddr, dstMacAddress net.HardwareAddr, srcIP net.IP, dstIP net.IP) {
	*packet.vlanTag = tag
	*packet.srcMAC = srcMACAddress
	*packet.dstMAC = dstMacAddress

	buf := gopacket.NewSerializeBuffer()
	serializeOptions := gopacket.SerializeOptions{}

	if srcIP != nil || dstIP != nil {
		serializeOptions = gopacket.SerializeOptions{ComputeChecksums: true}

		if srcIP != nil {
			*packet.srcIP = srcIP
		}
		if dstIP != nil {
			*packet.dstIP = dstIP
		}
		// We recalculate the checksum since the IP was modified
		if packet.isIPv6 {
			if parsedIP := packet.packet.Layer(layers.LayerTypeIPv6); parsedIP != nil {
				if parsedUDP := packet.packet.Layer(layers.LayerTypeUDP); parsedUDP != nil {
					parsedUDP.(*layers.UDP).SetNetworkLayerForChecksum(parsedIP.(*layers.IPv6))
				}
			}
		} else {
			if parsedIP := packet.packet.Layer(layers.LayerTypeIPv4); parsedIP != nil {
				if parsedUDP := packet.packet.Layer(layers.LayerTypeUDP); parsedUDP != nil {
					parsedUDP.(*layers.UDP).SetNetworkLayerForChecksum(parsedIP.(*layers.IPv4))
				}
			}
		}
	}

	gopacket.SerializePacket(buf, serializeOptions, packet.packet)
	err := handle.WritePacketData(buf.Bytes())
	if err != nil {
		slog.Error("Error sending packet", err)
		return
	}

	slog.Debug("Packet sent", packet.packet.String())
}
