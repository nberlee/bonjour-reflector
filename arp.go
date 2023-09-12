package main

import (
	"log/slog"
	"net"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
)

func ownupNetworkAddresses(netInterface string, srcMACAddress net.HardwareAddr, vlanIPMap map[uint16]net.IP, stop chan struct{}) {
	IPv6Address = generateIPv6FromMac(srcMACAddress)
	// Get a handle on the network interface
	rawTraffic, err := afpacket.NewTPacket(afpacket.OptInterface(netInterface))
	if err != nil {
		slog.Error("Could not find network interface", netInterface)
		os.Exit(1)
	}
	defer rawTraffic.Close()

	// Gratuitous ARP just once after startup
	for vlan, ip := range vlanIPMap {
		err := sendARP(rawTraffic, srcMACAddress, net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, ip, ip, vlan)
		if err != nil {
			slog.Error("Error sending gratuitous arp", err)
			continue
		}
	}
	// Announce link-local just once after startup
	for vlan := range vlanIPMap {

		err := sendNA(rawTraffic, srcMACAddress, net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}, IPv6Address, net.IPv6linklocalallnodes, vlan)
		if err != nil {
			slog.Error("Error sending ipv6 neighbor advertisement (optimistic DAD)", err)
			continue
		}
	}
}

// respondToArpRequests watches a handle for incoming ARP requests we might care about, and replies to them
//
// respondToArpRequests loops until 'stop' is closed.
func respondToArpRequests(rawTraffic *afpacket.TPacket, packet multicastPacket, srcMACAddress net.HardwareAddr, vlanIPMap map[uint16]net.IP) {
	ip := vlanIPMap[*packet.vlanTag]
	if ip == nil {
		return
	}

	arp := packet.packet.Layer(layers.LayerTypeARP).(*layers.ARP)
	if arp.Operation != layers.ARPRequest {
		return
	}

	if !net.IP(arp.DstProtAddress).Equal(ip) {
		return
	}

	err := sendARP(rawTraffic, srcMACAddress, net.HardwareAddr(arp.SourceHwAddress), ip, arp.SourceProtAddress, *packet.vlanTag)
	if err != nil {
		slog.Error("Error sending arp reply", err)
		return
	}

	slog.Debug("Replied to arp",
		"mac", net.HardwareAddr(arp.SourceHwAddress),
		"ip", ip.String())
}

func sendARP(rawTraffic *afpacket.TPacket, srcMACAddress net.HardwareAddr, dstMACAddress net.HardwareAddr, srcIP net.IP, dstIP net.IP, vlanTag uint16) error {
	if len(srcIP) == 16 {
		srcIP = srcIP[12:] // net.IP is 16 bytes, which make the FixLength fail as an ip can only be 4
	}
	if len(dstIP) == 16 {
		dstIP = dstIP[12:]
	}

	sendEth := layers.Ethernet{
		SrcMAC:       srcMACAddress,
		DstMAC:       dstMACAddress,
		EthernetType: layers.EthernetTypeDot1Q,
	}
	sendTag := layers.Dot1Q{
		Priority:       0,
		DropEligible:   false,
		VLANIdentifier: vlanTag,
		Type:           layers.EthernetTypeARP,
	}
	sendArp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   srcMACAddress,
		SourceProtAddress: srcIP,
		DstHwAddress:      dstMACAddress,
		DstProtAddress:    dstIP,
	}
	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts, &sendEth, &sendTag, &sendArp)
	if err != nil {
		return err
	}
	err = rawTraffic.WritePacketData(buf.Bytes())
	if err != nil {
		return err
	}
	return nil
}
