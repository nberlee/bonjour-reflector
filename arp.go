package main

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

func ownupNetworkAddresses(netInterface string, srcMACAddress net.HardwareAddr, vlanIPMap map[uint16]net.IP, stop chan struct{}) {
	IPv6Address = generateIPv6FromMac(srcMACAddress)
	// Get a handle on the network interface
	rawTraffic, err := pcap.OpenLive(netInterface, 65536, true, time.Second)
	if err != nil {
		logrus.Fatalf("Could not find network interface: %v", netInterface)
	}

	// Gratuitous ARP just once after startup
	for vlan, ip := range vlanIPMap {
		err := sendARP(rawTraffic, srcMACAddress, net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, ip, ip, vlan)
		if err != nil {
			logrus.Error(err)
			continue
		}
	}
	// Announce link-local just once after startup
	for vlan := range vlanIPMap {
		err := sendNA(rawTraffic, srcMACAddress, net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}, IPv6Address, net.ParseIP("ff02::1"), vlan)
		if err != nil {
			logrus.Error(err)
			continue
		}
	}

	filterTemplate := "not (ether src %s) and vlan and (arp or icmp6)"
	err = rawTraffic.SetBPFFilter(fmt.Sprintf(filterTemplate, srcMACAddress))
	if err != nil {
		logrus.Fatalf("Could not apply filter on network interface: %v", err)
	}
	src := gopacket.NewPacketSource(rawTraffic, layers.LayerTypeEthernet)
	in := src.Packets()

	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			if packet.Layer(layers.LayerTypeARP) != nil {
				respondToArpRequests(rawTraffic, packet, srcMACAddress, vlanIPMap)
			}
			if packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation) != nil {
				respondToNeighborSolicitation(rawTraffic, packet, srcMACAddress, vlanIPMap)
			}
		}
	}
}

// respondToArpRequests watches a handle for incoming ARP requests we might care about, and replies to them
//
// respondToArpRequests loops until 'stop' is closed.
func respondToArpRequests(rawTraffic *pcap.Handle, packet gopacket.Packet, srcMACAddress net.HardwareAddr, vlanIPMap map[uint16]net.IP) {
	tag := parseVLANTag(packet)
	ip := vlanIPMap[*tag]
	if ip == nil {
		return
	}

	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		return
	}

	arp := arpLayer.(*layers.ARP)
	if arp.Operation != layers.ARPRequest {
		return
	}

	if !net.IP(arp.DstProtAddress).Equal(ip) {
		return
	}

	err := sendARP(rawTraffic, srcMACAddress, net.HardwareAddr(arp.SourceHwAddress), ip, arp.SourceProtAddress, *tag)
	if err != nil {
		logrus.Error(err)
		return
	}

	logrus.Debugf("Replied to %v for ip %s", net.HardwareAddr(arp.SourceHwAddress), ip.String())
}

func sendARP(rawTraffic *pcap.Handle, srcMACAddress net.HardwareAddr, dstMACAddress net.HardwareAddr, srcIP net.IP, dstIP net.IP, vlanTag uint16) error {
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
