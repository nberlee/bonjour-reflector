package main

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

var IPv6Address net.IP

func respondToNeighborSolicitation(rawTraffic *pcap.Handle, packet gopacket.Packet, srcMACAddress net.HardwareAddr, vlanIPMap map[uint16]net.IP) {
	var tag uint16

	if parsedTag := packet.Layer(layers.LayerTypeDot1Q); parsedTag != nil {
		tag = parsedTag.(*layers.Dot1Q).VLANIdentifier
	}
	if vlanIPMap[tag] == nil {
		return
	}

	nsLayer := packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation)
	if nsLayer == nil {
		return
	}
	ns := nsLayer.(*layers.ICMPv6NeighborSolicitation)
	if !net.IP(ns.TargetAddress).Equal(IPv6Address) {
		return
	}

	var srcMAC net.HardwareAddr
	if parsedEth := packet.Layer(layers.LayerTypeEthernet); parsedEth != nil {
		srcMAC = parsedEth.(*layers.Ethernet).SrcMAC
	}

	var srcIP net.IP
	if parsedIP := packet.Layer(layers.LayerTypeIPv6); parsedIP != nil {
		srcIP = parsedIP.(*layers.IPv6).SrcIP
	}
	err := sendNA(rawTraffic, srcMACAddress, srcMAC, IPv6Address, srcIP, tag)
	if err != nil {
		logrus.Error(err)
		return
	}

	logrus.Infof("Replied to %v for ip %s", net.HardwareAddr(srcMAC), IPv6Address.String())

}

func sendNA(rawTraffic *pcap.Handle, srcMACAddress net.HardwareAddr, dstMACAddress net.HardwareAddr, srcIP net.IP, dstIP net.IP, vlanTag uint16) error {
	sendEth := layers.Ethernet{
		SrcMAC:       srcMACAddress,
		DstMAC:       dstMACAddress,
		EthernetType: layers.EthernetTypeDot1Q,
	}
	sendTag := layers.Dot1Q{
		Priority:       0,
		DropEligible:   false,
		VLANIdentifier: vlanTag,
		Type:           layers.EthernetTypeIPv6,
	}
	sendIpv6 := layers.IPv6{
		Version:    6,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		NextHeader: layers.IPProtocol(layers.IPProtocolICMPv6),
		HopLimit:   255,
	}
	sendICMPv6 := layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(136, 0),
	}
	sendNA := layers.ICMPv6NeighborAdvertisement{
		TargetAddress: srcIP,
		// We have implemented Optimistic DAD, so we cannot use override
		Flags: 0x40, // 0x20 = Override, 0x40 = Solicited
		Options: []layers.ICMPv6Option{
			{
				Type: layers.ICMPv6OptTargetAddress,
				Data: []byte(srcMACAddress),
			},
		},
	}
	if dstIP.IsMulticast() {
		sendNA.Flags = 0x0
	}
	sendICMPv6.SetNetworkLayerForChecksum(&sendIpv6)

	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts, &sendEth, &sendTag, &sendIpv6, &sendICMPv6, &sendNA)
	if err != nil {
		return err
	}
	err = rawTraffic.WritePacketData(buf.Bytes())
	if err != nil {
		return err
	}

	return nil
}

// Do a rfc2464 (section 4 + 5) address generation
func generateIPv6FromMac(srcMACAddress net.HardwareAddr) net.IP {
	return net.IP{
		0xFE,
		0x80,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		srcMACAddress[0],
		srcMACAddress[1],
		srcMACAddress[2],
		0xFF,
		0xFE,
		srcMACAddress[3],
		srcMACAddress[4],
		srcMACAddress[5],
	}
}
