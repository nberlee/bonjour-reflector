package main

import (
	"log/slog"
	"net"

	"github.com/gopacket/gopacket/afpacket"
)

func processBonjourPackets(rawTraffic *afpacket.TPacket, bonjourPacket multicastPacket, srcMACAddress net.HardwareAddr, poolsMap map[uint16][]uint16, vlanIPMap map[uint16]net.IP, allowedMacsMap map[macAddress]multicastDevice) {
	var dstMacAddress net.HardwareAddr

	slog.Debug("Bonjour packet received", bonjourPacket.packet.String())
	if !bonjourPacket.isDNSQuery && !bonjourPacket.isDNSResponse {
		slog.Warn("Received unexpected Bonjour packet", bonjourPacket.packet.String())
		return
	}

	var srcIP net.IP
	// Network devices may set dstMAC to the local MAC address
	// Rewrite dstMAC to ensure that it is set to the appropriate multicast MAC address
	if bonjourPacket.isIPv6 {
		dstMacAddress = net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0xFB}
		srcIP = IPv6Address
	} else {
		dstMacAddress = net.HardwareAddr{0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB}
	}

	// Forward the mDNS query or response to appropriate VLANs
	switch {
	case bonjourPacket.isDNSQuery:
		tags, ok := poolsMap[*bonjourPacket.vlanTag]
		if !ok {
			return
		}
		for _, tag := range tags {
			if !bonjourPacket.isIPv6 {
				srcIP, ok = vlanIPMap[tag]
				if !ok {
					srcIP = nil
				}
			}
			// Send the packet to the appropriate VLAN

			sendPacket(rawTraffic, &bonjourPacket, tag, srcMACAddress, dstMacAddress, srcIP, nil)
		}
	case bonjourPacket.isDNSResponse:
		device, ok := allowedMacsMap[macAddress(bonjourPacket.srcMAC.String())]
		if !ok {
			return
		}
		if device.OriginPool != *bonjourPacket.vlanTag {
			slog.Warn("Spoofing/vlan leak detected from sourceMac. Traffic was expected from expectedVlan, got a packet from vlanTag",
				"sourceMac", bonjourPacket.srcMAC.String(),
				"expectedVlan", device.OriginPool,
				"vlanTag", bonjourPacket.vlanTag)
			return
		}

		for _, tag := range device.SharedPools {
			if !bonjourPacket.isIPv6 {
				srcIP, ok = vlanIPMap[tag]
				if !ok {
					srcIP = nil
				}
			}

			sendPacket(rawTraffic, &bonjourPacket, tag, srcMACAddress, dstMacAddress, srcIP, nil)
		}
	}

}
