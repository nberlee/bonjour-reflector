package main

import (
	"log/slog"
	"net"
	"time"

	"github.com/gopacket/gopacket/afpacket"
	"github.com/zekroTJA/timedmap"
)

type ssdpRequest struct {
	ip           net.IP
	tag          uint16
	macAddress   net.HardwareAddr
	allowedVlans []uint16
}

var ssdpSessionDuration = 2 * time.Second

// SSDP request = multicast
// SSDP response = unicast to SSDP request src.
func processSSDPPackets(rawTraffic *afpacket.TPacket, ssdpPacket multicastPacket, srcMACAddress net.HardwareAddr, poolsMap map[uint16][]uint16, vlanIPMap map[uint16]net.IP, allowedMacsMap map[macAddress]multicastDevice) {
	var dstMacAddress net.HardwareAddr

	tmssdpQuerySession := timedmap.New(time.Second)
	tmssdpAdvertisementSession := timedmap.New(time.Second)

	var srcIP net.IP
	if ssdpPacket.isIPv6 {
		srcIP = IPv6Address // ssdp packet cannot be routed from other vlan as it is link-local, so just rewrite it to our own link-local.
	}

	// Forward the SSDP query to appropriate VLANs and save the SSDP request packet metadata for the response
	// Forward the SSDP response to the appropriate VLAN, lookup the matching SSDP request to fill in the unicast destination.
	switch {
	case ssdpPacket.isSSDPQuery:
		tags, ok := poolsMap[*ssdpPacket.vlanTag]
		if !ok {
			return
		}
		slog.Debug("SSDP query packet received", ssdpPacket.packet.String())
		if ssdpPacket.dstMAC == &srcMACAddress {

			slog.Info("Got a SSDP advertisement from an unicast packet. This is a protocol violation",
				"sourceMac", ssdpPacket.srcMAC.String())
			return
		}

		// Store network source network information for the SSDP response
		ssdpSession := ssdpRequest{
			ip:         *ssdpPacket.srcIP,
			tag:        *ssdpPacket.vlanTag,
			macAddress: *ssdpPacket.srcMAC,
		}

		// Network devices may set dstMAC to the local MAC address
		// Rewrite dstMAC to ensure that it is set to the appropriate multicast MAC address
		if ssdpPacket.isIPv6 {
			dstMacAddress = net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x03}
		} else {
			dstMacAddress = net.HardwareAddr{0x01, 0x00, 0x5E, 0x7F, 0xFF, 0xFA}
		}

		for _, tag := range tags {
			if !ssdpPacket.isIPv6 {
				srcIP, ok = vlanIPMap[tag]
				if !ok {
					srcIP = nil
				}
			}

			tmssdpQuerySession.Set(*ssdpPacket.srcPort, ssdpSession, time.Duration(ssdpPacket.maxWaitTime+1)*time.Second)
			sendPacket(rawTraffic, &ssdpPacket, tag, srcMACAddress, dstMacAddress, srcIP, nil)
		}
	case ssdpPacket.isSSDPAdvertisement:
		device, ok := allowedMacsMap[macAddress(ssdpPacket.srcMAC.String())]
		if !ok {
			return
		}
		slog.Debug("SSDP advertisement packet received", ssdpPacket.packet.String())
		if device.OriginPool != *ssdpPacket.vlanTag {
			slog.Warn("Spoofing/vlan leak detected from sourceMac. Traffic was expected from expectedVlan, got a packet from vlanTag",
				"sourceMac", ssdpPacket.srcMAC.String(),
				"expectedVlan", device.OriginPool,
				"vlanTag", *ssdpPacket.vlanTag)

			return
		}
		if ssdpPacket.dstMAC == &srcMACAddress {
			slog.Info("Got a SSDP advertisement from an unicast packet. This is a protocol violation",
				"sourceMac", ssdpPacket.srcMAC.String())

			return
		}

		// Store network source network information for the SSDP response
		ssdpSession := ssdpRequest{
			ip:           *ssdpPacket.srcIP,
			tag:          *ssdpPacket.vlanTag,
			macAddress:   *ssdpPacket.srcMAC,
			allowedVlans: device.SharedPools,
		}

		// Network devices may set dstMAC to the local MAC address
		// Rewrite dstMAC to ensure that it is set to the appropriate multicast MAC address
		if ssdpPacket.isIPv6 {
			dstMacAddress = net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x03}
		} else {
			dstMacAddress = net.HardwareAddr{0x01, 0x00, 0x5E, 0x7F, 0xFF, 0xFA}
		}

		for _, tag := range device.SharedPools {
			if !ssdpPacket.isIPv6 {
				srcIP, ok = vlanIPMap[tag]
				if !ok {
					srcIP = nil
				}
			}
			tmssdpAdvertisementSession.Set(*ssdpPacket.srcPort, ssdpSession, ssdpSessionDuration)
			sendPacket(rawTraffic, &ssdpPacket, tag, srcMACAddress, dstMacAddress, srcIP, nil)
		}
		// Allowed Mac-address responding from on a SSDP query
	case ssdpPacket.isSSDPResponse:
		device, ok := allowedMacsMap[macAddress(ssdpPacket.srcMAC.String())]
		if !ok {
			return
		}
		slog.Debug("SSDP query response packet received", ssdpPacket.packet.String())

		if device.OriginPool != *ssdpPacket.vlanTag {
			slog.Warn("Spoofing/vlan leak detected from sourceMac. Traffic was expected from expectedVlan, got a packet from vlanTag",
				"sourceMac", ssdpPacket.srcMAC.String(),
				"expectedVlan", device.OriginPool,
				"vlanTag", *ssdpPacket.vlanTag)

			return
		}
		if !tmssdpQuerySession.Contains(*ssdpPacket.dstPort) {
			slog.Info("No matching SSDP session found with SSDP request/advertisement",
				"sourcePort", uint32(*ssdpPacket.dstPort))

			return
		}
		tmssdpQuerySession.Refresh(*ssdpPacket.dstPort, ssdpSessionDuration)
		ssdpSession := tmssdpQuerySession.GetValue(*ssdpPacket.dstPort)

		tag := ssdpSession.(ssdpRequest).tag
		dstIP := ssdpSession.(ssdpRequest).ip
		dstMacAddress := ssdpSession.(ssdpRequest).macAddress

		if !ssdpPacket.isIPv6 {
			srcIP, ok = vlanIPMap[tag]
			if !ok {
				srcIP = nil
			}
		}

		sendPacket(rawTraffic, &ssdpPacket, tag, srcMACAddress, dstMacAddress, srcIP, dstIP)
	}
}
