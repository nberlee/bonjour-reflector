package main

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
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
func processSSDPPackets(netInterface string, srcMACAddress net.HardwareAddr, poolsMap map[uint16][]uint16, vlanIPMap map[uint16]net.IP, allowedMacsMap map[macAddress]multicastDevice) {
	var dstMacAddress net.HardwareAddr

	// Get a handle on the network interface
	rawTraffic, err := pcap.OpenLive(netInterface, 65536, true, time.Second)
	if err != nil {
		logrus.Fatalf("Could not find network interface: %v", netInterface)
	}

	filterTemplate := "not (ether src %s) and vlan and udp and ((dst net (239.255.255.250 or ff02::c or ff05::c or ff08::c) and dst port 1900) or (ether dst %s and not port 5353))"

	err = rawTraffic.SetBPFFilter(fmt.Sprintf(filterTemplate, srcMACAddress, srcMACAddress))
	if err != nil {
		logrus.Fatalf("Could not apply filter on network interface: %v", err)
	}

	// Get a channel of SSDP packets to process
	decoder := gopacket.DecodersByLayerName["Ethernet"]
	source := gopacket.NewPacketSource(rawTraffic, decoder)
	ssdpPackets := parsePacketsLazily(source)

	tmssdpQuerySession := timedmap.New(time.Second)

	for ssdpPacket := range ssdpPackets {
		if !ssdpPacket.isSSDPAdvertisement && !ssdpPacket.isSSDPQuery && !ssdpPacket.isSSDPResponse {
			logrus.Warnf("Got a packet that is not a SSDP query, response or advertisement:\n%s", ssdpPacket.packet.String())
			continue
		}

		var srcIP net.IP
		if ssdpPacket.isIPv6 {
			srcIP = IPv6Address // ssdp packet cannot be routed from other vlan as it is link-local, so just rewrite it to our own link-local.
		}

		// Forward the SSDP query to appropriate VLANs and save the SSDP request packet metadata for the response
		// Forward the SSDP response to the appropriate VLAN, lookup the matching SSDP request to fill in the unicast destination.
		if ssdpPacket.isSSDPQuery {
			tags, ok := poolsMap[*ssdpPacket.vlanTag]
			if !ok {
				continue
			}
			logrus.Debugf("SSDP query packet received:\n%s", ssdpPacket.packet.String())
			if ssdpPacket.dstMAC == &srcMACAddress {
				logrus.Infof("Protocol violation from %s, got a SSDP query from an unicast packet.", ssdpPacket.srcMAC.String())
				continue
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
		} else if ssdpPacket.isSSDPAdvertisement {
			device, ok := allowedMacsMap[macAddress(ssdpPacket.srcMAC.String())]
			if !ok {
				continue
			}
			logrus.Debugf("SSDP advertisement packet received:\n%s", ssdpPacket.packet.String())
			if device.OriginPool != *ssdpPacket.vlanTag {
				logrus.Warningf("spoofing/vlan leak detected from %s. Config expected traffic from VLAN %d, got a packet from %d.", ssdpPacket.srcMAC.String(), device.OriginPool, *ssdpPacket.vlanTag)
				continue
			}
			if ssdpPacket.dstMAC == &srcMACAddress {
				logrus.Infof("Protocol violation from %s, got a SSDP advertisement from an unicast packet.", ssdpPacket.srcMAC.String())
				continue
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
				sendPacket(rawTraffic, &ssdpPacket, tag, srcMACAddress, dstMacAddress, srcIP, nil)
			}
			// Allowed Mac-address responding from on a SSDP query
		} else if device, ok := allowedMacsMap[macAddress(ssdpPacket.srcMAC.String())]; ok && ssdpPacket.isSSDPResponse {

			logrus.Debugf("SSDP query response packet received:\n%s", ssdpPacket.packet.String())
			if device.OriginPool != *ssdpPacket.vlanTag {
				logrus.Warningf("spoofing/vlan leak detected from %s. Config expected traffic from VLAN %d, got a packet from VLAN %d.", ssdpPacket.srcMAC.String(), device.OriginPool, *ssdpPacket.vlanTag)
				continue
			}
			if !tmssdpQuerySession.Contains(*ssdpPacket.dstPort) {
				logrus.Infof("No matching SSDP session found with SSDP request/advertisement src port %d.\n", uint32(*ssdpPacket.dstPort))
				continue
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
}
