package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

func processBonjourPackets(netInterface string, srcMACAddress net.HardwareAddr, poolsMap map[uint16][]uint16, vlanIPMap map[uint16]net.IP, allowedMacsMap map[macAddress]multicastDevice) {
	var dstMacAddress net.HardwareAddr

	// Get a handle on the network interface
	rawTraffic, err := pcap.OpenLive(netInterface, 65536, true, time.Second)
	if err != nil {
		slog.Error("Could not find network interface", netInterface)
		os.Exit(1)
	}

	filterTemplate := "not (ether src %s) and vlan and (dst net (224.0.0.251 or ff02::fb) and udp dst port 5353)"
	err = rawTraffic.SetBPFFilter(fmt.Sprintf(filterTemplate, srcMACAddress))
	if err != nil {
		slog.Error("Could not apply filter on network interface", err)
		os.Exit(1)
	}

	// Get a channel of Bonjour packets to process
	decoder := gopacket.DecodersByLayerName["Ethernet"]
	source := gopacket.NewPacketSource(rawTraffic, decoder)
	bonjourPackets := parsePacketsLazily(source)

	for bonjourPacket := range bonjourPackets {
		slog.Debug("Bonjour packet received", bonjourPacket.packet.String())
		if !bonjourPacket.isDNSQuery && !bonjourPacket.isDNSResponse {
			slog.Warn("Received unexpected Bonjour packet", bonjourPacket.packet.String())
			continue
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
		if bonjourPacket.isDNSQuery {
			tags, ok := poolsMap[*bonjourPacket.vlanTag]
			if !ok {
				continue
			}
			for _, tag := range tags {
				if !bonjourPacket.isIPv6 {
					srcIP, ok = vlanIPMap[tag]
					if !ok {
						srcIP = nil
					}
				}

				sendPacket(rawTraffic, &bonjourPacket, tag, srcMACAddress, dstMacAddress, srcIP, nil)
			}
		} else if bonjourPacket.isDNSResponse {
			device, ok := allowedMacsMap[macAddress(bonjourPacket.srcMAC.String())]
			if !ok {
				continue
			}
			if device.OriginPool != *bonjourPacket.vlanTag {
				slog.Warn("Spoofing/vlan leak detected from sourceMac. Traffic was expected from expectedVlan, got a packet from vlanTag",
					"sourceMac", bonjourPacket.srcMAC.String(),
					"expectedVlan", device.OriginPool,
					"vlanTag", *&bonjourPacket.vlanTag)
				continue
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
}
