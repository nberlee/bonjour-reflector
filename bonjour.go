package main

import (
	"fmt"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"github.com/zekroTJA/timedmap"
)

type bonjourRequest struct {
	ip         net.IP
	tag        uint16
	macAddress net.HardwareAddr
}

var bonjourDuration = 2 * time.Second

func processBonjourPackets(netInterface string, srcMACAddress net.HardwareAddr, poolsMap map[uint16][]uint16, vlanIPMap map[uint16]net.IP, allowedMacsMap map[macAddress]multicastDevice) {
	var dstMacAddress net.HardwareAddr

	// Get a handle on the network interface
	rawTraffic, err := pcap.OpenLive(netInterface, 65536, promiscuous, time.Second)
	if err != nil {
		logrus.Fatalf("Could not find network interface: %v", netInterface)
	}

	filterTemplate := "not (ether src %s) and vlan and ((dst net (224.0.0.251 or ff02::fb) and udp dst port 5353) or (ether dst %s and src port 5353))"
	err = rawTraffic.SetBPFFilter(fmt.Sprintf(filterTemplate, srcMACAddress, srcMACAddress))
	if err != nil {
		logrus.Fatalf("Could not apply filter on network interface: %v", err)
	}

	// Get a channel of Bonjour packets to process
	decoder := gopacket.DecodersByLayerName["Ethernet"]
	source := gopacket.NewPacketSource(rawTraffic, decoder)
	bonjourPackets := parsePacketsLazily(source)

	tmbonjourSession := timedmap.New(time.Second)

	for bonjourPacket := range bonjourPackets {
		logrus.Debugf("Bonjour packet received:\n%s", bonjourPacket.packet.String())
		if !bonjourPacket.isDNSQuery && !bonjourPacket.isDNSResponse {
			logrus.Warningf("Received unexpected Bonjour packet: %s", bonjourPacket.packet.String())
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

			bonjourSession := bonjourRequest{
				ip:         *bonjourPacket.srcIP,
				tag:        *bonjourPacket.vlanTag,
				macAddress: *bonjourPacket.srcMAC,
			}

			for _, tag := range tags {
				if !bonjourPacket.isIPv6 {
					srcIP, ok = vlanIPMap[tag]
					if !ok {
						srcIP = nil
					}
				}
				if *bonjourPacket.srcPort != 5353 {
					tmbonjourSession.Set(*bonjourPacket.srcPort, bonjourSession, bonjourDuration)
				}
				sendPacket(rawTraffic, &bonjourPacket, tag, srcMACAddress, dstMacAddress, srcIP, nil)
			}
		} else if bonjourPacket.isDNSResponse && *bonjourPacket.dstPort == 5353 {
			device, ok := allowedMacsMap[macAddress(bonjourPacket.srcMAC.String())]
			if !ok {
				continue
			}
			if device.OriginPool != *bonjourPacket.vlanTag {
				logrus.Warningf("spoofing/vlan leak detected from %s. Config expected traffic from VLAN %d, got a packet from VLAN %d.", bonjourPacket.srcMAC.String(), device.OriginPool, *bonjourPacket.vlanTag)
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
		} else if bonjourPacket.isDNSResponse && *bonjourPacket.dstPort != 5353 {
			device, ok := allowedMacsMap[macAddress(bonjourPacket.srcMAC.String())]
			if !ok {
				continue
			}
			if device.OriginPool != *bonjourPacket.vlanTag {
				logrus.Warningf("spoofing/vlan leak detected from %s. Config expected traffic from VLAN %d, got a packet from VLAN %d.", bonjourPacket.srcMAC.String(), device.OriginPool, *bonjourPacket.vlanTag)
				continue
			}
			if !tmbonjourSession.Contains(*bonjourPacket.dstPort) {
				logrus.Infof("No matching Bonjour query found for Bonjour response packet: %s", bonjourPacket.packet.String())
				continue
			}

			tmbonjourSession.Refresh(*bonjourPacket.dstPort, bonjourDuration)
			bonjourSession := tmbonjourSession.GetValue(*bonjourPacket.dstPort)

			tag := bonjourSession.(bonjourRequest).tag
			dstIP := bonjourSession.(bonjourRequest).ip
			dstMacAddress := bonjourSession.(bonjourRequest).macAddress

			if !bonjourPacket.isIPv6 {
				srcIP, ok = vlanIPMap[tag]
				if !ok {
					srcIP = nil
				}
			}

			sendPacket(rawTraffic, &bonjourPacket, tag, srcMACAddress, dstMacAddress, srcIP, dstIP)
		}
	}
}
