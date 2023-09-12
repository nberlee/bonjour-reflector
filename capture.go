package main

import (
	"log/slog"
	"net"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/net/bpf"
)

func packetCapture(netInterface string, srcMACAddress net.HardwareAddr, poolsMap map[uint16][]uint16, vlanIPMap map[uint16]net.IP, allowedMacsMap map[macAddress]multicastDevice, stop chan struct{}) {

	handle, err := pcapgo.NewEthernetHandle(netInterface)
	if err != nil {
		slog.Error("Could not find network interface", netInterface)
		os.Exit(1)
	}

	if err = handle.SetPromiscuous(true); err != nil {
		handle.Close()

		slog.Error("Could not set promiscuous mode", err)
		os.Exit(1)
	}

	tpacket, err := afpacket.NewTPacket(afpacket.OptInterface(netInterface))
	if err != nil {
		slog.Error("Could not find network interface", netInterface)
		os.Exit(1)
	}

	srcMacFirst2Bytes := uint32(srcMACAddress[0])<<8 | uint32(srcMACAddress[1])
	srcMacLast4Bytes := uint32(srcMACAddress[2])<<24 | uint32(srcMACAddress[3])<<16 | uint32(srcMACAddress[4])<<8 | uint32(srcMACAddress[5])

	// tcpdump -dd -y EN10MB 'not (ether src aa:bb:cc:dd:ee:ff) and vlan and (arp or icmp6 or (dst net (224.0.0.251 or ff02::fb) and udp dst port 5353) or ((dst net (239.255.255.250 or ff02::c or ff05::c or ff08::c) and dst port 1900) or (ether dst aa:bb:cc:dd:ee:ff and not dst port 5353)))'
	filter := []bpf.RawInstruction{
		{Op: 0x20, Jt: 0, Jf: 0, K: 0x00000008},
		{Op: 0x15, Jt: 0, Jf: 2, K: srcMacLast4Bytes},
		{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000006},
		{Op: 0x15, Jt: 82, Jf: 0, K: srcMacFirst2Bytes},
		{Op: 0x28, Jt: 0, Jf: 0, K: 0x0000000c},
		{Op: 0x15, Jt: 2, Jf: 0, K: 0x00008100},
		{Op: 0x15, Jt: 1, Jf: 0, K: 0x000088a8},
		{Op: 0x15, Jt: 0, Jf: 78, K: 0x00009100},
		{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000010},
		{Op: 0x15, Jt: 75, Jf: 0, K: 0x00000806},
		{Op: 0x15, Jt: 0, Jf: 32, K: 0x000086dd},
		{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000018},
		{Op: 0x15, Jt: 72, Jf: 0, K: 0x0000003a},
		{Op: 0x15, Jt: 0, Jf: 2, K: 0x0000002c},
		{Op: 0x30, Jt: 0, Jf: 0, K: 0x0000003a},
		{Op: 0x15, Jt: 69, Jf: 0, K: 0x0000003a},
		{Op: 0x20, Jt: 0, Jf: 0, K: 0x0000002a},
		{Op: 0x15, Jt: 0, Jf: 11, K: 0xff020000},
		{Op: 0x20, Jt: 0, Jf: 0, K: 0x0000002e},
		{Op: 0x15, Jt: 0, Jf: 43, K: 0x00000000},
		{Op: 0x20, Jt: 0, Jf: 0, K: 0x00000032},
		{Op: 0x15, Jt: 0, Jf: 41, K: 0x00000000},
		{Op: 0x20, Jt: 0, Jf: 0, K: 0x00000036},
		{Op: 0x15, Jt: 0, Jf: 4, K: 0x000000fb},
		{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000018},
		{Op: 0x15, Jt: 0, Jf: 37, K: 0x00000011},
		{Op: 0x28, Jt: 0, Jf: 0, K: 0x0000003c},
		{Op: 0x15, Jt: 57, Jf: 35, K: 0x000014e9},
		{Op: 0x15, Jt: 8, Jf: 34, K: 0x0000000c},
		{Op: 0x15, Jt: 1, Jf: 0, K: 0xff050000},
		{Op: 0x15, Jt: 0, Jf: 32, K: 0xff080000},
		{Op: 0x20, Jt: 0, Jf: 0, K: 0x0000002e},
		{Op: 0x15, Jt: 0, Jf: 30, K: 0x00000000},
		{Op: 0x20, Jt: 0, Jf: 0, K: 0x00000032},
		{Op: 0x15, Jt: 0, Jf: 28, K: 0x00000000},
		{Op: 0x20, Jt: 0, Jf: 0, K: 0x00000036},
		{Op: 0x15, Jt: 0, Jf: 26, K: 0x0000000c},
		{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000018},
		{Op: 0x15, Jt: 2, Jf: 0, K: 0x00000084},
		{Op: 0x15, Jt: 1, Jf: 0, K: 0x00000006},
		{Op: 0x15, Jt: 0, Jf: 22, K: 0x00000011},
		{Op: 0x28, Jt: 0, Jf: 0, K: 0x0000003c},
		{Op: 0x15, Jt: 42, Jf: 20, K: 0x0000076c},
		{Op: 0x15, Jt: 0, Jf: 19, K: 0x00000800},
		{Op: 0x20, Jt: 0, Jf: 0, K: 0x00000022},
		{Op: 0x15, Jt: 0, Jf: 7, K: 0xe00000fb},
		{Op: 0x30, Jt: 0, Jf: 0, K: 0x0000001b},
		{Op: 0x15, Jt: 0, Jf: 15, K: 0x00000011},
		{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000018},
		{Op: 0x45, Jt: 13, Jf: 0, K: 0x00001fff},
		{Op: 0xb1, Jt: 0, Jf: 0, K: 0x00000012},
		{Op: 0x48, Jt: 0, Jf: 0, K: 0x00000014},
		{Op: 0x15, Jt: 32, Jf: 10, K: 0x000014e9},
		{Op: 0x15, Jt: 0, Jf: 9, K: 0xeffffffa},
		{Op: 0x30, Jt: 0, Jf: 0, K: 0x0000001b},
		{Op: 0x15, Jt: 2, Jf: 0, K: 0x00000084},
		{Op: 0x15, Jt: 1, Jf: 0, K: 0x00000006},
		{Op: 0x15, Jt: 0, Jf: 5, K: 0x00000011},
		{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000018},
		{Op: 0x45, Jt: 3, Jf: 0, K: 0x00001fff},
		{Op: 0xb1, Jt: 0, Jf: 0, K: 0x00000012},
		{Op: 0x48, Jt: 0, Jf: 0, K: 0x00000014},
		{Op: 0x15, Jt: 22, Jf: 0, K: 0x0000076c},
		{Op: 0x20, Jt: 0, Jf: 0, K: 0x00000002},
		{Op: 0x15, Jt: 0, Jf: 21, K: srcMacLast4Bytes},
		{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000000},
		{Op: 0x15, Jt: 0, Jf: 19, K: srcMacFirst2Bytes},
		{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000010},
		{Op: 0x15, Jt: 0, Jf: 6, K: 0x000086dd},
		{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000018},
		{Op: 0x15, Jt: 2, Jf: 0, K: 0x00000084},
		{Op: 0x15, Jt: 1, Jf: 0, K: 0x00000006},
		{Op: 0x15, Jt: 0, Jf: 12, K: 0x00000011},
		{Op: 0x28, Jt: 0, Jf: 0, K: 0x0000003c},
		{Op: 0x15, Jt: 11, Jf: 10, K: 0x000014e9},
		{Op: 0x15, Jt: 0, Jf: 9, K: 0x00000800},
		{Op: 0x30, Jt: 0, Jf: 0, K: 0x0000001b},
		{Op: 0x15, Jt: 2, Jf: 0, K: 0x00000084},
		{Op: 0x15, Jt: 1, Jf: 0, K: 0x00000006},
		{Op: 0x15, Jt: 0, Jf: 5, K: 0x00000011},
		{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000018},
		{Op: 0x45, Jt: 3, Jf: 0, K: 0x00001fff},
		{Op: 0xb1, Jt: 0, Jf: 0, K: 0x00000012},
		{Op: 0x48, Jt: 0, Jf: 0, K: 0x00000014},
		{Op: 0x15, Jt: 1, Jf: 0, K: 0x000014e9},
		{Op: 0x6, Jt: 0, Jf: 0, K: 0x00040000},
		{Op: 0x6, Jt: 0, Jf: 0, K: 0x00000000},
	}
	if err = handle.SetBPF(filter); err != nil {
		handle.Close()

		slog.Error("Could not apply filter on network interface", err)
		os.Exit(1)
	}

	// Get a channel of packets to process
	decoder := gopacket.DecodersByLayerName["Ethernet"]
	source := gopacket.NewPacketSource(handle, decoder)

	packets := parsePacketsLazily(source)

	for {
		select {
		case packet, ok := <-packets:
			if !ok {
				return // packets channel closed, exit loop
			}

			if packet.packet == nil || packet.vlanTag == nil || packet.srcMAC == nil || packet.dstMAC == nil {
				continue
			}

			switch {
			case packet.isARP:
				respondToArpRequests(tpacket, packet, srcMACAddress, vlanIPMap)
			case packet.isNDP:
				respondToNeighborSolicitation(tpacket, packet, srcMACAddress, vlanIPMap)
			case packet.isSSDPAdvertisement || packet.isSSDPQuery || packet.isSSDPResponse:
				processSSDPPackets(tpacket, packet, srcMACAddress, poolsMap, vlanIPMap, allowedMacsMap)
			case packet.isDNSQuery || packet.isDNSResponse:
				processBonjourPackets(tpacket, packet, srcMACAddress, poolsMap, vlanIPMap, allowedMacsMap)
			default:
				slog.Debug("Unkown Packet received", packet.packet.String())
			}
		case <-stop:
			return // Received a signal on the stop channel, exit loop
		}
	}
}
