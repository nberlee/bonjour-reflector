package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Read config file and generate mDNS forwarding maps
	configPath := flag.String("config", "config.toml", "Config file in TOML format")
	debug := flag.Bool("debug", false, "Enable pprof server on /debug/pprof/")
	flag.Parse()

	// Start debug server
	if *debug {
		go debugServer(6060)
	}

	cfg, err := readConfig(*configPath)
	if err != nil {
		log.Fatalf("Could not read configuration: %v", err)
	}
	poolsMap := mapByPool(cfg.Devices)
	vlanIPMap := mapIpSourceByVlan(cfg.VlanIPSource)
	allowedMacsMap := cfg.Devices

	// Get a handle on the network interface
	rawTraffic, err := pcap.OpenLive(cfg.NetInterface, 65536, true, time.Second)
	if err != nil {
		log.Fatalf("Could not find network interface: %v", cfg.NetInterface)
	}

	// Get the local MAC address, to filter out Bonjour packet generated locally
	intf, err := net.InterfaceByName(cfg.NetInterface)
	if err != nil {
		log.Fatal(err)
	}
	srcMACAddress := intf.HardwareAddr
	processBonjourPackets(rawTraffic, srcMACAddress, poolsMap, vlanIPMap, allowedMacsMap)

}

func processBonjourPackets(rawTraffic *pcap.Handle, srcMACAddress net.HardwareAddr, poolsMap map[uint16][]uint16, vlanIPMap map[uint16]net.IP, allowedMacsMap map[macAddress]multicastDevice) {
	var dstMacAddress net.HardwareAddr

	filterTemplate := "not (ether src %s) and vlan and (dst net (224.0.0.251 or ff02::fb) and udp dst port 5353)"
	err := rawTraffic.SetBPFFilter(fmt.Sprintf(filterTemplate, srcMACAddress))
	if err != nil {
		log.Fatalf("Could not apply filter on network interface: %v", err)
	}

	// Get a channel of Bonjour packets to process
	decoder := gopacket.DecodersByLayerName["Ethernet"]
	source := gopacket.NewPacketSource(rawTraffic, decoder)
	bonjourPackets := parsePacketsLazily(source)

	for bonjourPacket := range bonjourPackets {
		fmt.Printf("Bonjour packet received:\n%s\n", bonjourPacket.packet.String())

		// Network devices may set dstMAC to the local MAC address
		// Rewrite dstMAC to ensure that it is set to the appropriate multicast MAC address
		if bonjourPacket.isIPv6 {
			dstMacAddress = net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0xFB}
		} else {
			dstMacAddress = net.HardwareAddr{0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB}
		}

		var srcIP net.IP

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
		} else {
			device, ok := allowedMacsMap[macAddress(bonjourPacket.srcMAC.String())]
			if !ok {
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

func debugServer(port int) {
	err := http.ListenAndServe(fmt.Sprintf("localhost:%d", port), nil)
	if err != nil {
		log.Fatalf("The application was started with -debug flag but could not listen on port %v: \n %s", port, err)
	}
}
