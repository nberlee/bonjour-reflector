package main

import (
	"flag"
	"net"
	"time"

	//_ "net/http/pprof"

	"github.com/sirupsen/logrus"
	_ "go.uber.org/automaxprocs"
)

var promiscuous bool = false

func main() {
	// Read config file and generate mDNS forwarding maps
	configPath := flag.String("config", "", "Config file in TOML format")
	//debug := flag.Bool("debug", false, "Enable pprof server on /debug/pprof/")
	verbose := flag.Bool("verbose", false, "See packets")
	silent := flag.Bool("silent", false, "Only warnings and errors")
	keepVlanFilter := flag.Bool("keep-vlan-filter", false, "Keep vlan filter")
	noSSDP := flag.Bool("no-ssdp", false, "Disable SSDP")
	noBonjour := flag.Bool("no-bonjour", false, "Disable Bonjour")
	noNDPARP := flag.Bool("no-ndp-arp", false, "Disable NDP and ARP")
	promiscuous = *flag.Bool("promiscuous", false, "Enable promiscuous mode")

	flag.Parse()

	// Start debug server
	//if *debug {
	//	go debugServer(6060)
	//}
	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}
	if *silent {
		logrus.SetLevel(logrus.WarnLevel)
	}
	logrus.SetFormatter(&logrus.TextFormatter{
		DisableQuote: true,
	})
	if configPath == nil || *configPath == "" {
		var err error
		configPath, err = findConfigFile()
		if err != nil {
			logrus.Fatal("Could not find config file")
		}
	}
	cfg, err := readConfig(*configPath)
	if err != nil {
		logrus.Fatalf("Could not read configuration: %v", err)
	}
	poolsMap := mapByPool(cfg.Devices)
	vlanIPMap := mapIpSourceByVlan(cfg.VlanIPSource)

	intf, err := net.InterfaceByName(cfg.NetInterface)
	if err != nil {
		logrus.Fatal(err)
	}
	srcMACAddress := intf.HardwareAddr

	if !*keepVlanFilter {
		removeVlanFilter(intf.Name)
	}

	stop := make(chan struct{})
	defer close(stop)

	if !*noNDPARP {
		go ownupNetworkAddresses(cfg.NetInterface, srcMACAddress, vlanIPMap, stop)
	}

	allowedMacsMap := mapLowerCaseMac(cfg.Devices)
	if !*noSSDP {
		if *noBonjour {
			processSSDPPackets(cfg.NetInterface, srcMACAddress, poolsMap, vlanIPMap, allowedMacsMap)
			return
		}
		go processSSDPPackets(cfg.NetInterface, srcMACAddress, poolsMap, vlanIPMap, allowedMacsMap)
	}
	if *noBonjour {
		for {
			time.Sleep(1 * time.Hour)
		}
	}

	processBonjourPackets(cfg.NetInterface, srcMACAddress, poolsMap, vlanIPMap, allowedMacsMap)

}

//func debugServer(port int) {
//	err := http.ListenAndServe(fmt.Sprintf("localhost:%d", port), nil)
//	if err != nil {
//		logrus.Fatalf("The application was started with -debug flag but could not listen on port %v: \n %s", port, err)
//	}
//}
