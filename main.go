package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"

	"github.com/sirupsen/logrus"
	_ "go.uber.org/automaxprocs"
)

func main() {
	// Read config file and generate mDNS forwarding maps
	configPath := flag.String("config", "", "Config file in TOML format")
	debug := flag.Bool("debug", false, "Enable pprof server on /debug/pprof/")
	verbose := flag.Bool("verbose", false, "See packets")
	silent := flag.Bool("silent", false, "Only warnings and errors")

	flag.Parse()

	// Start debug server
	if *debug {
		go debugServer(6060)
	}
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

	removeVlanFilter(intf.Name)

	stop := make(chan struct{})
	defer close(stop)

	go ownupNetworkAddresses(cfg.NetInterface, srcMACAddress, vlanIPMap, stop)

	allowedMacsMap := mapLowerCaseMac(cfg.Devices)
	go processSSDPPackets(cfg.NetInterface, srcMACAddress, poolsMap, vlanIPMap, allowedMacsMap)

	processBonjourPackets(cfg.NetInterface, srcMACAddress, poolsMap, vlanIPMap, allowedMacsMap)

}

func debugServer(port int) {
	err := http.ListenAndServe(fmt.Sprintf("localhost:%d", port), nil)
	if err != nil {
		logrus.Fatalf("The application was started with -debug flag but could not listen on port %v: \n %s", port, err)
	}
}
