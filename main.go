package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"

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
	l := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	if *verbose {
		l = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))

	}
	if *silent {
		l = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelWarn,
		}))
	}

	slog.SetDefault(l)

	if configPath == nil || *configPath == "" {
		var err error
		configPath, err = findConfigFile()
		if err != nil {
			slog.Error("Could not find config file")
			os.Exit(1)
		}
	}
	cfg, err := readConfig(*configPath)
	if err != nil {
		slog.Error("Could not read configuration", err)
		os.Exit(1)
	}
	poolsMap := mapByPool(cfg.Devices)
	vlanIPMap := mapIpSourceByVlan(cfg.VlanIPSource)

	intf, err := net.InterfaceByName(cfg.NetInterface)
	if err != nil {
		slog.Error("failed to get interface",
			"interface", cfg.NetInterface,
			"error", err)
		os.Exit(1)
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
		slog.Error("The application was started with -debug flag but could not listen on port",
			"port", port,
			"error", err)
		os.Exit(1)
	}
}
