package main

import (
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	_ "go.uber.org/automaxprocs"
)

func main() {
	// Read config file and generate mDNS forwarding maps
	configPath := flag.String("config", "", "Config file in TOML format")
	verbose := flag.Bool("verbose", false, "See packets")
	silent := flag.Bool("silent", false, "Only warnings and errors")

	flag.Parse()

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

	allowedMacsMap := mapLowerCaseMac(cfg.Devices)

	go packetCapture(cfg.NetInterface, srcMACAddress, poolsMap, vlanIPMap, allowedMacsMap, stop)
	go ownupNetworkAddresses(cfg.NetInterface, srcMACAddress, vlanIPMap, stop)

	// Create a channel to listen for SIGTERM or SIGINT signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// Block until a signal is received
	<-sigCh

	// Optionally, log or perform some cleanup
	slog.Info("Received termination signal. Exiting...")
}
