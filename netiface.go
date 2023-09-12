package main

import (
	"log/slog"

	"github.com/safchain/ethtool"
)

func removeVlanFilter(iface string) {
	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		panic(err.Error())
	}
	defer ethHandle.Close()

	features, err := ethHandle.Features(iface)
	if err != nil {
		slog.Error("Unable to get features for interface", iface, err)
		return
	}
	if !features["rx-vlan-filter"] {
		return
	}

	slog.Info("Hardware vlan filter (rx-vlan-filter) is enabled, disabling it")

	err = ethHandle.Change(iface, map[string]bool{
		"rx-vlan-filter": false,
	})
	if err != nil {
		slog.Error("Unable to remove the hardware vlan filter (rx-vlan-filter)", err)
	}

}
