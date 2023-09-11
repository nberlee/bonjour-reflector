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

	err = ethHandle.Change(iface, map[string]bool{
		"rx-vlan-filter": false,
	})
	if err != nil {
		slog.Error("Unable to remove the hardware vlan filter (rx-vlan-filter)", err)
	}

}
