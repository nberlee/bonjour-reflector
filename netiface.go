package main

import (
	"github.com/safchain/ethtool"
	"github.com/sirupsen/logrus"
)

func removeVlanFilter(iface string) {
	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		panic(err.Error())
	}
	defer ethHandle.Close()

	features, err := ethHandle.Features(iface)
	if err != nil {
		logrus.Errorf("Unable to get all interface features of %s: %v", iface, err)
		return
	}

	if !features["rx-vlan-filter"] {
		return
	}

	logrus.Infof("Changing hardware vlan filter (rx-vlan-filter) of interface %s to false.", iface)
	err = ethHandle.Change(iface, map[string]bool{
		"rx-vlan-filter": false,
	})
	if err != nil {
		logrus.Errorf("Unable to remove the hardware vlan filter (rx-vlan-filter): %v", err)
	}

}
