package main

import (
	"io/ioutil"
	"net"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml"
	"github.com/sirupsen/logrus"
)

type macAddress string

type config struct {
	NetInterface string                         `toml:"net_interface"`
	Devices      map[macAddress]multicastDevice `toml:"devices"`
	VlanIPSource map[vlanID]vlanIpSource        `toml:"vlan"`
}

type multicastDevice struct {
	OriginPool  uint16   `toml:"origin_pool"`
	SharedPools []uint16 `toml:"shared_pools"`
}

type vlanID string
type vlanIpSource struct {
	IpSource net.IP `toml:"ip_source"`
}

func readConfig(path string) (cfg config, err error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return config{}, err
	}
	err = toml.Unmarshal(content, &cfg)
	return cfg, err
}

func mapByPool(devices map[macAddress]multicastDevice) map[uint16]([]uint16) {
	seen := make(map[uint16]map[uint16]bool)
	poolsMap := make(map[uint16]([]uint16))
	for _, device := range devices {
		for _, pool := range device.SharedPools {
			if _, ok := seen[pool]; !ok {
				seen[pool] = make(map[uint16]bool)
			}
			if _, ok := seen[pool][device.OriginPool]; !ok {
				seen[pool][device.OriginPool] = true
				poolsMap[pool] = append(poolsMap[pool], device.OriginPool)
			}
		}
	}
	return poolsMap
}

func mapIpSourceByVlan(vlanipsource map[vlanID]vlanIpSource) map[uint16](net.IP) {
	vlanMap := make(map[uint16](net.IP))
	for vlan, value := range vlanipsource {
		vlanID, err := strconv.Atoi(string(vlan))
		if err != nil {
			logrus.Errorf("cannot decode %s to vlanID\n", vlan)
			continue
		}
		vlanMap[uint16(vlanID)] = value.IpSource
	}
	return vlanMap
}

func mapLowerCaseMac(devices map[macAddress]multicastDevice) map[macAddress]multicastDevice {
	newDevices := make(map[macAddress]multicastDevice)
	for mac, device := range devices {
		lowerCaseMac := strings.ToLower(string(mac))

		newDevices[macAddress(lowerCaseMac)] = device
	}
	return newDevices
}
