The config.toml file is used to configure the reflector.

* `net_interface` is the interface the container will use to send and receive packets. In a container this is always `eth0`.
* `devices` is a list of devices that will be available to the `shared_pools` vlan ids. Only devices that are listed here will be available to the shared_pools. The `origin_pool` is the vlan id that the device is connected to. The `shared_pools` are the vlan ids that the device will be available to.

This example we have the following networks:
* Media network `100`, the reflector will use ip `192.168.100.2` on this network.
* Client network `101`, the reflector will use ip `192.168.101.2` on this network.
* IoT network `103`, the reflector will use ip `192.168.103.2` on this network.

In this example the following devices are available to the networks:
* Bedroom TV `71:27:06:20:A7:E6` is connected to the media network `100` and is available to the client network `101` and IoT network `103`.
* Onkyo amplifier `01:10:B1:E1:69:98` is connected to the media network `100` and is available to the client network `101` and IoT network `103`.
* NVidia Shield `00:04:4B:5D:F2:D3` is connected to the media network `100` and is available to the client network `101` and IoT network `103`.
* Volumio bathroom `DC:A6:32:2B:31:19` is connected to the IoT network `103` and is available to the client network `101`.

Please note, this is not bidirectional. This means in this example the reflector will deny initiated MDNS/SSDP from the Nvidia Shield in `100` to connect to the client network. But it will allow the client network to connect to the Nvidia Shield in `100`. So `origin_pool` is the network the device is connected to, and `shared_pools` are the networks the device is available to.

```toml
net_interface = "eth0"

[devices]

    [devices."71:27:06:20:A7:E6"]
    description = "Bedroom TV"
    origin_pool = 100
    shared_pools = [101, 103]

    [devices."01:10:B1:E1:69:98"]
    description = "Onkyo amplifier"
    origin_pool = 100
    shared_pools = [101, 103]

    [devices."00:04:4B:5D:F2:D3"]
    description = "NVidia Shield"
    origin_pool = 100
    shared_pools = [101, 103]

    [devices."DC:A6:32:2B:31:19"]
    description = "Volumio bathroom"
    origin_pool = 103
    shared_pools = [101]

[vlan]

    [vlan.100]
    ip_source = "192.168.100.2"

    [vlan.101]
    ip_source = "192.168.101.2"

    [vlan.103]
    ip_source = "192.168.103.2"
```