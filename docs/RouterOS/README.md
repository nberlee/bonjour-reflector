
# Setup container and network

This step-by-step guide will help you setup your mikrotik router to run the reflector container. It assumes you have one bridge with vlans configured. The container will only respond to tagged vlans. Any untagged traffic will be dropped.

## Enable container support

1. Add the package containers by [downloading](https://mikrotik.com/download) the `extra package` for your CPU architecture, extract it and upload `container7.*-cpuarch.npk` to the root of your RouterOS, reboot.
2. After the reboot, make sure the package is installed by running `/system package print` (or winbox system -> packages) and check if the package is listed.
3. Enable container mode - Make sure you are in neighbourhood of your router and execute `/system/device-mode/update container=yes`, follow instructions on screen. Validate the container mode is enabled by running `/system/device-mode/print` and check if `container: yes` is listed.

## Setup network
Note: Best practice is for Docker installs to utilize a dedicated bridge for the containers, and in their [documentation](https://help.mikrotik.com/docs/display/ROS/Container) Mikrotik configures the same on your router. However, for this particular container this would not work, so do make sure to specify the actual bridge on which your VLANs run. 

1. Create a veth interface to be used by the reflector container, this interface will be used to connect the container to the bridge. The address and gateway are not used, but are required to create the interface. `/interface/veth/add name=veth1-reflector address=127.1.0.10/32 gateway=127.1.0.1` 

2. Create a bridge port for the veth interface. Make sure to change the `bridge=` to your bridge name. `ingress-filtering=no` on the port is really needed, not sure why, as in the next step we assign the vlans ids. use a non existent pvid, as it won't be needed. `/interface/bridge/port/add bridge=bridge1 edge=yes frame-types=admit-only-vlan-tagged ingress-filtering=no interface=veth1-reflector learn=yes multicast-router=permanent point-to-point=yes pvid=999`
3. Add `veth1-reflector` as tagged port to the vlans you want to use.

Change the `bridge` to your bridge and `vlan-ids` to the vlans you want to use.

Please note, these commands open an editor, to save the changes press `ctrl+o` to exit the editor. Interfaces are comma separated, so if you want to add multiple interfaces, add a comma between them.

```mikrotik
/interface/bridge/vlan/edit [/interface/bridge/vlan/find bridge=bridge1 vlan-ids=100] tagged
```
```mikrotik
/interface/bridge/vlan/edit [/interface/bridge/vlan/find bridge=bridge1 vlan-ids=101] tagged
```
```mikrotik
/interface/bridge/vlan/edit [/interface/bridge/vlan/find bridge=bridge1 vlan-ids=103] tagged
```

# Configure container
The container is only ~8MB on disk, if your router doesn't have a lot of storage, tmpfs can be used to store the container. See this youtube of Mikrotik for more info: https://www.youtube.com/watch?v=KO9wbarVPOk and make sure to replace the paths below with the tmpfs 'disk' path.

## Image pull configuration
The reflector container is hosted on github container registry. To be able to pull the image, you need to configure the registry. This can be done by adding a registry to the router. 

```mikrotik
/container config set registry-url=https://ghcr.io tmpdir=tmpfs/pull
```

The `tmpdir` can be any directory, if your router has enough memory it is recommended if you are using tmpfs.

## config.toml
The config.toml file is used to configure the reflector.

See the [config.md](../config.md) for detailed explaination.

Edit your own `config.toml` and upload it to your router in a directory, for example the default `/pub` directory, as its not strait forward to create a directory in RouterOS.

Afterwards changes may be done to the file without reuploading again, using:

```mikrotik
/file edit pub/config.toml
```

## Container mount
Create a container mount to the directory you uploaded the `config.toml` to. Make sure to change the `src` to the path you uploaded the file to.

```mikrotik
/container mounts add dst=/config name=reflector-config src=/pub
```
(RouterOS can only mount directories, not files.)

## Container logging
RouterOS doesn't show the container logs in the log viewer as the loglevel is not high enough. This can be changed by adding a logging rule.

```mikrotik
/system logging add topics=container
```


## Create container
Creating the container is better to be done using a script. As updating a container in RouterOS is still relatively hard, and there is no docker-compose way of doing it, we need to remove the old container and create a new one. The script below will do this for you. Replace the `containers/` in `rootdir` with the directory you want to store the container incase you are using tmpfs. 

If you just want to test:
```mikrotik
/container/add remote-image=ghcr.io/nberlee/bonjour-reflector:main int=veth1-reflector root-dir=containers/reflector mounts=reflector-config logging=yes start-on-boot="yes" comment="bonjour-reflector"
```


A more permanent, status checking, and updating script:
```mikrotik
/system script add dont-require-permissions=no name=recreate-reflector-container owner=admin policy=read,write,test source=":local tag \"ghcr.io/nberlee/bonjour-reflector:main\";\r\
    \n:local interface \"veth1-reflector\";\r\
    \n:local containerLogging \"yes\";\r\
    \n:local mount \"reflector-config\";\r\
    \n:local rootdir \"containers/reflector\";\r\
    \n\r\
    \n#pinghost for internet connectivity check\r\
    \n:local pinghost \"ghcr.io\";\r\
    \n\r\
    \n# check if container is already running and remove stopped containers\r\
    \nforeach container in=[/container/find tag=\$tag] do={\r\
    \n  :local status [/container/get \$container status];\r\
    \n  if (\$status != \"running\") do={\r\
    \n    /container/remove \$container;\r\
    \n  }\r\
    \n  if (\$status = \"running\") do={\r\
    \n    :error \"container already running\";\r\
    \n  }\r\
    \n}\r\
    \n\r\
    \n# test if we have internet connectivity\r\
    \n:local continue true;\r\
    \n:while (\$continue) do={\r\
    \n  do {\r\
    \n    /ping address=\$pinghost count=1;\r\
    \n    :set continue false;\r\
    \n   } on-error={\r\
    \n    delay 1s;\r\
    \n  }\r\
    \n} \r\
    \n\r\
    \n:local reflector [/container/add remote-image=\$tag int=\$interface root-dir=\$rootdir mounts=\$mount logging=\$containerLogging start-on-boot=\"yes\" comment=\"bonjour-reflector\"];\r\
    \n:while ([/container/get \$reflector status] != \"stopped\") do={ :delay 1s; }\r\
    \n/container/start \$reflector;\r\
    \n\r\
    \n"
```
execute the script
```mikrotik
/system/script/run recreate-reflector-container
```

observe your container is running:
```mikrotik
/container/print
```

You may want to add the script to the scheduler to run it every 5 minutes or at boot. This way the container will be recreated if it crashes or is stopped for some reason.

## Update container
The script can be used to update the container as well. Just stop the container and start the script in the future.

# Troubleshooting
The container is minimal and has no shell. So you can't login to the container. You can however check the logs by looking in the RouterOS log.
## Container not starting
Check the RouterOS log for errors. If you see the following error:
```
Could not find config file
```
This means the container could not find the `config.toml` file. Make sure you uploaded the file to the correct directory and mounted it correctly.

---
```
failure: could not add
```
Please make sure your RouterOS has enabled container support. See step 3 in `Enable container support`.

---
## No MDNS/SSDP is reflected
Make sure traffic is going into the container and is coming out. You can do see this in winbox with the following steps:
1. Tools -> Packet Sniffer
2. Tab Filter, Interfaces -> select veth1-reflector
3. Make sure direction is any and no other filters are set. Press Apply, then press Start. 
4. Press Packets and add VLAN to the columns. by clicking on the arrow next to the column names -> Show Columns -> VLAN -> OK
5. Do not forget to stop the packet sniffer when you are done.

* tx = packets going into the container
* rx = packets coming out of the container

If you see packets going in but not coming out, run the container in verbose mode by adding `/bonjour-reflector -verbose` to Cmd in the container settings. Then check the RouterOS logs. You should all packets that are actionable by the reflector. These include:
* SSDP query packet received:
* SSDP advertisement packet received:
* SSDP query response packet received:
* Bonjour packet received:
* Packet sent:
* Replied to %v for ip %s

Were `response packet` means that there is actual SSDP sessions set up. Which is a good sign.

If you see packets coming out of the container but no response packet are received make absolute sure you have assigned the correct vlan ids on the bridge for the veth1-reflector interface. Also check if the veth1-reflector interface port is set to `ingress-filtering=no` and `frame-types=admit-only-vlan-tagged`.

