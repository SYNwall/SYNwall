# SYNwall use case

We can make a quick example to show one of many use cases where a SYNwall-like approach can be useful. This comes from a real-world scenario we saw several time.



## Scenario

In our scenario we are providing Hardware control devices for Electrical Power Stations in the wild. These Power Stations are placed in a lot of places without Network connectivity (mountains, etc), so we bought a satellite access from a 3rd party provider.

<img src="https://github.com/SYNwall/SYNwall_site/blob/master/assets/images/SYNwall_use_case_1.png" width="600" height="400" />

The Connectivity Provider gave us an access to a subnet, which is shared with others system and devices we do not own or control, so we can consider this environment hostile, even if not placed on a public access network.



## Possible solutions

We can face this situation in several ways, by using some technologies like VPN or Firewalls, but all these solutions are sub-optimal:

- the device number is huge, we can not install physical firewall for each
- the number of devices changes very often, with new installations. Configuration of local firewalls with an IP approach will be cumbersome
- the devices are battery powered, any useless power drain should be avoided



## The SYNwall approach

With the SYNwall module we can address all our issues: by deploying a single module on all the devices, we are going to reach our final goals:

- isolate from the network the devices
- leave the devices communicating each other in a mesh network
- avoid any maintenance when a device is added or removed and keep maintenance activity at minimum
- provide a secure and super-light way to protect all our systems

<img src="https://github.com/SYNwall/SYNwall_site/blob/master/assets/images/SYNwall_use_case_2.png" width="600" height="400" />



## Creating the module

Depending on your situation (how many different versions of OS you are running on your end devices) you may decide to follow different approaches:

- pre-compile the module before distribution (which is probably the best way to go)
- send-out sources and compile in places (if the environment is available)
- pre-install the module on your newly deployed devices

In the first two cases, the [AWX](https://github.com/SYNwall/SYNwall_distrib) module provided in the SYNwall package, can helps you in scaling these activities

Creating the module is straightforward:

```
# sudo apt-get install linux-headers-$(uname -r)
# git clone https://github.com/SYNwall/SYNwall.git
# cd SYNwall
# make
```

You can also cross-compile module by setting some environment variables in the proper way:

```
ARCH                     ---> Target Architecture
CROSS_COMPILE            ---> Toolchain Path
KERNEL                   ---> Kernel Sources (header at least)
```



## Installing

Once the module is on the end device, the installation is simple as an `insmod`

```
sudo insmod SYNwall.ko psk=123456789012345678901234567890123 precision=10 portk=12,13,14,15,16 load_delay=10000 enable_udp=1
```

The important part here is the `PSK`: this key will be shared between all the devices to grant access to them and create the isolated mesh in the hostile environment. As all the `PSKs` this must be kept secret, rotated if needed, and all the other thing we usually do with `PSKs`.

For all the other parameter and instructions, see the main [README](https://github.com/SYNwall/SYNwall/blob/master/README.md).



## Managing

In order to keep access to our end devices once the SYNwall has been installed, you need alternatively:

- a system (PC, Server, etc) with SYNwall installed
- a proxy with SYNgate installed (a customized SYNwall module build to act as a gateway for connections, see [README](https://github.com/SYNwall/SYNwall/blob/master/README.md))
