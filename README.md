SYNwall 
=======
Zero config (IoT) firewall.

SYNwall is a project built (for the time being) as a Linux Kernel Module, to implement a transparent and no-config/no-maintenance firewall.

Basics
------

Usually IoT devices are out of a central control, with low profile hardware, tough environmental conditions and...we have no time to dedicate to maintain the security.
So, may be we can not patch our IoT infrastructure and it will be very hard to maintain a "firewall-like" access control.

The idea is to create a de-centralized one-way OneTimePassword code to enable the NETWORK access to the device. All the traffic not containing the OTP will be discarded.
No prior knowledge about who need to access is required, we just need a Pre-Shared Key to deploy. The protection will be completely transparent to the application level, because implemented at network protocol level (TCP and UDP).

Install
-------

This repository contains the Linux Kernel module. It has been tested with **3.x, 4.x and 5.x** version on **X86_64, ARM, MIPS and AARCH64** architecures.

It requires the current kernel headers for compilation, which can be usually installed with the proper package manager. For example on Debian like distros

```sudo apt-get install linux-headers-$(uname -r)```

Than, it should be enough to run the compilation:

```make```

Configuration
-------------

The module can be loaded in the usual way, with ```insmod``` or ```modprobe```. 

It has several parameters that allow you to cusomize the behaviour:

- Pre-Shared Key used for the OneTimePassword

  psk: ""

  The PSK, must be a sequence of bytes from 32 to 1024. It will be part of the OTP, so the length of it will influence the size of the OTP injected in the packet. Without this parameter, the module will not load.

- Enable UDP

  enable_udp: 0

  Enable/Disable the OTP for UDP protocol. By default it is **disabled**. Set to **1** to enable it. The OTP on UDP requires the module to be active on both of the communicating devices, since the OTP must be removed (by the module) before the packet is forwarded to the application level. If this is not true, you may experience weird behaviors.
  The UDP connection tracking, relies on **conntrack** module, so you may have to insert it to use this functionality (this depends on the installation). An error will be displayed in the kernel log if so.

- Time precision parameter

  precision: 10

  The OTP is computed also with the current device time. Since the date could be different on the participating devices, you can "round" the time on a specific value, to allow time skew. Default is **10**.

  The precision is expressed in power of two (you may argue why...it has been a decision to increase performance and have low impact on low end devices
       ...
       9   ->   1 second
       10  ->   8 seconds
       ...

- Disable the OTP for outgoing packets

  disable_out: 0

  You may want to disable the OTP in outgoing packet, by settings this to **1**. In this case the module will just drop the packets without OTP, but it will not participate to the communication mesh with other SYNwall devices. It can be useful in case of issues with the outgoing packets on uplink devices.

- Enable DoS protection

  enable_antidos: 0

  This option can be enabled by setting this to **1**. If set, this will limit the OTP computation on the device to a given number (```allow_otp_ms``` variable, set to 1000 by default). In this case, only one OTP computation per second is allowed, preserving the CPU time of the device in case of a DoS attack.

- Enable IP Spoofing protection

  enable_antispoof: 0

  By default the IP is not part of the OTP. This could lead to some replay attack. You can enable the antispoof protection to be fully safe. This may break the communication if some NATs are in place between the devices.

- Delay in starting up the module functionalities (ms)

  load_delay: 10000

  You can decide to wait a while before activating the protection after the module load. This could be useful, in case of issues and after a reboot, to gain access to the device. The default is 10 seconds.

- List of ports for port knocking failsafe

  portk: 0,0,0,0,0

  If the device clock is going bananas, it could be difficult to get access. One way could be the "delay" discussed before, but you can also set a sequence of "port knocking" which can disable the module for a while. The list, if defined, must be of 5 TCP ports. 
  If the module identify a SYN packet on these ports in one second, it disable itself for the same time set as "load_delay". **NOTE**: if you actively use the sequence, remember to change it, since it can be easily sniffed!

Example of usage
----------------

**_WARNING_**: this is going to drop all the traffic to your device, so be sure to know how to access with another SYNwall device or by disabling it remotely (port knocking).

```sudo insmod SYNwall.ko psk="123456789012345678901234567890123" precision=10 portk=12,13,14,15,16 load_delay=5000 enable_udp=1```

Project Structure
-----------------

**SYNwall** repository:

   - SYNwall_netfilter (.c and .h): Netfilter main package, with hooks and basic process functions
      - SYNauth (.c and .h): authentication functins, used to manage hashes and crypt stuff
      - SYNquark (.c and .h): Quark hashing implementation, directly based on the work done by Jean-Philippe Aumasson (@veorq)
   - SYNgate_netfilter (.c and .h): Netfilter package for SOCKS server module. It implements only the "outgoing" packet marking and
                                    is able to manage multiple PSK and Networks

**SYNwall_distrib** repository:
   - Ansible scripts for automatic distribution. See README.md there

Performances
------------

Everything has been implemented to be used on low end devices, with very low resources. The choice of Quark hashing for the crpyto hash has been done for this reason. The overhead added by the OTP computation is almost invisible in the regular usage:

![low](https://github.com/SYNwall/SYNwall_site/blob/master/assets/images/synwall_constant_load.png)

whilst you can see a consistent CPU saving when a lot of traffic is sent to the device:

![high](https://github.com/SYNwall/SYNwall_site/blob/master/assets/images/synwall_heavy_load.png)

SYNgate
-------

As a companion tool, the repository has also the **SYNgate** module. The **SYNgate** has been built with the same logic of the base module **SYNwall**, but it is working for multiple networks and PSK. You can define a multiple set of networks (with the related PSK and other options). The idea is to install it on a SOCKS server, to allow to use it for different protocols and destinations. The [SYNwall_VM](https://github.com/SYNwall/SYNwall_VM) repository contains some script to build such a system with a SOCKS server and the module pre-installed.

**SYNgate** is working only on **outgoing** traffic.


SYNgate Configuration
---------------------

The module can be loaded in the usual way, with ```insmod``` or ```modprobe```.

It has several parameters that allow you to cusomize the behaviour. It is very similar to the **SYNwall** configuration, but with a different logic: parameters are (comma separated) list of values. The first value of a list correspond to the first of the others. Not all params are available, just the ones that make sense (remember the SYNgate will not affect incoming traffic):

It has only one paramter different from the **SYNwall** config, the **dstnet_list**

- Destination network

  dstnet_list: ""

  List of networks in the IP/MASK format. Example: 192.168.1.0/24. If an IP is given (instead of network address), the network will be computed. All the IPs belonging to this network, will have the connection parameters (PSK, precision, etc) specified in the oter lists, at the same array index.

- Pre-Shared Key used for the OneTimePassword

  psk_list: ""

  The PSK, must be a sequence of bytes from 32 to 1024. It will be part of the OTP, so the length of it will influence the size of the OTP injected in the packet. Without this parameter, the module will not load.

- Enable UDP

  enable_udp_list: 0

  Enable/Disable the OTP for UDP protocol. By default it is **disabled**. Set to **1** to enable it. The OTP on UDP requires the module to be active on both of the communicating devices, since the OTP must be removed (by the module) before the packet is forwarded to the application level. If this is not true, you may experience weird behaviors.
  The UDP connection tracking, relies on **conntrack** module, so you may have to insert it to use this functionality (this depends on the installation). An error will be displayed in the kernel log if so.

- Time precision parameter

  precision_list: 10

  The OTP is computed also with the current device time. Since the date could be different on the participating devices, you can "round" the time on a specific value, to allow time skew.

  The precision is expressed in power of two (you may argue why...it has been a decision to increase performance and have low impact on low end devices
       ...
       9   ->   1 second
       10  ->   8 seconds
       ...

- Enable IP Spoofing protection

  enable_antispoof_list: 0

  By default the IP is not part of the OTP. This could lead to some replay attack. You can enable the antispoof protection to be fully safe. This may break the communication if some NATs are in place between the devices.


License
-------
GPL-3.0

Author Information
------------------
Sorint.Lab
