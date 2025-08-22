# LinuxFirewall
Simple Linux kernel firewall module.

This module intercepts all incoming and outgoing packets and allows or denies them based on a set of rules.

## Installing LinuxFirewall
Download the source code.
To do set the rules for the firewall, edit the code in the `load-firewall_configuration()` function.
Here you can set the list of blocked ports and IPs. <br>
Below is an example of a configuration that blocks 8.8.8.8, and port 22. This code would be added into the configuration function
```c
// Block port 22
global_firewall_rules.blocked_ports[0] = 22;

// Block 8.8.8.8
global_firewall_rules.blocked_IPs[0] = in_aton("8.8.8.8");

// Update the termination positions for each array
global_firewall_rules.blocked_ports[1] = 0;
global_firewall_rules.blocked_IPs[1] = 0;
```
Then compile it with `make`. You can then run
```bash
sudo insmod linuxFirewall.ko
```
You can load it with `insmod`
```bash
sudo insmod linuxFirewall.ko
```
You can check logs with `dmesg`
```bash
sudo dmesg | tail
```
It can be unloaded using `rmmod`
```bash
sudo rmmod linuxFirewall
```
