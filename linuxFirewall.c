/*
 * linuxFirewall.c - Example firewall Linux kernel module
 *
 * Copyright (C) 2025 NobleNomadic
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/inet.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NobleNomadic");
MODULE_DESCRIPTION("Firewall module to filter data that is sent into the kernel");
MODULE_VERSION("1.1");

#define MAX_BLOCKED_PORTS 512
#define MAX_BLOCKED_IPS 512

// Structure to store a rule for the firewall
typedef struct {
    // Store blocked ports in a list of a integers
    int blocked_ports[MAX_BLOCKED_PORTS];
    // Store IPs in integer format for faster comparison
    __be32 blocked_IPs[MAX_BLOCKED_IPS];
} firewall_rules_config;
// In each array is the list of IPs and ports with a 0 to terminate the list

static firewall_rules_config global_firewall_rules;

// Compare the packet header with the rules in the firewall strucutre
// Return 1 if a rule is triggered, 0 for ok
static int inspect_packet(struct iphdr *iph) {
    int i;
    __be32 saddr = iph->saddr;

    // Check IP blocklist
    // Loop over the ports in the firewall rules and compare the IP
    for (i = 0; i < MAX_BLOCKED_IPS && global_firewall_rules.blocked_IPs[i]; i++) {
        if (saddr == global_firewall_rules.blocked_IPs[i]) {
            return 1;
        }
    }

    // Check port blocklist if it came from a UDP or TCP port
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
        unsigned short src_port = 0;

        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);
            src_port = ntohs(tcph->source);
        }

        else {
            struct udphdr *udph = (struct udphdr *)((__u32 *)iph + iph->ihl);
            src_port = ntohs(udph->source);
        }

        // Loop over the list of blocked ports
        for (i = 0; i < MAX_BLOCKED_PORTS && global_firewall_rules.blocked_ports[i]; i++) {
            // If the current port matches the one where the packet came from, then return 1 to drop the packet
            if (src_port == global_firewall_rules.blocked_ports[i]) {
                return 1;
            }
        }
    }
    // Return 0 to allow packet to continue to kernel
    return 0;
}

// Hook function
// All packets are redirected to the hook and are either accepted or dropped based on the firewall rules configuration
static unsigned int firewall_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph = ip_hdr(skb);

    if (!iph)
        return NF_ACCEPT;

    if (inspect_packet(iph)) {
        printk(KERN_INFO "[*] Dropped packet from: %pI4\n", &iph->saddr);
        return NF_DROP;
    }

    printk(KERN_INFO "[*] Accepted packet from: %pI4\n", &iph->saddr);
    return NF_ACCEPT;
}

// Struct needed to register the hook function with the kernel
static struct nf_hook_ops netfilter_ops;

// Here you can define the rules you want your firewall to have
static int load_firewall_configuration(void) {
    // Here you can define the list of ports and IPs you want to block
    // Make sure to update the terminater value positions below

    // Set the terminator value
    global_firewall_rules.blocked_ports[0] = 0;
    global_firewall_rules.blocked_IPs[0] = 0;
    return 0;
}

// Firewall startup function. Register the hook, make a log, and setup the firewall rules.
static int __init firewall_init(void) {
    // Load the configuration
    load_firewall_configuration();

    // Register hook so that all information is checked with the hook before continuing
    netfilter_ops.hook = firewall_hook;
    netfilter_ops.hooknum = NF_INET_PRE_ROUTING;
    netfilter_ops.pf = PF_INET;
    netfilter_ops.priority = NF_IP_PRI_FIRST;

    printk(KERN_INFO "[*] Linux firewall module loaded.\n");

    return nf_register_net_hook(&init_net, &netfilter_ops);
}

// Unregister the hook with netfilter and make a log
static void __exit firewall_exit(void) {
    nf_unregister_net_hook(&init_net, &netfilter_ops);
    printk(KERN_INFO "[*] Linux firewall module removed\n");
}

module_init(firewall_init);
module_exit(firewall_exit);
