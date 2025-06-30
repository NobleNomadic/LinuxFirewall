#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <stdio.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NobleNomadic");
MODULE_DESCRIPTION("Firewall module to filter data that is sent into the kernel");
MOODULE_VERSION("0.1");

// Struct for simplifying packet data for processing
static struct packet_data {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct icmphdr *icmp_header;
    struct arphdr *arp_header;
    struct ethhdr *eth_header;
    struct sock *socket;
    struct sk_buff *skb;
};

// Struct to contain the firewall rules loaded from a file
// Single rule
static struct firewall_rule {
    unsigned int source_ip;          // Public IP where the packet came from
    unsigned short source_port;      // The port the packet is coming from
    unsigned short destination_port; // The port the packet is going to
    unsigned char protocol;          // The protocal used (TCP, UDP, etc)
    unsigned char action;            // Action to run on packet (block source IP, drop packet, etc)
};
// Main array of rules

// Struct for the hook
static struct nf_hook_ops netfilter_ops;

// Module init
// Make a log and register the firewall module so that all network data is processed with the hook function
static int __init firewallInit(void) {
    // Register hook globally with the kernel
    netfilter_ops.hook = firewallHook;
    netfilter_ops.hooknum = NF_INET_PRE_ROUTING;
    netfilter_ops.pf = PF_INET;
    netfilter_ops.priority = NF_IP_PRI_FIRST;

    // Make a log to show module loaded successfully
    printk(KERN_INFO "[*] Linux firewall module loaded.\n");

    // Register the hook
    return nf_register_hook(&init_net, &netfilter_ops);
}

// Hook function to process data from packets
// Return NF_ACCEPT to allow the packet to pass through
// Return NF_DROP to drop the packet
static unsigned int firewallHook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    // Get the packet as a struct
    struct iphdr *iph = ip_hdr(skb);

    // Pass the packet through the rules file
    // Load the rules and convert them to a structure to run checks on

    // If the packet makes it to the end of the function rule checks, it passes. Make a kern_info log of this
    printk(KERN_INFO "[*] Packet accepted from: %pI4\n", &iph->saddr);
    return NF_ACCEPT;
}

// Exit function
static void __exit firewallExit(void) {
    printk(KERN_INFO "[*] Linux firewall module removed\n");
}
