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

// Each incoming packet is redirected to the firewall hook function
// The data for the firewall rules are stored in a struct, and compared with the data of the packet
// If the packet matches the rules, the hook function returns NF_ACCEPT, allowing the packet to pass through
// If the packet does not match the rules, the hook function returns NF_DROP, dropping the packet

// Module init
// Make a log and register the firewall module so that all network data is processed with the hook function
static int __init firewallInit(void) {
    // Register hook globally with the kernel
    netfilter_ops.hook = firewallHook;
    netfilter_ops.hooknum = NF_INET_PRE_ROUTING;
    netfilter_ops.pf = PF_INET;
    netfilter_ops.priority = NF_IP_PRI_FIRST;

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

    // Pass the packet through the rules filter here

    // If the packet makes it to the end of the function rule checks, it passes
    // Make a kern_info log of this, there is no need to give a warning or error
    printk(KERN_INFO "[*] Packet accepted from: %pI4\n", &iph->saddr);
    return NF_ACCEPT;
}

// Exit function
static void __exit firewallExit(void) {
    printk(KERN_INFO "[*] Linux firewall module removed\n");
}
