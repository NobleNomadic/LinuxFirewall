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
MODULE_VERSION("0.1");

#define MAX_BLOCKED_PORTS 16
#define MAX_BLOCKED_IPS 16

typedef struct {
    int blocked_ports[MAX_BLOCKED_PORTS];
    // Store IPs in integer format for faster comparison
    __be32 blocked_IPs[MAX_BLOCKED_IPS];
} firewall_rules_config;

static firewall_rules_config global_firewall_rules;

static int inspect_packet(struct iphdr *iph) {
    int i;
    __be32 saddr = iph->saddr;

    // Check IP blocklist
    for (i = 0; i < MAX_BLOCKED_IPS && global_firewall_rules.blocked_IPs[i]; i++) {
        if (saddr == global_firewall_rules.blocked_IPs[i]) {
            return 1;
        }
    }

    // Check port blocklist
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
        unsigned short src_port = 0;

        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);
            src_port = ntohs(tcph->source);
        } else {
            struct udphdr *udph = (struct udphdr *)((__u32 *)iph + iph->ihl);
            src_port = ntohs(udph->source);
        }

        for (i = 0; i < MAX_BLOCKED_PORTS && global_firewall_rules.blocked_ports[i]; i++) {
            if (src_port == global_firewall_rules.blocked_ports[i]) {
                return 1;
            }
        }
    }

    return 0;
}

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

static struct nf_hook_ops netfilter_ops;

static int __init firewall_init(void) {
    global_firewall_rules.blocked_ports[0] = 0; // terminator
    global_firewall_rules.blocked_IPs[0] = 0; // terminator

    netfilter_ops.hook = firewall_hook;
    netfilter_ops.hooknum = NF_INET_PRE_ROUTING;
    netfilter_ops.pf = PF_INET;
    netfilter_ops.priority = NF_IP_PRI_FIRST;

    printk(KERN_INFO "[*] Linux firewall module loaded.\n");

    return nf_register_net_hook(&init_net, &netfilter_ops);
}

static void __exit firewall_exit(void) {
    nf_unregister_net_hook(&init_net, &netfilter_ops);
    printk(KERN_INFO "[*] Linux firewall module removed\n");
}

module_init(firewall_init);
module_exit(firewall_exit);
