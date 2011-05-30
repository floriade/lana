/*
 * Lightweight Autonomic Network Architecture
 *
 * Dummy test module.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/cpu.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>

#include "xt_skb.h"
#include "xt_idp.h"
#include "xt_engine.h"

struct testhdr {
	char payload[32];
};

static int __init init_fbtestgen_module(void)
{
	size_t len = 0, nethdr_len = 0;
	struct sk_buff *skb;
	struct net_device *dev;
	struct ethhdr *eth;
	struct testhdr *testh;

	dev = dev_get_by_name(&init_net, "eth10");
	if (!dev)
		return -ENOENT;
	if (!netif_device_present(dev) || !netif_running(dev))
		return -EIO;
	len += LL_RESERVED_SPACE(dev);
	len += sizeof(struct ethhdr);
	len += sizeof(struct testhdr);
	skb = alloc_skb(len, GFP_KERNEL);
	if (unlikely(!skb))
		return -ENOMEM;
	skb_reserve(skb, LL_RESERVED_SPACE(dev));
	skb->dev = dev;
	eth = (struct ethhdr *) skb_put(skb, sizeof(*eth));
	eth->h_proto = skb->protocol = cpu_to_be16(0xFEFE);
	memset(eth->h_dest, 0xFF, ETH_ALEN);
	memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
	nethdr_len += sizeof(*eth);
	skb_set_network_header(skb, nethdr_len);
	testh = (struct testhdr *) skb_put(skb, sizeof(*testh));
	memset(testh->payload, 0xAE, sizeof(testh->payload));

	write_next_idp_to_skb(skb, IDP_UNKNOWN, /*IDP_UNKNOWN*/ 1);
	process_packet(skb, TYPE_INGRESS);

	return 0;
}

static void __exit cleanup_fbtestgen_module(void)
{
}

module_init(init_fbtestgen_module);
module_exit(cleanup_fbtestgen_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA testgen module");

