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

#include "xt_skb.h"
#include "xt_idp.h"
#include "xt_sched.h"

#define PKTS 1400000UL

static int __init init_fbtestgen_module(void)
{
	unsigned long num = PKTS;
	struct sk_buff *skb;
	ppesched_init();

	while (num--) {
		skb = alloc_skb(96, GFP_ATOMIC);
		if (unlikely(!skb))
			return -ENOMEM;
		if (num > 1400000UL - 4)
			time_mark_skb_first(skb);
		if (num < 4)
			time_mark_skb_last(skb);
		skb_put(skb, 64);
		write_next_idp_to_skb(skb, IDP_UNKNOWN, 1 /* idp 1 */);
		ppesched_sched(skb, TYPE_EGRESS);
	}

	printk(KERN_INFO "test done, %lu pkts!\n", PKTS);
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
