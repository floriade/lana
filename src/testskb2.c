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
#include "xt_engine.h"

#define PKTS 3000000UL
#define PKT_LEN 96

static int __init init_fbtestgen2_module(void)
{
	unsigned long i;
	ppesched_init();
	for (i = 0; i < PKTS; ++i) {
		struct sk_buff *skb = alloc_skb(PKT_LEN, GFP_ATOMIC);
		if (unlikely(!skb))
			break;
		skb_put(skb, 64);
		if (i < 4)
			time_mark_skb_first(skb);
		if (i >= PKTS-4)
			time_mark_skb_last(skb);
		write_next_idp_to_skb(skb, IDP_UNKNOWN, /*IDP_UNKNOWN*/ 1);
		ppesched_sched(skb, TYPE_EGRESS);
	}
	printk(KERN_INFO "test done, %lu pkts!\n", PKTS);
	return 0;
}

static void __exit cleanup_fbtestgen2_module(void)
{
}

module_init(init_fbtestgen2_module);
module_exit(cleanup_fbtestgen2_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA testgen module");
