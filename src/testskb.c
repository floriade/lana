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

static int __init init_fbtestgen_module(void)
{
	struct sk_buff *skb;

	skb = alloc_skb(250, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	write_next_idp_to_skb(skb, IDP_UNKNOWN, 1);
	/* Assuming scheduler is loaded! */
	ppesched_init();
	ppesched_sched(skb, TYPE_EGRESS);
	printk(KERN_INFO "skb enqueued!\n");

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
