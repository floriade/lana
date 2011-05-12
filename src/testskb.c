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

#define PKTS 140000UL
#define PKT_LEN 96

static int __init init_fbtestgen_module(void)
{
	unsigned long i;
	struct sk_buff **skba;

	ppesched_init();

	skba = kmalloc(sizeof(*skba) * PKTS, GFP_KERNEL);
	if (!skba)
		return -ENOMEM;
	memset(skba, 0, sizeof(*skba) * PKTS);
	for (i = 0; i < PKTS; ++i) {
		skba[i] = alloc_skb(PKT_LEN, GFP_KERNEL);
		if (unlikely(!skba[i]))
			goto err;
		skb_put(skba[i], 64);
		write_next_idp_to_skb(skba[i], IDP_UNKNOWN, IDP_UNKNOWN /*1*/);
	}

	time_mark_skb_first(skba[0]);
	time_mark_skb_first(skba[1]);
	time_mark_skb_first(skba[2]);
	time_mark_skb_first(skba[3]);

	time_mark_skb_last(skba[PKTS-1-3]);
	time_mark_skb_last(skba[PKTS-1-2]);
	time_mark_skb_last(skba[PKTS-1-1]);
	time_mark_skb_last(skba[PKTS-1-0]);

	for (i = 0; i < PKTS; ++i)
		ppesched_sched(skba[i], TYPE_EGRESS);

	kfree(skba);
	printk(KERN_INFO "test done, %lu pkts!\n", PKTS);
	return 0;
err:
	for (i = 0; i < PKTS; ++i) {
		if (skba[i])
			kfree_skb(skba[i]);
	}
	return -ENOMEM;
}

static void __exit cleanup_fbtestgen_module(void)
{
}

module_init(init_fbtestgen_module);
module_exit(cleanup_fbtestgen_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA testgen module");
