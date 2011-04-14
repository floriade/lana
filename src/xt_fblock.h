/*
 * Lightweight Autonomic Network Architecture
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#ifndef XT_FBLOCK_H
#define XT_FBLOCK_H

#include <linux/if.h>
#include <linux/skbuff.h>

struct functional_block;

struct functional_block_ops {
	int (*net_fb_rx)(struct functional_block *origin,
			 struct sk_buff *skb);
};

struct functional_block {
	char name[IFNAMSIZ];
	unsigned int cpu;
	u16 flags;
	u16 priv_flags;
	struct functional_block_ops *ops;
};

#endif /* XT_FBLOCK_H */
