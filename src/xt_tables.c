/*
 * Lightweight Autonomic Network Architecture
 *
 * Global LANA IDP translation tables, core backend.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/atomic.h>

#include "xt_tables.h"
#include "xt_fblock.h"

struct idp_fb_elem {
	struct functional_block *fblock;
	struct idp_fb_elem *next;
	struct rcu_head rcu;
	atomic_t refcnt;
};

int init_tables(void)
{
	return 0;
}
EXPORT_SYMBOL_GPL(init_tables);

void cleanup_tables(void)
{
}
EXPORT_SYMBOL_GPL(cleanup_tables);

