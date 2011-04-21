/*
 * Lightweight Autonomic Network Architecture
 *
 * Builds Functional Block objects requested by its type. Holds global
 * reference to all registered functional blocks.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include "xt_critbit.h"
#include "xt_builder.h"
#include "xt_fblock.h"

static struct critbit_tree fbmap;

int register_fblock_type(char *name)
{
	return 0;
}
EXPORT_SYMBOL_GPL(register_fblock_type);

void unregister_fblock_type(char *name)
{
}
EXPORT_SYMBOL_GPL(unregister_fblock_type);

int init_fblock_builder(void)
{
	get_critbit_cache();
	critbit_init_tree(&fbmap);
	return 0;
}
EXPORT_SYMBOL_GPL(init_fblock_builder);

void cleanup_fblock_builder(void)
{
	put_critbit_cache();
}
EXPORT_SYMBOL_GPL(cleanup_fblock_builder);

