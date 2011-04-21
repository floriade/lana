/*
 * Lightweight Autonomic Network Architecture
 *
 * Builds Functional Block objects requested by its type. Holds global
 * reference to all registered functional blocks. Invoked from userspace
 * via xt_user Netlink.
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

int register_fblock_type(struct fblock_factory_ops *fops)
{
	return critbit_insert(&fbmap, fops->type);
}
EXPORT_SYMBOL_GPL(register_fblock_type);

void unregister_fblock_type(struct fblock_factory_ops *fops)
{
	critbit_delete(&fbmap, fops->type);
}
EXPORT_SYMBOL_GPL(unregister_fblock_type);

struct fblock *build_fblock_object(char *type, char *name, void *priv,
				   unsigned long flags, struct fblock_ops *ops)
{
	struct fblock *fb;
	struct fblock_factory_ops *fops = struct_of(critbit_get(&fbmap, type),
						    struct fblock_factory_ops);
	fb = fops->ctor(name, priv, flags, ops);
	if (!fb)
		return NULL;
	fb->fops = fops;
	return fb;
}
EXPORT_SYMBOL(build_fblock_object);

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

