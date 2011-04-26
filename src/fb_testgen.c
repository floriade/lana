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

#include "xt_builder.h"

static struct fblock *fb1, *fb2, *fb3;

static int __init init_fbtestgen_module(void)
{
	/* Only xt_user is actually doing this,
	 * just for testing purpose here. */

	fb1 = build_fblock_object("test", "fb1");
	if (!fb1)
		return -ENOMEM;
	fb2 = build_fblock_object("test", "fb2");
	if (!fb2) {
		unregister_fblock_namespace(fb1);
		return -ENOMEM;
	}
	fb3 = build_fblock_object("test", "fb3");
	if (!fb3) {
		unregister_fblock_namespace(fb1);
		unregister_fblock_namespace(fb2);
		return -ENOMEM;
	}

	printk(KERN_INFO "[lana] fbtestgen loaded!\n");
	return 0;
}

static void __exit cleanup_fbtestgen_module(void)
{
	unregister_fblock_namespace(fb1);
	unregister_fblock_namespace(fb2);
	unregister_fblock_namespace(fb3);
	printk(KERN_INFO "[lana] fbtestgen unloaded!\n");
}

module_init(init_fbtestgen_module);
module_exit(cleanup_fbtestgen_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA testgen module");
