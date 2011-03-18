/*
 * Lightweight Autonomic Network Architecture
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/module.h>
#include <linux/kernel.h>

#include "fb_glue.h"

static int __init init_lana_core_module(void)
{
	printk(KERN_INFO "[lana] core loaded!\n");
	return 0;
}

static void __exit cleanup_lana_core_module(void)
{
	printk(KERN_INFO "[lana] core removed!\n");
}

module_init(init_lana_core_module);
module_exit(cleanup_lana_core_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA core driver");

