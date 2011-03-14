/*
 * Lightweight Autonomic Network Architecture
 *
 * LANA vlink control messages via netlink socket. This allows userspace
 * applications like 'vlink' to control the whole LANA vlink layer.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/module.h>
#include <linux/kernel.h>

static int __init init_nlvlink_module(void)
{
	printk(KERN_INFO "LANA netlink vlink layer loaded!\n");
	return 0;
}

static void __exit cleanup_nlvlink_module(void)
{
	printk(KERN_INFO "LANA netlink vlink layer removed!\n");
}

module_init(init_nlvlink_module);
module_exit(cleanup_nlvlink_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("Netlink subsystem for LANA virtual link layer drivers");
