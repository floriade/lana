/*
 * Lightweight Autonomic Network Architecture
 *
 * Collector and loader for all core extensions (xt_*).
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <net/net_namespace.h>

#include "xt_fblock.h"
#include "xt_vlink.h"
#include "xt_engine.h"
#include "xt_tables.h"

struct proc_dir_entry *lana_proc_dir;
EXPORT_SYMBOL(lana_proc_dir);

static int __init init_lana_core_module(void)
{
	int ret;

	ret = init_vlink_system();
	if (ret)
		return -ENOMEM;
	lana_proc_dir = proc_mkdir("lana", init_net.proc_net);
	if (!lana_proc_dir)
		goto err;
	ret = init_worker_engines();
	if (ret)
		goto err2;
	ret = init_tables();
	if (ret)
		goto err3;

	printk(KERN_INFO "[lana] core loaded!\n");
	return 0;

err3:
	cleanup_worker_engines();
err2:
	remove_proc_entry("lana", init_net.proc_net);
err:
	cleanup_vlink_system();
	return -ENOMEM;
}

static void __exit cleanup_lana_core_module(void)
{
	cleanup_worker_engines();
	remove_proc_entry("lana", init_net.proc_net);
	cleanup_tables();
	cleanup_vlink_system();

	printk(KERN_INFO "[lana] core removed!\n");
}

module_init(init_lana_core_module);
module_exit(cleanup_lana_core_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA core driver");

