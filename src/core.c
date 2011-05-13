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
#include "xt_builder.h"
#include "xt_sched.h"
#include "xt_user.h"
#include "xt_migrate.h"

struct proc_dir_entry *lana_proc_dir;
EXPORT_SYMBOL(lana_proc_dir);
struct proc_dir_entry *fblock_proc_dir;
EXPORT_SYMBOL(fblock_proc_dir);
struct proc_dir_entry *sched_proc_dir;
EXPORT_SYMBOL(sched_proc_dir);

static int __init init_lana_core_module(void)
{
	int ret;

	printk(KERN_INFO "[lana] bootstrapping core ...\n");
	try_migrate_procs_to(0);
	lana_proc_dir = proc_mkdir("lana", init_net.proc_net);
	if (!lana_proc_dir)
		return -ENOMEM;
	fblock_proc_dir = proc_mkdir("fblock", lana_proc_dir);
	if (!fblock_proc_dir)
		goto err;
	sched_proc_dir = proc_mkdir("sched", lana_proc_dir);
	if (!sched_proc_dir)
		goto err0;
	ret = init_vlink_system();
	if (ret)
		goto err1;
	ret = init_worker_engines();
	if (ret)
		goto err2;
	ret = init_fblock_tables();
	if (ret)
		goto err3;
	ret = init_fblock_builder();
	if (ret)
		goto err4;
	ret = init_ppesched_system();
	if (ret)
		goto err5;
	ret = init_userctl_system();
	if (ret)
		goto err6;
	printk(KERN_INFO "[lana] core up and running!\n");
	return 0;
err6:
	cleanup_ppesched_system();
err5:
	cleanup_fblock_builder();
err4:
	cleanup_fblock_tables();
err3:
	cleanup_worker_engines();
err2:
	cleanup_vlink_system();
err1:
	remove_proc_entry("sched", lana_proc_dir);
err0:
	remove_proc_entry("fblock", lana_proc_dir);
err:
	remove_proc_entry("lana", init_net.proc_net);
	return -ENOMEM;
}

static void __exit cleanup_lana_core_module(void)
{
	printk(KERN_INFO "[lana] halting core ...\n");
	cleanup_userctl_system();
	cleanup_worker_engines();
	cleanup_fblock_tables();
	cleanup_ppesched_system();
	cleanup_fblock_builder();
	cleanup_vlink_system();
	remove_proc_entry("fblock", lana_proc_dir);
	remove_proc_entry("sched", lana_proc_dir);
	remove_proc_entry("lana", init_net.proc_net);
	printk(KERN_INFO "[lana] core shut down!\n");
}

module_init(init_lana_core_module);
module_exit(cleanup_lana_core_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA core driver");

