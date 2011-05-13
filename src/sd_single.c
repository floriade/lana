/*
 * Lightweight Autonomic Network Architecture
 *
 * Single CPU scheduler.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cache.h>
#include <linux/cpumask.h>
#include <linux/spinlock.h>

#include "xt_sched.h"
#include "xt_engine.h"

/* TODO: change via procfs */
#define RUN_ON_CPU 0

static volatile unsigned long cpu = RUN_ON_CPU;

static int ppe_single_sched(struct sk_buff *skb, enum path_type dir)
{
	enqueue_on_engine(skb, cpu, dir);
	return PPE_SUCCESS;
}

static struct ppesched_discipline_ops ppe_single_ops __read_mostly = {
	.discipline_sched = ppe_single_sched,
};

static struct ppesched_discipline ppe_single __read_mostly = {
	.name = "singlecpu",
	.ops = &ppe_single_ops,
	.owner = THIS_MODULE,
};

static int __init init_ppe_single_module(void)
{
	return ppesched_discipline_register(&ppe_single);
}

static void __exit cleanup_ppe_single_module(void)
{
	return ppesched_discipline_unregister(&ppe_single);
}

module_init(init_ppe_single_module);
module_exit(cleanup_ppe_single_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA single CPU scheduler");

