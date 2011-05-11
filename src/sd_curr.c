/*
 * Lightweight Autonomic Network Architecture
 *
 * Current CPU scheduler.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cache.h>
#include <linux/cpumask.h>

#include "xt_sched.h"
#include "xt_engine.h"

static int ppe_curr_init(void)
{
	return 0;
}

static int ppe_curr_sched(struct sk_buff *skb, enum path_type dir)
{
	enqueue_on_engine(skb, smp_processor_id(), dir);
	return PPE_SUCCESS;
}

static void ppe_curr_cleanup(void)
{
}

static struct ppesched_discipline_ops ppe_curr_ops __read_mostly = {
	.discipline_init = ppe_curr_init,
	.discipline_sched = ppe_curr_sched,
	.discipline_cleanup = ppe_curr_cleanup,
};

static struct ppesched_discipline ppe_curr __read_mostly = {
	.name = "currcpu",
	.ops = &ppe_curr_ops,
	.owner = THIS_MODULE,
};

static int __init init_ppe_curr_module(void)
{
	return ppesched_discipline_register(&ppe_curr);
}

static void __exit cleanup_ppe_curr_module(void)
{
	return ppesched_discipline_unregister(&ppe_curr);
}

module_init(init_ppe_curr_module);
module_exit(cleanup_ppe_curr_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA current CPU scheduler");

