/*
 * Lightweight Autonomic Network Architecture
 *
 * Round robin scheduler.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cache.h>
#include <linux/cpumask.h>
#include <linux/atomic.h>

#include "xt_sched.h"
#include "xt_engine.h"

static atomic_t cpu;

static int ppe_rr_init(void)
{
	atomic_set(&cpu, -1);
	atomic_set(&cpu, cpumask_next(atomic_read(&cpu), cpu_online_mask));
	return 0;
}

static int ppe_rr_sched(struct sk_buff *skb, enum path_type dir)
{
	int __cpu;
	atomic_set(&cpu, cpumask_next((__cpu = atomic_read(&cpu)),
		   cpu_online_mask));
	switch (dir) {
	case TYPE_EGRESS:
		enqueue_egress_on_engine(skb, __cpu);
		break;
	case TYPE_INGRESS:
		enqueue_ingress_on_engine(skb, __cpu);
		break;
	default:
		return PPE_ERROR;
	}
	return PPE_SUCCESS;
}

static void ppe_rr_cleanup(void)
{
}

static struct ppesched_discipline_ops ppe_rr_ops __read_mostly = {
	.discipline_init = ppe_rr_init,
	.discipline_sched = ppe_rr_sched,
	.discipline_cleanup = ppe_rr_cleanup,
};

static struct ppesched_discipline ppe_rr __read_mostly = {
	.name = "roundrobin",
	.ops = &ppe_rr_ops,
	.owner = THIS_MODULE,
};

static int __init init_ppe_rr_module(void)
{
	return ppesched_discipline_register(&ppe_rr);
}

static void __exit cleanup_ppe_rr_module(void)
{
	return ppesched_discipline_unregister(&ppe_rr);
}

module_init(init_ppe_rr_module);
module_exit(cleanup_ppe_rr_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA round robin scheduler");

