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

#include "xt_sched.h"
#include "xt_engine.h"

static volatile unsigned long cpu = 0;
static unsigned long __read_mostly cpu_max;

static int ppe_rr_init(void)
{
	cpu_max = num_online_cpus();
	return 0;
}

static int ppe_rr_sched(struct sk_buff *skb, enum path_type dir)
{
#ifdef __MIGRATE
	unsigned long ncpu = cpu++ & (cpu_max - 1);
	while (ncpu == USERSPACECPU)
		ncpu = cpu++ & (cpu_max - 1);
	enqueue_on_engine(skb, ncpu, dir);
#else
	enqueue_on_engine(skb, cpu++ & (cpu_max - 1), dir);
#endif /* __MIGRATE */
	return PPE_SUCCESS;
}

static struct ppesched_discipline_ops ppe_rr_ops __read_mostly = {
	.discipline_init = ppe_rr_init,
	.discipline_sched = ppe_rr_sched,
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

