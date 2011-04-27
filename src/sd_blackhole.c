/*
 * Lightweight Autonomic Network Architecture
 *
 * Blackhole scheduler.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 *
 * Note: Quantum tunneling is not supported, too.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cache.h>

#include "xt_sched.h"
#include "xt_engine.h"

static int ppe_blackhole_init(void)
{
	return 0;
}

static int ppe_blackhole_sched(struct sk_buff *skb, enum path_type dir)
{
	/* ... entering the event horizon! */
	kfree(skb);
	return PPE_SUCCESS;
}

static void ppe_blackhole_cleanup(void)
{
}

static struct ppesched_discipline_ops ppe_blackhole_ops __read_mostly = {
	.discipline_init = ppe_blackhole_init,
	.discipline_sched = ppe_blackhole_sched,
	.discipline_cleanup = ppe_blackhole_cleanup,
};

static struct ppesched_discipline ppe_blackhole __read_mostly = {
	.name = "blackhole",
	.ops = &ppe_blackhole_ops,
	.owner = THIS_MODULE,
};

static int __init init_ppe_blackhole_module(void)
{
	return ppesched_discipline_register(&ppe_blackhole);
}

static void __exit cleanup_ppe_blackhole_module(void)
{
	return ppesched_discipline_unregister(&ppe_blackhole);
}

module_init(init_ppe_blackhole_module);
module_exit(cleanup_ppe_blackhole_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA black hole scheduler");

