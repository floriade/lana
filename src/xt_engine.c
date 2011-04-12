/*
 * Lightweight Autonomic Network Architecture
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/cpu.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/wait.h>

#include "xt_engine.h"

static struct worker_engine __percpu *engines;

int enqueue_egress_on_engine(struct skb_buff *skb, unsigned int cpu)
{
	return 0;
}

int enqueue_ingress_on_engine(struct skb_buff *skb, unsigned int cpu)
{
	return 0;
}

static int engine_thread(void *arg)
{
	printk(KERN_INFO "[lana] ");

	while (!kthread_should_stop())
		;

	return 0;
}

int init_worker_engines(void)
{
	int ret = 0;
	unsigned int cpu;
	char name[32];

	engines = alloc_percpu(struct worker_engine);
	if (!engines)
		return -ENOMEM;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct worker_engine *engine;

		memset(name, 0, sizeof(name));
		snprintf(name, sizeof(name), "ppe%u", cpu);

		engine = per_cpu_ptr(workers, cpu);
		engine->cpu = cpu;
		kthread_create_on_node
	}
	put_online_cpus();

	printk(KERN_INFO "[lana] Packet Processing Engines running!\n");
	return ret;
}
EXPORT_SYMBOL_GPL(init_worker_engines);

void cleanup_worker_engines(void)
{
	unsigned int cpu;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct worker_engine *engine;

		engine = per_cpu_ptr(workers, cpu);
		destroy_workqueue(engine->queue);
	}
	put_online_cpus();
	free_percpu(workers);

	printk(KERN_INFO "[lana] Packet Processing Engines removed!\n");
}
EXPORT_SYMBOL_GPL(cleanup_worker_engines);

