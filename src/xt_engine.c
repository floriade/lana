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
#include <linux/kthread.h>

#include "xt_engine.h"

static struct worker_engine __percpu *engines;

int enqueue_egress_on_engine(struct sk_buff *skb, unsigned int cpu)
{
	return 0;
}

int enqueue_ingress_on_engine(struct sk_buff *skb, unsigned int cpu)
{
	return 0;
}

static int engine_thread(void *arg)
{
	struct worker_engine *ppe = per_cpu_ptr(engines,
						smp_processor_id());

	printk(KERN_INFO "[lana] Packet Processing Engine running "
	       "on CPU%u!\n", smp_processor_id());

	while (1) {
		wait_event_interruptible(ppe->wq, kthread_should_stop());
		if (kthread_should_stop())
			break;
	}

	printk(KERN_INFO "[lana] Packet Processing Engine stopped "
	       "on CPU%u!\n", smp_processor_id());
	return 0;
}

int init_worker_engines(void)
{
	int ret = 0;
	unsigned int cpu;

	engines = alloc_percpu(struct worker_engine);
	if (!engines)
		return -ENOMEM;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct worker_engine *ppe;
		ppe = per_cpu_ptr(engines, cpu);
		ppe->cpu = cpu;
		ppe->lock = __SPIN_LOCK_UNLOCKED(lock);
		ppe->flags = 0;
		memset(&ppe->stats, 0, sizeof(ppe->stats));
		init_waitqueue_head(&ppe->wq);
#ifndef kthread_create_on_node
		ppe->thread = kthread_create(engine_thread, NULL,
					     "ppe%u", cpu);
#else /* Use NUMA affinity for kthread stack */
		ppe->thread = kthread_create_on_node(engine_thread, NULL,
						     cpu, "ppe%u", cpu);
#endif
		if (IS_ERR(ppe->thread)) {
			printk(KERN_ERR "[lana] Error creationg thread on "
			       "node %u!\n", cpu);
			ret = -EIO;
			break;
		}

		kthread_bind(ppe->thread, cpu);
		wake_up_process(ppe->thread);
	}
	put_online_cpus();

	return ret;
}
EXPORT_SYMBOL_GPL(init_worker_engines);

void cleanup_worker_engines(void)
{
	unsigned int cpu;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct worker_engine *ppe;
		ppe = per_cpu_ptr(engines, cpu);
		kthread_stop(ppe->thread);
	}
	put_online_cpus();
	free_percpu(engines);
}
EXPORT_SYMBOL_GPL(cleanup_worker_engines);

