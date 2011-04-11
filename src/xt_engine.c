/*
 * Lightweight Autonomic Network Architecture
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/workqueue.h>
#include <linux/cpu.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/wait.h>

#define ENGINE_RUNNING   (1 << 0)
#define ENGINE_STOPPED   (1 << 1)

struct worker_qstats {
        u64 packets;
        u32 errors;
        u32 dropped;
};

struct worker_engine {
	spinlock_t lock;                /* Engine lock                */
	unsigned int cpu;               /* CPU the engine is bound to */
	uint32_t flags;                 /* Engine status flags        */
	struct sk_buff_head *ingressq;  /* Incoming from PHY          */
	struct worker_qstats stats_iq;  /* Stats for ingress queue    */
	struct sk_buff_head *egressq;   /* Incoming from Socket       */
	struct worker_qstats stats_eq;  /* Stats for egress queue     */
	wait_queue_head_t wq;           /* Thread waitqueue           */
} ____cacheline_aligned_in_smp;

static struct worker_engine __percpu *engines;

/* todo: kthread for each online_cpu */
/* v-- to be fixed */

int enqueue_egress_on_engine(struct skb_buff *skb, unsigned int cpu)
{
	return 0;
}

int enqueue_ingress_on_engine(struct skb_buff *skb, unsigned int cpu)
{
	return 0;
}

int init_worker_engines(void)
{
	int ret = 0;
	unsigned int cpu;
	char name[32];

	workers = alloc_percpu(struct worker_engine);
	if (!workers)
		return -ENOMEM;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct worker_engine *engine;

		memset(name, 0, sizeof(name));
		snprintf(name, sizeof(name), "ppe%u", cpu);

		engine = per_cpu_ptr(workers, cpu);
		engine->cpu = cpu;
		engine->queue = create_workqueue(name);
		if (!engine->queue) {
			ret = -ENOMEM; /* TODO: Cleanup mem */
			break;
		}
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
		struct worker_engine *engine;

		engine = per_cpu_ptr(workers, cpu);
		destroy_workqueue(engine->queue);
	}
	put_online_cpus();
	free_percpu(workers);
}
EXPORT_SYMBOL_GPL(cleanup_worker_engines);

