/*
 * Lightweight Autonomic Network Architecture
 *
 * LANA packet processing engines. Incoming packtes are scheduled onto one
 * of the CPU-affine engines and processed on the Functional Block stack.
 * There are two queues where packets can be added, one from PHY direction
 * for incoming packets (ingress) and one from the socket handler direction
 * for outgoing packets (egress).
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
#include <linux/proc_fs.h>

#include "xt_engine.h"

struct worker_engine __percpu *engines;
extern struct proc_dir_entry *lana_proc_dir;

void cleanup_worker_engines(void);

static int engine_thread(void *arg)
{
	struct worker_engine *ppe = per_cpu_ptr(engines,
						smp_processor_id());
	if (ppe->cpu != smp_processor_id())
		panic("[lana] Engine scheduled on wrong CPU!\n");

	printk(KERN_INFO "[lana] Packet Processing Engine running "
	       "on CPU%u!\n", smp_processor_id());

	while (1) {
		wait_event_interruptible(ppe->wq, (kthread_should_stop() ||
					 !skb_queue_empty(&ppe->ingressq) ||
					 !skb_queue_empty(&ppe->egressq)));
		if (unlikely(kthread_should_stop()))
			break;

		write_lock(&ppe->stats.lock);
		ppe->stats.packets++;
		write_unlock(&ppe->stats.lock);
	}

	printk(KERN_INFO "[lana] Packet Processing Engine stopped "
	       "on CPU%u!\n", smp_processor_id());
	return 0;
}

static int engine_procfs_stats(char *page, char **start, off_t offset, 
			       int count, int *eof, void *data)
{
	off_t len = 0;
	struct worker_engine *ppe = data;

	read_lock(&ppe->stats.lock);
	len += sprintf(page + len, "packets: %llu\n", ppe->stats.packets);
	len += sprintf(page + len, "errors:  %u\n", ppe->stats.errors);
	len += sprintf(page + len, "drops:   %llu\n", ppe->stats.dropped);
	read_unlock(&ppe->stats.lock);
	*eof = 1;

	return len;
}

int init_worker_engines(void)
{
	int ret = 0;
	unsigned int cpu;
	char name[64];

	engines = alloc_percpu(struct worker_engine);
	if (!engines)
		return -ENOMEM;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct worker_engine *ppe;

		ppe = per_cpu_ptr(engines, cpu);
		memset(&ppe->stats, 0, sizeof(ppe->stats));
		ppe->stats.lock = __RW_LOCK_UNLOCKED(lock);
		ppe->cpu = cpu;

		skb_queue_head_init(&ppe->ingressq);
		skb_queue_head_init(&ppe->egressq);

		memset(name, 0, sizeof(name));
		snprintf(name, sizeof(name), "ppe%u", cpu);

		ppe->proc = create_proc_read_entry(name, 0444, lana_proc_dir,
						   engine_procfs_stats, ppe);
		if (!ppe->proc) {
			ret = -ENOMEM;
			break;
		}

		init_waitqueue_head(&ppe->wq);
		ppe->thread = kthread_create_on_node(engine_thread, NULL,
						     cpu, name);
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

	if (ret < 0)
		cleanup_worker_engines();
	return ret;
}
EXPORT_SYMBOL_GPL(init_worker_engines);

void cleanup_worker_engines(void)
{
	unsigned int cpu;
	char name[64];

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct worker_engine *ppe;

		memset(name, 0, sizeof(name));
		snprintf(name, sizeof(name), "ppe%u", cpu);

		ppe = per_cpu_ptr(engines, cpu);
		if (!IS_ERR(ppe->thread))
			kthread_stop(ppe->thread);
		if (ppe->proc)
			remove_proc_entry(name, lana_proc_dir);
	}
	put_online_cpus();
	free_percpu(engines);
}
EXPORT_SYMBOL_GPL(cleanup_worker_engines);

