/*
 * Lightweight Autonomic Network Architecture
 *
 * LANA packet processing engines. Incoming packtes are scheduled onto one
 * of the CPU-affine engines and processed on the Functional Block stack.
 * There are two queues where packets can be added, one from PHY direction
 * for incoming packets (ingress) and one from the socket handler direction
 * for outgoing packets (egress). Support for NUMA-affinity added.
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
#include <linux/sched.h>

#include "xt_engine.h"
#include "xt_skb.h"

struct worker_engine __percpu *engines;
extern struct proc_dir_entry *lana_proc_dir;

void cleanup_worker_engines(void);

static inline struct ppe_queue *__first_ppe_queue(struct worker_engine *ppe)
{
	return ppe->inqs.head;
}

static inline struct ppe_queue
*__next_filled_ppe_queue(struct ppe_queue *ppeq)
{
	do ppeq = ppeq->next;
	while (skb_queue_empty(&ppeq->queue));
	return ppeq;
}

static inline int __ppe_queues_have_load(struct worker_engine *ppe)
{
	return atomic64_read(&ppe->load) != 0;
}

static int process_packet(struct sk_buff *skb, enum path_type dir)
{
	idp_t cont;
	while ((cont = read_next_idp_from_skb(skb))) {
		/* Call FB receive function */
		/* ret = send_to_idp(cont, dir, skb); */
	}
	return 0;
}

static int engine_thread(void *arg)
{
	int ret;
	struct sk_buff *skb;
	struct ppe_queue *ppeq;
	struct worker_engine *ppe = per_cpu_ptr(engines,
						smp_processor_id());

	if (ppe->cpu != smp_processor_id())
		panic("[lana] Engine scheduled on wrong CPU!\n");
	printk(KERN_INFO "[lana] Packet Processing Engine running "
	       "on CPU%u!\n", smp_processor_id());

	ppeq = __first_ppe_queue(ppe);
	while (1) {
		wait_event_interruptible(ppe->wait_queue,
					 (kthread_should_stop() ||
					  __ppe_queues_have_load(ppe)));
		if (unlikely(kthread_should_stop()))
			break;

		ppeq = __next_filled_ppe_queue(ppeq);
		write_lock(&ppeq->stats.lock);
		ppeq->stats.packets++;
		write_unlock(&ppeq->stats.lock);
		skb = skb_dequeue(&ppeq->queue);
		ret = process_packet(skb, ppeq->type);
		switch (ret) {
		case PPE_DROPPED:
			write_lock(&ppeq->stats.lock);
			ppeq->stats.dropped++;
			write_unlock(&ppeq->stats.lock);
			break;
		case PPE_ERROR:
			write_lock(&ppeq->stats.lock);
			ppeq->stats.errors++;
			write_unlock(&ppeq->stats.lock);
			break;
		default:
			break;
		}
		kfree_skb(skb);
	}

	printk(KERN_INFO "[lana] Packet Processing Engine stopped "
	       "on CPU%u!\n", smp_processor_id());
	return 0;
}

static int engine_procfs_stats(char *page, char **start, off_t offset, 
			       int count, int *eof, void *data)
{
	int i;
	off_t len = 0;
	struct worker_engine *ppe = data;

	len += sprintf(page + len, "engine: %p\n", ppe);
	len += sprintf(page + len, "cpu: %u, numa node: %d\n",
		       ppe->cpu, cpu_to_node(ppe->cpu));
	len += sprintf(page + len, "load: %lu\n",
		       atomic64_read(&ppe->load));
	for (i = 0; i < NUM_TYPES; ++i) {
		read_lock(&ppe->inqs.ptrs[i]->stats.lock);
		len += sprintf(page + len, "queue: %p\n",
			       ppe->inqs.ptrs[i]);
		len += sprintf(page + len, "  type: %u\n",
			       ppe->inqs.ptrs[i]->type);
		len += sprintf(page + len, "  packets: %llu\n",
			       ppe->inqs.ptrs[i]->stats.packets);
		len += sprintf(page + len, "  errors: %u\n",
			       ppe->inqs.ptrs[i]->stats.errors);
		len += sprintf(page + len, "  drops: %llu\n",
			       ppe->inqs.ptrs[i]->stats.dropped);
		read_unlock(&ppe->inqs.ptrs[i]->stats.lock);
	}
	/* FIXME: fits in page? */
	*eof = 1;
	return len;
}

static inline void add_to_ppe_squeue(struct ppe_squeue *qs,
				     struct ppe_queue *q)
{
	q->next = qs->head;
	qs->head = q;
	qs->ptrs[q->type] = q;
}

static void finish_ppe_squeue(struct ppe_squeue *qs)
{
	struct ppe_queue *q = qs->head;
	while (q->next)
		q = q->next;
	q->next = qs->head;
}

static int init_ppe_squeue(struct ppe_squeue *queues, unsigned int cpu)
{
	int i;
	struct ppe_queue *tmp;

	for (i = 0; i < NUM_TYPES; ++i) {
		tmp = kzalloc_node(sizeof(*tmp), GFP_KERNEL,
				   cpu_to_node(cpu));
		if (!tmp)
			return -ENOMEM;
		tmp->type = (enum path_type) i;
		tmp->stats.lock = __RW_LOCK_UNLOCKED(lock);
		tmp->next = NULL;
		skb_queue_head_init(&tmp->queue);
		add_to_ppe_squeue(queues, tmp);
	}

	finish_ppe_squeue(queues);
	return 0;
}

static void cleanup_ppe_squeue(struct ppe_squeue *queues)
{
	int i;

	for (i = 0; i < NUM_TYPES; ++i) {
		if (queues->ptrs[i])
			kfree(queues->ptrs[i]);
		queues->ptrs[i] = NULL;
	}
	queues->head = NULL;
}

int init_worker_engines(void)
{
	int ret = 0;
	unsigned int cpu;
	char name[64];
	struct sched_param param = { .sched_priority = MAX_RT_PRIO-1 };

	engines = alloc_percpu(struct worker_engine);
	if (!engines)
		return -ENOMEM;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct worker_engine *ppe;
		ppe = per_cpu_ptr(engines, cpu);
		ppe->cpu = cpu;
		ppe->inqs.head = NULL;
		memset(&ppe->inqs, 0, sizeof(ppe->inqs));
		ret = init_ppe_squeue(&ppe->inqs, ppe->cpu);
		if (ret < 0)
			break;
		atomic64_set(&ppe->load, 0);
		memset(name, 0, sizeof(name));
		snprintf(name, sizeof(name), "ppe%u", cpu);
		ppe->proc = create_proc_read_entry(name, 0444, lana_proc_dir,
						   engine_procfs_stats, ppe);
		if (!ppe->proc) {
			ret = -ENOMEM;
			break;
		}

		init_waitqueue_head(&ppe->wait_queue);
		ppe->thread = kthread_create_on_node(engine_thread, NULL,
						     cpu_to_node(cpu), name);
		if (IS_ERR(ppe->thread)) {
			printk(KERN_ERR "[lana] Error creationg thread on "
			       "node %u!\n", cpu);
			ret = -EIO;
			break;
		}

		kthread_bind(ppe->thread, cpu);
		sched_setscheduler(ppe->thread, SCHED_FIFO, &param);
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
		cleanup_ppe_squeue(&ppe->inqs);
	}
	put_online_cpus();
	free_percpu(engines);
}
EXPORT_SYMBOL_GPL(cleanup_worker_engines);

