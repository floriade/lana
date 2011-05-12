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
#include <linux/u64_stats_sync.h>
#include <linux/prefetch.h>
#include <linux/sched.h>
#include <linux/hrtimer.h>

#include "xt_engine.h"
#include "xt_skb.h"
#include "xt_fblock.h"

struct worker_engine __percpu *engines;
EXPORT_SYMBOL_GPL(engines);
extern struct proc_dir_entry *lana_proc_dir;

void cleanup_worker_engines(void);

static inline struct ppe_queue *first_ppe_queue(struct worker_engine *ppe)
{
	return ppe->inqs.head;
}

static inline struct ppe_queue *next_filled_ppe_queue(struct ppe_queue *ppeq)
{
	ppeq = ppeq->next;
testq:
	if (!skb_queue_empty(&ppeq->queue))
		return ppeq;
	if (!skb_queue_empty(&ppeq->next->queue))
		return ppeq->next;
	ppeq = ppeq->next->next;
	goto testq;
}

static inline int ppe_queues_have_load(struct worker_engine *ppe)
{
	/* add new stuff here */
	if (!skb_queue_empty(&ppe->inqs.ptrs[TYPE_INGRESS]->queue))
		return 1;
	if (!skb_queue_empty(&ppe->inqs.ptrs[TYPE_EGRESS]->queue))
		return 1;
	return 0;
}

static inline int process_packet(struct sk_buff *skb, enum path_type dir)
{
	int ret = PPE_DROPPED;
	idp_t cont;
	struct fblock *fb;
	prefetch(skb->cb);
	while ((cont = read_next_idp_from_skb(skb))) {
		fb = __search_fblock(cont);
		if (unlikely(!fb))
			return PPE_ERROR;
		/* Called in rcu_read_lock context */
		ret = fb->ops->netfb_rx(fb, skb, &dir);
		put_fblock(fb);
		if (ret == PPE_DROPPED)
			return PPE_DROPPED;
		prefetch(skb->cb);
	}
	return ret;
}

static int engine_thread(void *arg)
{
	int ret, need_lock = 0;
	struct sk_buff *skb;
	struct ppe_queue *ppeq;
	struct worker_engine *ppe = per_cpu_ptr(engines,
						smp_processor_id());

	if (ppe->cpu != smp_processor_id())
		panic("[lana] Engine scheduled on wrong CPU!\n");
	printk(KERN_INFO "[lana] Packet Processing Engine running "
	       "on CPU%u!\n", smp_processor_id());

	if (!rcu_read_lock_held())
		need_lock = 1;
	ppeq = first_ppe_queue(ppe);
	while (likely(!kthread_should_stop())) {
		if (!ppe_queues_have_load(ppe)) {
			wait_event_interruptible_timeout(ppe->wait_queue,
						(kthread_should_stop() ||
						 ppe_queues_have_load(ppe)), 10);
			continue;
		}

		ppeq = next_filled_ppe_queue(ppeq);
		skb = skb_dequeue(&ppeq->queue);
		if (unlikely(skb_is_time_marked_first(skb)))
			ppe->timef = ktime_get();
		if (need_lock)
			rcu_read_lock();
		ret = process_packet(skb, ppeq->type);
		if (need_lock)
			rcu_read_unlock();
		if (unlikely(skb_is_time_marked_last(skb)))
			ppe->timel = ktime_get();

		u64_stats_update_begin(&ppeq->stats.syncp);
		ppeq->stats.packets++;
		ppeq->stats.bytes += skb->len;
		if (ret == PPE_DROPPED)
			ppeq->stats.dropped++;
		else if (unlikely(ret == PPE_ERROR))
			ppeq->stats.errors++;
		u64_stats_update_end(&ppeq->stats.syncp);
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
	unsigned int sstart;

	len += sprintf(page + len, "engine: %p\n", ppe);
	len += sprintf(page + len, "cpu: %u, numa node: %d\n",
		       ppe->cpu, cpu_to_node(ppe->cpu));
	len += sprintf(page + len, "hrt: %llu us\n",
		       ktime_us_delta(ppe->timel, ppe->timef));
	for (i = 0; i < NUM_TYPES; ++i) {
		do {
			sstart = u64_stats_fetch_begin(&ppe->inqs.ptrs[i]->stats.syncp);
			len += sprintf(page + len, "queue: %p\n",
				       ppe->inqs.ptrs[i]);
			len += sprintf(page + len, "  type: %u\n",
				       ppe->inqs.ptrs[i]->type);
			len += sprintf(page + len, "  packets: %llu\n",
				       ppe->inqs.ptrs[i]->stats.packets);
			len += sprintf(page + len, "  bytes: %llu\n",
				       ppe->inqs.ptrs[i]->stats.bytes);
			len += sprintf(page + len, "  errors: %u\n",
				       ppe->inqs.ptrs[i]->stats.errors);
			len += sprintf(page + len, "  drops: %llu\n",
				       ppe->inqs.ptrs[i]->stats.dropped);
		} while (u64_stats_fetch_retry(&ppe->inqs.ptrs[i]->stats.syncp, sstart));
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
		memset(name, 0, sizeof(name));
		snprintf(name, sizeof(name), "ppe%u", cpu);
		ppe->proc = create_proc_read_entry(name, 0400, lana_proc_dir,
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

