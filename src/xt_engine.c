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
#include <linux/kthread.h>
#include <linux/proc_fs.h>
#include <linux/u64_stats_sync.h>
#include <linux/prefetch.h>
#include <linux/sched.h>
#include <linux/hrtimer.h>
#include <linux/jiffies.h>
#include <linux/kernel_stat.h>

#include "xt_engine.h"
#include "xt_skb.h"
#include "xt_fblock.h"

struct worker_engine __percpu *engines;
EXPORT_SYMBOL_GPL(engines);
extern struct proc_dir_entry *lana_proc_dir;

void cleanup_worker_engines(void);

static inline int ppe_queues_have_load(struct worker_engine *ppe)
{
	/* add new stuff here */
	if (!skb_queue_empty(&ppe->inqs[TYPE_INGRESS].queue))
		return TYPE_INGRESS;
	if (!skb_queue_empty(&ppe->inqs[TYPE_EGRESS].queue))
		return TYPE_EGRESS;
	return -EAGAIN;
}

static inline int process_packet(struct sk_buff *skb, enum path_type dir)
{
	int ret = PPE_ERROR;
	idp_t cont;
	struct fblock *fb;
	prefetch(skb->cb);
	while ((cont = read_next_idp_from_skb(skb))) {
		fb = __search_fblock(cont);
		if (unlikely(!fb))
			return PPE_ERROR;
		/* Called in rcu_read_lock context */
		ret = fb->netfb_rx(fb, skb, &dir);
		put_fblock(fb);
		if (ret == PPE_DROPPED)
			/* fblock freed skb */
			return PPE_DROPPED;
		prefetch(skb->cb);
	}
	return ret;
}

static int engine_thread(void *arg)
{
	int ret, queue, need_lock = 0;
	struct sk_buff *skb;
	unsigned long cpu = smp_processor_id();
	struct worker_engine *ppe = per_cpu_ptr(engines, cpu);
	if (ppe->cpu != cpu)
		panic("[lana] Engine scheduled on wrong CPU!\n");
	printk(KERN_INFO "[lana] Packet Processing Engine running "
	       "on CPU%lu!\n", cpu);
	if (!rcu_read_lock_held())
		need_lock = 1;
	set_current_state(TASK_INTERRUPTIBLE);
	while (likely(!kthread_should_stop())) {
		preempt_disable();
		if ((queue = ppe_queues_have_load(ppe)) < 0) {
			preempt_enable_no_resched();
			schedule();
			preempt_disable();
		}
		__set_current_state(TASK_RUNNING);
		while ((skb = skb_dequeue(&ppe->inqs[queue].queue)) != NULL) {
			if (unlikely(skb_is_time_marked_first(skb)))
				ppe->timef = ktime_get();
			if (need_lock)
				rcu_read_lock();
			ret = process_packet(skb, ppe->inqs[queue].type);
			if (need_lock)
				rcu_read_unlock();
			if (unlikely(skb_is_time_marked_last(skb)))
				ppe->timel = ktime_get();
			ppe->pkts++;
			u64_stats_update_begin(&ppe->inqs[queue].stats.syncp);
			ppe->inqs[queue].stats.packets++;
			ppe->inqs[queue].stats.bytes += skb->len;
			if (ret == PPE_DROPPED)
				ppe->inqs[queue].stats.dropped++;
			else if (unlikely(ret == PPE_ERROR)) {
				ppe->inqs[queue].stats.errors++;
				kfree_skb(skb);
			}
			u64_stats_update_end(&ppe->inqs[queue].stats.syncp);
			preempt_enable_no_resched();
			cond_resched();
			preempt_disable();
		}
		preempt_enable();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);
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
			sstart = u64_stats_fetch_begin(&ppe->inqs[i].stats.syncp);
			len += sprintf(page + len, "queue: %p\n", &ppe->inqs[i]);
			len += sprintf(page + len, "  type: %u\n",
				       ppe->inqs[i].type);
			len += sprintf(page + len, "  packets: %llu\n",
				       ppe->inqs[i].stats.packets);
			len += sprintf(page + len, "  bytes: %llu\n",
				       ppe->inqs[i].stats.bytes);
			len += sprintf(page + len, "  errors: %u\n",
				       ppe->inqs[i].stats.errors);
			len += sprintf(page + len, "  drops: %llu\n",
				       ppe->inqs[i].stats.dropped);
		} while (u64_stats_fetch_retry(&ppe->inqs[i].stats.syncp, sstart));
	}
	/* FIXME: fits in page? */
	*eof = 1;
	return len;
}

#define WAKE_TIME_MAX	(1 << 27)
#define WAKE_TIME_MIN	(1 << 11)

static enum hrtimer_restart engine_timer_handler(struct hrtimer *self)
{
	unsigned long n = 0;
	struct tasklet_hrtimer *thr = container_of(self, struct tasklet_hrtimer, timer);
	struct worker_engine *ppe = container_of(thr, struct worker_engine, htimer);

	n = (WAKE_TIME_MIN | ppe->pkts) & 0xffffffff;
	n = ((n >>  1) & 0x55555555) | ((n <<  1) & 0xaaaaaaaa);
	n = ((n >>  2) & 0x33333333) | ((n <<  2) & 0xcccccccc);
	n = ((n >>  4) & 0x0f0f0f0f) | ((n <<  4) & 0xf0f0f0f0);
	n = ((n >>  8) & 0x00ff00ff) | ((n <<  8) & 0xff00ff00);
	n = ((n >> 16) & 0x0000ffff) | ((n << 16) & 0xffff0000);
	n = n & (WAKE_TIME_MAX - 1);

	tasklet_hrtimer_start(&ppe->htimer, ktime_set(0, n), HRTIMER_MODE_REL);
	if (ppe->thread->state != TASK_RUNNING)
		wake_up_process(ppe->thread);
	ppe->pkts = 0;
	return HRTIMER_NORESTART;
}

int init_worker_engines(void)
{
	int i, ret = 0;
	unsigned int cpu;
	char name[64];

	engines = alloc_percpu(struct worker_engine);
	if (!engines)
		return -ENOMEM;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct worker_engine *ppe;
#ifdef __MIGRATE
		if (cpu == USERSPACECPU)
			continue;
#endif /* __MIGRATE */
		ppe = per_cpu_ptr(engines, cpu);
		ppe->cpu = cpu;
		memset(&ppe->inqs, 0, sizeof(ppe->inqs));
		for (i = 0; i < NUM_QUEUES; ++i)
			skb_queue_head_init(&ppe->inqs[i].queue);
		memset(name, 0, sizeof(name));
		snprintf(name, sizeof(name), "ppe%u", cpu);
		ppe->proc = create_proc_read_entry(name, 0400, lana_proc_dir,
						   engine_procfs_stats, ppe);
		if (!ppe->proc) {
			ret = -ENOMEM;
			break;
		}
		ppe->pkts = 0;
		ppe->thread = kthread_create_on_node(engine_thread, NULL,
						     cpu_to_node(cpu), name);
		if (IS_ERR(ppe->thread)) {
			printk(KERN_ERR "[lana] Error creationg thread on "
			       "node %u!\n", cpu);
			ret = -EIO;
			break;
		}
		kthread_bind(ppe->thread, cpu);
		tasklet_hrtimer_init(&ppe->htimer, engine_timer_handler,
				     CLOCK_REALTIME, HRTIMER_MODE_ABS);
		tasklet_hrtimer_start(&ppe->htimer, ktime_set(1, 0),
				      HRTIMER_MODE_REL);
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
#ifdef __MIGRATE
		if (cpu == USERSPACECPU)
			continue;
#endif /* __MIGRATE */
		memset(name, 0, sizeof(name));
		snprintf(name, sizeof(name), "ppe%u", cpu);
		ppe = per_cpu_ptr(engines, cpu);
		if (!IS_ERR(ppe->thread)) {
			tasklet_hrtimer_cancel(&ppe->htimer);
			kthread_stop(ppe->thread);
		}
		if (ppe->proc)
			remove_proc_entry(name, lana_proc_dir);
	}
	put_online_cpus();
	free_percpu(engines);
}
EXPORT_SYMBOL_GPL(cleanup_worker_engines);

