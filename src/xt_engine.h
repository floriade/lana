/*
 * Lightweight Autonomic Network Architecture
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#ifndef XT_ENGINE_H
#define XT_ENGINE_H

#include <linux/skbuff.h>
#include <linux/wait.h>
#include <linux/cpu.h>
#include <linux/sched.h>
#include <linux/u64_stats_sync.h>
#include <linux/atomic.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>

#include "xt_conf.h"
#include "xt_fblock.h"

#define NUM_QUEUES              NUM_TYPES

#define PPE_SUCCESS             0
#define PPE_DROPPED             1
#define PPE_ERROR               2

struct worker_estats {
	u64 packets;
	u64 bytes;
	u64 dropped;
	struct u64_stats_sync syncp;
	u32 errors;
};

struct ppe_queue {
	enum path_type type;
	struct sk_buff_head queue;
	struct worker_estats stats;
};

struct worker_engine {
	struct ppe_queue inqs[NUM_QUEUES];
	ktime_t timef, timel;
	struct proc_dir_entry *proc;
	struct task_struct *thread;
	struct tasklet_hrtimer htimer;
	unsigned int cpu;
	unsigned int pkts;
	volatile int ppe_timer_set;
} ____cacheline_aligned;

extern int init_worker_engines(void);
extern void cleanup_worker_engines(void);
extern struct worker_engine __percpu *engines;

#define WAKE_TIME_MAX (1 << 30)
#define WAKE_TIME_MIN (1 << 15)

static inline void wake_engine_cond(unsigned int cpu)
{
	unsigned long n = 0;
	struct worker_engine *ppe = per_cpu_ptr(engines, cpu);
#ifdef __MIGRATE
	if (cpu == USERSPACECPU)
		return;
#endif /* __MIGRATE */
	if (ppe->ppe_timer_set)
		return;
	ppe->ppe_timer_set = 1;
	n = (WAKE_TIME_MIN | ppe->pkts) & 0xffffffff;
	n = ((n >>  1) & 0x55555555) | ((n <<  1) & 0xaaaaaaaa);
	n = ((n >>  2) & 0x33333333) | ((n <<  2) & 0xcccccccc);
	n = ((n >>  4) & 0x0f0f0f0f) | ((n <<  4) & 0xf0f0f0f0);
	n = ((n >>  8) & 0x00ff00ff) | ((n <<  8) & 0xff00ff00);
	n = ((n >> 16) & 0x0000ffff) | ((n << 16) & 0xffff0000);
	n = n & (WAKE_TIME_MAX - 1);
	tasklet_hrtimer_start(&ppe->htimer, ktime_set(0, n),
			      HRTIMER_MODE_REL);
}

static inline void enqueue_egress_on_engine(struct sk_buff *skb,
					    unsigned int cpu)
{
	struct worker_engine *ppe = per_cpu_ptr(engines, cpu);
#ifdef __MIGRATE
	if (cpu == USERSPACECPU)
		return;
#endif /* __MIGRATE */
	skb_queue_tail(&ppe->inqs[TYPE_EGRESS].queue, skb);
	wake_engine_cond(cpu);
}

static inline void enqueue_ingress_on_engine(struct sk_buff *skb,
					     unsigned int cpu)
{
	struct worker_engine *ppe = per_cpu_ptr(engines, cpu);
#ifdef __MIGRATE
	if (cpu == USERSPACECPU)
		return;
#endif /* __MIGRATE */
	skb_queue_tail(&ppe->inqs[TYPE_INGRESS].queue, skb);
	wake_engine_cond(cpu);
}

static inline void enqueue_on_engine(struct sk_buff *skb,
				     unsigned int cpu,
				     enum path_type type)
{
	struct worker_engine *ppe = per_cpu_ptr(engines, cpu);
#ifdef __MIGRATE
	if (cpu == USERSPACECPU)
		return;
#endif /* __MIGRATE */
	skb_queue_tail(&ppe->inqs[type].queue, skb);
	wake_engine_cond(cpu);
}

#endif /* XT_ENGINE_H */

