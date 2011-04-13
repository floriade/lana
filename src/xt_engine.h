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
#include <linux/atomic.h>

enum path_type {
	TYPE_INGRESS = 0,
#define TYPE_INGRESS           TYPE_INGRESS
	TYPE_EGRESS,
#define TYPE_EGRESS            TYPE_EGRESS
	_TYPE_MAX,
};

#define NUM_TYPES               _TYPE_MAX
#define NUM_QUEUES              NUM_TYPES

#define PPE_SUCCESS             0
#define PPE_DROPPED             1
#define PPE_ERROR               2

struct worker_estats {
	u64 packets;
	u32 errors;
	u64 dropped;
	rwlock_t lock;
};

struct ppe_queue {
	enum path_type type;
	struct sk_buff_head queue;
	struct worker_estats stats;
	struct ppe_queue *next;
} ____cacheline_aligned_in_smp;

struct ppe_squeue {
	struct ppe_queue *head;
	struct ppe_queue *ptrs[NUM_QUEUES];
};

struct worker_engine {
	unsigned int cpu;
	struct proc_dir_entry *proc;
	struct task_struct *thread;
	struct ppe_squeue inqs;
	wait_queue_head_t wait_queue;
	atomic64_t load;
} ____cacheline_aligned_in_smp;

extern int init_worker_engines(void);
extern void cleanup_worker_engines(void);
extern struct worker_engine __percpu *engines;

static inline void enqueue_egress_on_engine(struct sk_buff *skb,
					    unsigned int cpu)
{
        struct worker_engine *ppe = per_cpu_ptr(engines, cpu);
        skb_queue_tail(&ppe->inqs.ptrs[TYPE_EGRESS]->queue, skb);
	atomic64_inc(&ppe->load);
}

static inline void enqueue_ingress_on_engine(struct sk_buff *skb,
					     unsigned int cpu)
{
        struct worker_engine *ppe = per_cpu_ptr(engines, cpu);
        skb_queue_tail(&ppe->inqs.ptrs[TYPE_INGRESS]->queue, skb);
	atomic64_inc(&ppe->load);
}

#endif /* XT_ENGINE_H */

