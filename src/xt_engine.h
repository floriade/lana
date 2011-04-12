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

#define PROC_DIR_PREFIX "/proc/net/"

struct worker_estats {
	u64 packets;
	u32 errors;
	u64 dropped;
	rwlock_t lock;
};

struct worker_engine {
	struct sk_buff_head ingressq;   /* Incoming from PHY          */
	struct sk_buff_head egressq;    /* Incoming from Socket       */
	struct worker_estats stats;     /* Worker statistics          */
	struct proc_dir_entry *proc;    /* Proc directory entry       */
	struct task_struct *thread;     /* Task struct of thread      */
	wait_queue_head_t wq;           /* Thread waitqueue           */
} ____cacheline_aligned_in_smp;

extern int init_worker_engines(void);
extern void cleanup_worker_engines(void);

extern struct worker_engine __percpu *engines;

static inline void enqueue_egress_on_engine(struct sk_buff *skb,
					    unsigned int cpu)
{
        struct worker_engine *ppe = per_cpu_ptr(engines, cpu);
        skb_queue_tail(&ppe->egressq, skb);
}

static inline void enqueue_ingress_on_engine(struct sk_buff *skb,
					     unsigned int cpu)
{
        struct worker_engine *ppe = per_cpu_ptr(engines, cpu);
        skb_queue_tail(&ppe->ingressq, skb);
}

#endif /* XT_ENGINE_H */

