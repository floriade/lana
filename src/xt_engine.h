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

#define ENGINE_RUNNING   (1 << 0)
#define ENGINE_STOPPED   (1 << 1)

struct worker_estats {
	u64 packets;
	u32 errors;
	u32 dropped;
};

struct worker_engine {
	spinlock_t lock;                /* Engine lock                */
	unsigned int cpu;               /* CPU the engine is bound to */
	uint32_t flags;                 /* Engine status flags        */
	struct sk_buff_head *ingressq;  /* Incoming from PHY          */
	struct sk_buff_head *egressq;   /* Incoming from Socket       */
	wait_queue_head_t wq;           /* Thread waitqueue           */
	struct worker_estats stats;     /* Worker statistics          */
	struct task_struct *thread;     /* Task struct of thread      */
} ____cacheline_aligned_in_smp;

/* TODO: (later) add initial IDP */
extern int enqueue_egress_on_engine(struct sk_buff *skb, unsigned int cpu);
extern int enqueue_ingress_on_engine(struct sk_buff *skb, unsigned int cpu);
extern int init_worker_engines(void);
extern void cleanup_worker_engines(void);

#endif /* XT_ENGINE_H */

