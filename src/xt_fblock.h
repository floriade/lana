/*
 * Lightweight Autonomic Network Architecture
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#ifndef XT_FBLOCK_H
#define XT_FBLOCK_H

#include <linux/if.h>
#include <linux/cpu.h>
#include <linux/skbuff.h>
#include <linux/notifier.h>

#include "xt_idp.h"

#define FBNAMSIZ IFNAMSIZ
#define MAXNBLKS 32

struct fblock;
struct fblock_ops {
	int (*netfb_rx)(struct sk_buff *skb);
	int (*event_rx)(struct notifier_block *self, unsigned long cmd,
			void *args);
};

struct fblock_notifier {
	struct notifier_block nb;
	struct fblock_notifier *next;
};

struct fblock_subscrib {
	struct atomic_notifier_head subscribers;
};

struct fblock {
	char name[FBNAMSIZ];
	u32 flags;
	void *private_data;
	struct fblock_ops *ops;
	struct fblock_notifier *notifiers;
	struct fblock_subscrib *others;
	struct fblock *next;
	struct rcu_head rcu;
	atomic_t refcnt;
	idp_t idp;
} ____cacheline_aligned_in_smp;

extern struct fblock *alloc_fblock(gfp_t flags);
extern void kfree_fblock(struct fblock *p);

extern int register_fblock_namespace(struct fblock *p);
extern int register_fblock_idp(struct fblock *p, idp_t idp);

extern int unregister_fblock(struct fblock *p);
extern void unregister_fblock_namespace(struct fblock *p);

extern int xchg_fblock_idp(idp_t idp, struct fblock *new);
extern int xchg_fblock(struct fblock *old, struct fblock *new);

extern struct fblock *search_fblock(idp_t idp);
extern struct fblock *__search_fblock(idp_t idp);

extern idp_t get_fblock_namespace_mapping(char *name); /* acquires rcu_read_lock */
extern idp_t __get_fblock_namespace_mapping(char *name);

extern int change_fblock_namespace_mapping(char *name, idp_t new); 
extern int __change_fblock_namespace_mapping(char *name, idp_t new);

extern int init_fblock_tables(void);
extern void cleanup_fblock_tables(void);

static inline void get_fblock(struct fblock *b)
{
	atomic_inc(&b->refcnt);
}

static inline void put_fblock(struct fblock *b)
{
	if (likely(!atomic_dec_and_test(&b->refcnt)))
		return;
	kfree_fblock(b);
}
#endif /* XT_FBLOCK_H */
