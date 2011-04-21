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
#include <linux/rwlock.h>
#include <linux/skbuff.h>
#include <linux/notifier.h>

#include "xt_idp.h"

#define FBLOCK_DOWN_PREPARE	 0x0001	/* Notify of fblock going down */
#define FBLOCK_DOWN		 0x0002	/* Notify of fblock is down    */

#define FBNAMSIZ                 IFNAMSIZ
#define TYPNAMSIZ                FBNAMSIZ

struct fblock;

struct fblock_ops {
	int (*netfb_rx)(struct fblock *fb, struct sk_buff *skb);
	int (*event_rx)(struct notifier_block *self, unsigned long cmd,
			void *args);
};

struct fblock_factory_ops {
	char type[TYPNAMSIZ];
	struct fblock *(*ctor)(char *name);
	void (*dtor)(struct fblock *fb);
} ____cacheline_aligned;

struct fblock_notifier {
	struct fblock *self;
	struct fblock *remote;
	struct notifier_block nb;
	struct fblock_notifier *next;
} ____cacheline_aligned;

struct fblock_subscrib {
	struct atomic_notifier_head subscribers;
};

struct fblock {
	char name[FBNAMSIZ];
	void *private_data;
	struct fblock_ops *ops;
	struct fblock_factory_ops *fops;
	struct fblock_notifier *notifiers;
	struct fblock_subscrib *others;
	struct fblock *next;
	struct rcu_head rcu;
	atomic_t refcnt;
	idp_t idp;
	rwlock_t lock;
} ____cacheline_aligned;

extern struct fblock *alloc_fblock(gfp_t flags);
extern void kfree_fblock(struct fblock *p);

extern int init_fblock(struct fblock *fb, char *name, void *priv,
		       struct fblock_ops *ops);
extern void cleanup_fblock(struct fblock *fb);

extern int register_fblock_namespace(struct fblock *p);
extern int register_fblock_idp(struct fblock *p, idp_t idp);

extern int unregister_fblock(struct fblock *p);
extern void unregister_fblock_namespace(struct fblock *p);

extern int xchg_fblock_idp(idp_t idp, struct fblock *new);
extern int xchg_fblock(struct fblock *old, struct fblock *new);

extern struct fblock *search_fblock(idp_t idp);
extern struct fblock *__search_fblock(idp_t idp);

extern idp_t get_fblock_namespace_mapping(char *name);
extern idp_t __get_fblock_namespace_mapping(char *name);

extern int change_fblock_namespace_mapping(char *name, idp_t new); 
extern int __change_fblock_namespace_mapping(char *name, idp_t new);

extern int init_fblock_tables(void);
extern void cleanup_fblock_tables(void);

extern int subscribe_to_remote_fblock(struct fblock *us,
				      struct fblock *remote);
extern void unsubscribe_from_remote_fblock(struct fblock *us,
					   struct fblock *remote);

static inline void init_fblock_subscriber(struct fblock *fb,
					  struct notifier_block *nb)
{
	nb->priority = 0;
	nb->notifier_call = fb->ops->event_rx;
	nb->next = NULL;
}

static inline int
fblock_register_foreign_subscriber(struct fblock *us,
				   struct notifier_block *remote)
{
	return atomic_notifier_chain_register(&us->others->subscribers,
					      remote);
}

static inline void
fblock_unregister_foreign_subscriber(struct fblock *us,
				     struct notifier_block *remote)
{
	atomic_notifier_chain_unregister(&us->others->subscribers, remote);
}

static inline int notify_fblock_subscribers(struct fblock *us,
					    unsigned long cmd, void *arg)
{
	if (unlikely(!us->others))
		return -ENOENT;
	return atomic_notifier_call_chain(&us->others->subscribers, cmd, arg);
}

static inline void get_fblock(struct fblock *fb)
{
	atomic_inc(&fb->refcnt);
}

static inline void put_fblock(struct fblock *fb)
{
	if (likely(!atomic_dec_and_test(&fb->refcnt)))
		return;
	cleanup_fblock(fb);
	kfree_fblock(fb);
}

#endif /* XT_FBLOCK_H */
