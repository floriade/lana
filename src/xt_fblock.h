/*
 * Lightweight Autonomic Network Architecture
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#ifndef XT_FBLOCK_H
#define XT_FBLOCK_H

#ifdef __KERNEL__

#include <linux/proc_fs.h>
#include <linux/if.h>
#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/notifier.h>
#include <linux/radix-tree.h>

#include "xt_idp.h"

enum path_type {
        TYPE_INGRESS = 0,
#define TYPE_INGRESS		TYPE_INGRESS
        TYPE_EGRESS,
#define TYPE_EGRESS		TYPE_EGRESS
        _TYPE_MAX,
};

extern const char *path_names[];

enum fblock_mode {
	MODE_SOURCE = 0,
#define MODE_SOURCE		MODE_SOURCE
	MODE_SINK,
#define MODE_SINK		MODE_SINK
	MODE_DUAL,
#define MODE_DUAL		MODE_DUAL
};

#define NUM_TYPES		_TYPE_MAX

#define FBLOCK_BIND_IDP		0x0001
#define FBLOCK_UNBIND_IDP	0x0002
#define FBLOCK_SET_OPT		0x0003
#define FBLOCK_DOWN_PREPARE	0x0004
#define FBLOCK_DOWN		0x0005

#endif /* __KERNEL__ */

#define FBNAMSIZ		IFNAMSIZ
#define TYPNAMSIZ		FBNAMSIZ

#ifdef __KERNEL__

extern struct proc_dir_entry *fblock_proc_dir;

struct fblock_bind_msg {
	enum path_type dir;
	idp_t idp;
};

struct fblock_opt_msg {
	char *key;
	char *val;
};

struct fblock;

struct fblock_factory {
	char type[TYPNAMSIZ];
	enum fblock_mode mode;
	struct module *owner;
	struct fblock *(*ctor)(char *name);
	void (*dtor)(struct fblock *fb);
	void (*dtor_outside_rcu)(struct fblock *fb);
} ____cacheline_aligned;

struct fblock_notifier {
	struct fblock *self;
	struct notifier_block nb;
	struct fblock_notifier *next;
	idp_t remote;
};

struct fblock_subscrib {
	struct atomic_notifier_head subscribers;
};

struct fblock {
	char name[FBNAMSIZ];
	void __percpu *private_data;
	int (*netfb_rx)(const struct fblock * const fb,
			struct sk_buff * const skb,
			enum path_type * const dir);
	int (*event_rx)(struct notifier_block *self, unsigned long cmd,
			void *args);
	struct fblock_factory *factory;
	struct fblock_notifier *notifiers;
	struct fblock_subscrib *others;
	struct rcu_head rcu;
	atomic_t refcnt;
	idp_t idp;
	spinlock_t lock; /* Used in notifiers */
} ____cacheline_aligned;

extern void free_fblock_rcu(struct rcu_head *rp);

static inline void get_fblock(struct fblock *fb)
{
	atomic_inc(&fb->refcnt);
}

static inline void put_fblock(struct fblock *fb)
{
	if (likely(!atomic_dec_and_test(&fb->refcnt)))
		return;
	if (fb->factory) {
		if (fb->factory->dtor_outside_rcu)
			fb->factory->dtor_outside_rcu(fb);
		call_rcu(&fb->rcu, free_fblock_rcu);
	}
}

/*
 * Note: __* variants do not hold the rcu_read_lock!
 */

/* Allocate/free a new fblock object. */
extern struct fblock *alloc_fblock(gfp_t flags);
extern void kfree_fblock(struct fblock *p);

/* Initialize/cleanup a fblock object. */
extern int init_fblock(struct fblock *fb, char *name, void __percpu *priv);
extern void cleanup_fblock(struct fblock *fb);
extern void cleanup_fblock_ctor(struct fblock *fb);

/*
 * Registers a fblock object to the stack. Latter variant allocates 
 * a new unused idp, former uses a given _free_ idp.
 */
extern int register_fblock(struct fblock *p, idp_t idp);
extern int register_fblock_namespace(struct fblock *p);

/*
 * Unregisters a fblock object from the stack. Former variant does not 
 * release the idp to name mapping, latter variant frees it, too.
 */
extern void unregister_fblock(struct fblock *p);
extern void unregister_fblock_namespace(struct fblock *p);
extern void unregister_fblock_namespace_no_rcu(struct fblock *p);

extern struct radix_tree_root fblmap;

/* Caller needs to do a put_fblock() after his work is done! */
/* Called within RCU read lock! */
#define __search_fblock(idp)					\
({								\
	struct fblock *ret = radix_tree_lookup(&fblmap, idp);	\
	if (likely(ret))					\
		get_fblock(ret);				\
	ret;							\
})

/* Returns fblock object specified by idp or name. */
extern struct fblock *search_fblock(idp_t idp);
extern struct fblock *search_fblock_n(char *name);

/* Migrate state from src to dst and drop of dst states */
extern void fblock_migrate_p(struct fblock *dst, struct fblock *src);
extern void fblock_migrate_r(struct fblock *dst, struct fblock *src);

/* Notify fblock of new option. */
extern int fblock_set_option(struct fblock *fb, char *opt_string);
extern int __fblock_set_option(struct fblock *fb, char *opt_string);

/* Binds two fblock objects, increments refcount each. */
extern int fblock_bind(struct fblock *fb1, struct fblock *fb2);
extern int __fblock_bind(struct fblock *fb1, struct fblock *fb2);

/* Unbinds two fblock objects, decrements refcount each. */
extern int fblock_unbind(struct fblock *fb1, struct fblock *fb2);
extern int __fblock_unbind(struct fblock *fb1, struct fblock *fb2);

/* Lookup idp by fblock name. */
extern idp_t get_fblock_namespace_mapping(char *name);
extern idp_t __get_fblock_namespace_mapping(char *name);

/*
 * Maps existing fblock name to a new idp, can be used if object has been
 * removed via unregister_fblock.
 */
extern int change_fblock_namespace_mapping(char *name, idp_t new); 
extern int __change_fblock_namespace_mapping(char *name, idp_t new);

extern int subscribe_to_remote_fblock(struct fblock *us,
				      struct fblock *remote);
extern void unsubscribe_from_remote_fblock(struct fblock *us,
					   struct fblock *remote);

static inline void init_fblock_subscriber(struct fblock *fb,
					  struct notifier_block *nb)
{
	nb->priority = 0;
	nb->notifier_call = fb->event_rx;
	nb->next = NULL;
}

static inline int
fblock_register_foreign_subscriber(struct fblock *us,
				   struct notifier_block *remote)
{
	return atomic_notifier_chain_register(&rcu_dereference_raw(us->others)->subscribers,
					      remote);
}

static inline void
fblock_unregister_foreign_subscriber(struct fblock *us,
				     struct notifier_block *remote)
{
	atomic_notifier_chain_unregister(&rcu_dereference_raw(us->others)->subscribers,
					 remote);
}

static inline int notify_fblock_subscribers(struct fblock *us,
					    unsigned long cmd, void *arg)
{
	if (unlikely(!rcu_dereference_raw(us->others)))
		return -ENOENT;
	return atomic_notifier_call_chain(&rcu_dereference_raw(us->others)->subscribers,
					  cmd, arg);
}

extern int init_fblock_tables(void);
extern void cleanup_fblock_tables(void);

/* here is the address, e.g. __builtin_return_address(0) */
static inline void fblock_over_panic(struct fblock *fb, void *here)
{
	printk(KERN_EMERG "fblock_over_panic: text:%p ptr:%p idp:%u refs:%d "
			  "name:%s priv:%p fac:%p not:%p others: %p\n",
	       here, fb, fb->idp, atomic_read(&fb->refcnt), fb->name, 
	       fb->private_data, fb->factory, fb->notifiers, fb->others);
	BUG();
}

#endif /* __KERNEL__ */
#endif /* XT_FBLOCK_H */
