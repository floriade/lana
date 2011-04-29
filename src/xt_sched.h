/*
 * Lightweight Autonomic Network Architecture
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#ifndef XT_SCHED_H
#define XT_SCHED_H

#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/proc_fs.h>

#include "xt_fblock.h"

extern struct proc_dir_entry *sched_proc_dir;

struct ppesched_discipline_ops {
	int (*discipline_init)(void);
	int (*discipline_sched)(struct sk_buff *skb, enum path_type dir);
	void (*discipline_cleanup)(void);
};

struct ppesched_discipline {
	char *name;
	struct ppesched_discipline_ops *ops;
	struct module *owner;
};

extern int ppesched_init(void);
extern int ppesched_sched(struct sk_buff *skb, enum path_type dir);
extern void ppesched_cleanup(void);

extern int ppesched_discipline_register(struct ppesched_discipline *pd);
extern void ppesched_discipline_unregister(struct ppesched_discipline *pd);

extern int init_ppesched_system(void);
extern void cleanup_ppesched_system(void);

#endif /* XT_SCHED_H */
