/*
 * Lightweight Autonomic Network Architecture
 *
 * Ingress and egress flow ppe-scheduler. Flows that traverse the network
 * stack, e.g. ranging from PHY to the socket handler, are kept CPU-affine
 * for the communication. This scheduler classifies the packet and enqueues
 * it into the specific PPE.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <net/netlink.h>
#include <net/sock.h>

#include "xt_sched.h"

#define MAX_SCHED 32

static int ppesched_current = 0;
static spinlock_t ppesched_lock;
struct ppesched_discipline *ppesched_discipline_table[MAX_SCHED];

extern struct proc_dir_entry *lana_proc_dir;
static struct proc_dir_entry *ppesched_proc;

int ppesched_init(void)
{
	int ret;
	unsigned long flags;
	spin_lock_irqsave(&ppesched_lock, flags);
	ret = ppesched_discipline_table[ppesched_current]->ops->discipline_init();
	spin_unlock_irqrestore(&ppesched_lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(ppesched_init);

int ppesched_sched(struct sk_buff *skb, enum path_type dir)
{
	int ret;
	unsigned long flags;
	spin_lock_irqsave(&ppesched_lock, flags);
	ret = ppesched_discipline_table[ppesched_current]->ops->discipline_sched(skb, dir);
	spin_unlock_irqrestore(&ppesched_lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(ppesched_sched);

void ppesched_cleanup(void)
{
	unsigned long flags;
	spin_lock_irqsave(&ppesched_lock, flags);
	ppesched_discipline_table[ppesched_current]->ops->discipline_cleanup();
	spin_unlock_irqrestore(&ppesched_lock, flags);
}
EXPORT_SYMBOL_GPL(ppesched_cleanup);

int ppesched_discipline_register(struct ppesched_discipline *pd)
{
	int i, done = 0;
	spin_lock(&ppesched_lock);
	for (i = 0; i < MAX_SCHED; ++i) {
		if (!ppesched_discipline_table[i]) {
			ppesched_discipline_table[i] = pd;
			done = 1;
			break;
		}
	}
	spin_unlock(&ppesched_lock);
	return done ? 0 : -ENOMEM;
}
EXPORT_SYMBOL_GPL(ppesched_discipline_register);

void ppesched_discipline_unregister(struct ppesched_discipline *pd)
{
	int i;
	spin_lock(&ppesched_lock);
	for (i = 0; i < MAX_SCHED; ++i) {
		if (ppesched_discipline_table[i] == pd) {
			ppesched_discipline_table[i] = NULL;
			break;
		}
	}
	spin_unlock(&ppesched_lock);
}
EXPORT_SYMBOL_GPL(ppesched_discipline_unregister);

static int ppesched_procfs(char *page, char **start, off_t offset,
			   int count, int *eof, void *data)
{
	int i;
	off_t len = 0;

	spin_lock(&ppesched_lock);
	len += sprintf(page + len, "running: %s\n",
		       ppesched_discipline_table[ppesched_current]->name);
	len += sprintf(page + len, "name addr id\n");
	for (i = 0; i < MAX_SCHED; ++i) {
		if (ppesched_discipline_table[i])
			len += sprintf(page + len, "%s %p %d\n",
				       ppesched_discipline_table[i]->name,
				       ppesched_discipline_table[i], i);
	}
	spin_unlock(&ppesched_lock);

	*eof = 1;
	return len;
}

int init_ppesched_system(void)
{
	ppesched_lock = __SPIN_LOCK_UNLOCKED(ppesched_lock);
	memset(ppesched_discipline_table, 0,
	       sizeof(ppesched_discipline_table));
	ppesched_proc = create_proc_read_entry("ppesched", 0444, lana_proc_dir,
					       ppesched_procfs, NULL);
	if (!ppesched_proc)
		return -ENOMEM;
	return 0;
}
EXPORT_SYMBOL_GPL(init_ppesched_system);

void cleanup_ppesched_system(void)
{
	remove_proc_entry("ppesched", lana_proc_dir);
//	netlink_kernel_release(ppesched_sock);
}
EXPORT_SYMBOL_GPL(cleanup_ppesched_system);

