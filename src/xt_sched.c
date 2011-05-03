/*
 * Lightweight Autonomic Network Architecture
 *
 * Ingress and egress flow ppe-scheduler. Flows that traverse the network
 * stack, e.g. ranging from PHY to the socket handler, are kept CPU-affine
 * for the communication. This scheduler framework offers modules to register
 * their disciplines.
 *
 * Change scheduling policies with, i.e. echo "1" > /proc/net/lana/ppesched
 * where "n" is the id of the discipline.
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

#include "xt_sched.h"

#define MAX_SCHED 32

static int ppesched_current = -1;
static spinlock_t ppesched_lock;
struct ppesched_discipline *ppesched_discipline_table[MAX_SCHED];

extern struct proc_dir_entry *lana_proc_dir;
static struct proc_dir_entry *ppesched_proc;

int ppesched_init(void)
{
	int ret;
	unsigned long flags;
	spin_lock_irqsave(&ppesched_lock, flags);
	if (unlikely(ppesched_current == -1)) {
		spin_unlock_irqrestore(&ppesched_lock, flags);
		return -ENOENT;
	}
	ret = ppesched_discipline_table[ppesched_current]->ops->discipline_init();
	spin_unlock_irqrestore(&ppesched_lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(ppesched_init);

/* ppesched_current must be set previously! */
int ppesched_sched(struct sk_buff *skb, enum path_type dir)
{
	int ret;
	unsigned long flags;
	spin_lock_irqsave(&ppesched_lock, flags);
	if (unlikely(ppesched_current == -1)) {
		kfree_skb(skb);
		spin_unlock_irqrestore(&ppesched_lock, flags);
		return -EIO;
	}
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
			if (unlikely(ppesched_current == -1)) {
				ppesched_current = i;
				__module_get(pd->owner);
			}
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
			if (i == ppesched_current) {
				ppesched_current = -1;
				module_put(pd->owner);
			}
			break;
		}
	}
	spin_unlock(&ppesched_lock);
}
EXPORT_SYMBOL_GPL(ppesched_discipline_unregister);

static int ppesched_procfs_read(char *page, char **start, off_t offset,
				int count, int *eof, void *data)
{
	int i;
	off_t len = 0;

	spin_lock(&ppesched_lock);
	len += sprintf(page + len, "running: %s\n",
		       ppesched_current != -1 ?
		       ppesched_discipline_table[ppesched_current]->name :
		       "none");
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

static int ppesched_procfs_write(struct file *file, const char __user *buffer,
				 unsigned long count, void *data)
{
	int ret, res;
	size_t len;
	char *discipline;

	discipline = kzalloc(32, GFP_KERNEL);
	if (!discipline)
		return -ENOMEM;
	len = min(sizeof(discipline), (size_t) count);
	if (copy_from_user(discipline, buffer, len)) {
		ret = -EFAULT;
		goto out;
	}
	discipline[sizeof(discipline) - 1] = 0;
	res = simple_strtol(discipline, &discipline, 10);
	if (res >= MAX_SCHED || res < -1) {
		ret = -EINVAL;
		goto out;
	}
	spin_lock(&ppesched_lock);
	if (res >= 0 && !ppesched_discipline_table[res]) {
		spin_unlock(&ppesched_lock);
		ret = -EINVAL;
		goto out;
	}
	if (ppesched_current != -1)
		module_put(ppesched_discipline_table[ppesched_current]->owner);
	ppesched_current = res;
	if (ppesched_current != -1)
		__module_get(ppesched_discipline_table[res]->owner);
	spin_unlock(&ppesched_lock);

	return count;
out:
	kfree(discipline);
	return ret;
}

int init_ppesched_system(void)
{
	ppesched_lock = __SPIN_LOCK_UNLOCKED(ppesched_lock);
	memset(ppesched_discipline_table, 0,
	       sizeof(ppesched_discipline_table));
	ppesched_proc = create_proc_entry("ppesched", 0600, lana_proc_dir);
	if (!ppesched_proc)
		return -ENOMEM;
	ppesched_proc->read_proc = ppesched_procfs_read;
	ppesched_proc->write_proc = ppesched_procfs_write;
	return 0;
}
EXPORT_SYMBOL_GPL(init_ppesched_system);

void cleanup_ppesched_system(void)
{
	remove_proc_entry("ppesched", lana_proc_dir);
}
EXPORT_SYMBOL_GPL(cleanup_ppesched_system);

