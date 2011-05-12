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

static int pc = -1;
static spinlock_t ppesched_lock;
struct ppesched_discipline *pdt[MAX_SCHED];

extern struct proc_dir_entry *lana_proc_dir;
static struct proc_dir_entry *ppesched_proc;

int ppesched_init(void)
{
	int ret;
	unsigned long flags;
	spin_lock_irqsave(&ppesched_lock, flags);
	if (unlikely(pc == -1)) {
		spin_unlock_irqrestore(&ppesched_lock, flags);
		return -ENOENT;
	}
	if (!pdt[pc]->ops->discipline_init) {
		spin_unlock_irqrestore(&ppesched_lock, flags);
		return 0;
	}
	ret = pdt[pc]->ops->discipline_init();
	spin_unlock_irqrestore(&ppesched_lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(ppesched_init);

int ppesched_sched(struct sk_buff *skb, enum path_type dir)
{
	int ret;
	unsigned long flags;
	spin_lock_irqsave(&ppesched_lock, flags);
	if (unlikely(pc == -1)) {
		spin_unlock_irqrestore(&ppesched_lock, flags);
		kfree_skb(skb);
		return -EIO;
	}
	if (!pdt[pc]->ops->discipline_sched) {
		spin_unlock_irqrestore(&ppesched_lock, flags);
		kfree_skb(skb);
		return -EIO;
	}
	ret = pdt[pc]->ops->discipline_sched(skb, dir);
	spin_unlock_irqrestore(&ppesched_lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(ppesched_sched);

void ppesched_cleanup(void)
{
	unsigned long flags;
	spin_lock_irqsave(&ppesched_lock, flags);
	if (unlikely(pc == -1)) {
		spin_unlock_irqrestore(&ppesched_lock, flags);
		return;
	}
	if (!pdt[pc]->ops->discipline_cleanup) {
		spin_unlock_irqrestore(&ppesched_lock, flags);
		return;
	}
	pdt[pc]->ops->discipline_cleanup();
	spin_unlock_irqrestore(&ppesched_lock, flags);
}
EXPORT_SYMBOL_GPL(ppesched_cleanup);

int ppesched_discipline_register(struct ppesched_discipline *pd)
{
	int i, done = 0;
	unsigned long flags;
	spin_lock_irqsave(&ppesched_lock, flags);
	for (i = 0; i < MAX_SCHED; ++i) {
		if (!pdt[i]) {
			pdt[i] = pd;
			if (unlikely(pc == -1)) {
				pc = i;
				__module_get(pd->owner);
			}
			done = 1;
			break;
		}
	}
	spin_unlock_irqrestore(&ppesched_lock, flags);
	return done ? 0 : -ENOMEM;
}
EXPORT_SYMBOL_GPL(ppesched_discipline_register);

void ppesched_discipline_unregister(struct ppesched_discipline *pd)
{
	int i;
	unsigned long flags;
	spin_lock_irqsave(&ppesched_lock, flags);
	for (i = 0; i < MAX_SCHED; ++i) {
		if (pdt[i] == pd) {
			pdt[i] = NULL;
			if (i == pc) {
				pc = -1;
				module_put(pd->owner);
			}
			break;
		}
	}
	spin_unlock_irqrestore(&ppesched_lock, flags);
}
EXPORT_SYMBOL_GPL(ppesched_discipline_unregister);

static int ppesched_procfs_read(char *page, char **start, off_t offset,
				int count, int *eof, void *data)
{
	int i;
	off_t len = 0;

	spin_lock(&ppesched_lock);
	len += sprintf(page + len, "running: %s\n",
		       pc != -1 ?
		       pdt[pc]->name :
		       "none");
	len += sprintf(page + len, "name addr id\n");
	for (i = 0; i < MAX_SCHED; ++i) {
		if (pdt[i])
			len += sprintf(page + len, "%s %p %d\n",
				       pdt[i]->name,
				       pdt[i], i);
	}
	spin_unlock(&ppesched_lock);

	*eof = 1;
	return len;
}

static int ppesched_procfs_write(struct file *file, const char __user *buffer,
				 unsigned long count, void *data)
{
	int ret, res;
	unsigned long flags;
	size_t len;
	char *discipline;

	if (count > 64)
		return -EINVAL;
	len = count;
	discipline = kmalloc(len, GFP_KERNEL);
	if (!discipline)
		return -ENOMEM;
	memset(discipline, 0, len);
	if (copy_from_user(discipline, buffer, len)) {
		ret = -EFAULT;
		goto out;
	}
	discipline[len - 1] = 0;
	res = simple_strtol(discipline, &discipline, 10);
	if (res >= MAX_SCHED || res < -1) {
		ret = -EINVAL;
		goto out;
	}
	spin_lock_irqsave(&ppesched_lock, flags);
	if (res >= 0) {
		if (!pdt[res]) {
			spin_unlock_irqrestore(&ppesched_lock, flags);
			ret = -EINVAL;
			goto out;
		}
	}
	if (pc != -1)
		module_put(pdt[pc]->owner);
	pc = res;
	if (pc != -1)
		__module_get(pdt[pc]->owner);
	spin_unlock_irqrestore(&ppesched_lock, flags);

	ret = count;
out:
	kfree(discipline);
	return ret;
}

int init_ppesched_system(void)
{
	ppesched_lock = __SPIN_LOCK_UNLOCKED(ppesched_lock);
	memset(pdt, 0, sizeof(pdt));
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

