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
#include <linux/rcupdate.h>
#include <linux/module.h>

#include "xt_sched.h"

#define MAX_SCHED 32

static volatile int pc = -1;
static struct ppesched_discipline *pdt[MAX_SCHED];

extern struct proc_dir_entry *lana_proc_dir;
static struct proc_dir_entry *ppesched_proc;

int ppesched_init(void)
{
	struct ppesched_discipline *dis;
	if (unlikely(pc == -1))
		return -ENOENT;
	dis = rcu_dereference_raw(pdt[pc]);
	if (!dis->ops->discipline_init)
		return 0;
	return dis->ops->discipline_init();
}
EXPORT_SYMBOL_GPL(ppesched_init);

int ppesched_sched(struct sk_buff *skb, enum path_type dir)
{
	struct ppesched_discipline *dis;
	if (unlikely(pc == -1)) {
		kfree_skb(skb);
		return -EIO;
	}
	dis = rcu_dereference_raw(pdt[pc]);
	if (unlikely(!dis || !dis->ops->discipline_sched)) {
		kfree_skb(skb);
		return -EIO;
	}
	return dis->ops->discipline_sched(skb, dir);
}
EXPORT_SYMBOL_GPL(ppesched_sched);

void ppesched_cleanup(void)
{
	struct ppesched_discipline *dis;
	if (unlikely(pc == -1))
		return;
	dis = rcu_dereference_raw(pdt[pc]);
	if (!dis->ops->discipline_cleanup)
		return;
	dis->ops->discipline_cleanup();
}
EXPORT_SYMBOL_GPL(ppesched_cleanup);

int ppesched_discipline_register(struct ppesched_discipline *pd)
{
	int i, done = 0;
	for (i = 0; i < MAX_SCHED; ++i) {
		if (!rcu_dereference_raw(pdt[i])) {
			rcu_assign_pointer(pdt[i], pd);
			if (unlikely(pc == -1)) {
				pc = i;
				barrier();
				__module_get(pd->owner);
			}
			done = 1;
			break;
		}
	}
	return done ? 0 : -ENOMEM;
}
EXPORT_SYMBOL_GPL(ppesched_discipline_register);

void ppesched_discipline_unregister(struct ppesched_discipline *pd)
{
	int i;
	for (i = 0; i < MAX_SCHED; ++i) {
		if (rcu_dereference_raw(pdt[i]) == pd) {
			rcu_assign_pointer(pdt[i], NULL);
			if (i == pc) {
				pc = -1;
				barrier();
				module_put(pd->owner);
			}
			break;
		}
	}
}
EXPORT_SYMBOL_GPL(ppesched_discipline_unregister);

static int ppesched_procfs_read(char *page, char **start, off_t offset,
				int count, int *eof, void *data)
{
	int i;
	off_t len = 0;

	len += sprintf(page + len, "running: %s\n",
		       pc != -1 ?
		       rcu_dereference_raw(pdt[pc])->name :
		       "none");
	len += sprintf(page + len, "name addr id\n");
	for (i = 0; i < MAX_SCHED; ++i) {
		if (pdt[i])
			len += sprintf(page + len, "%s %p %d\n",
				       rcu_dereference_raw(pdt[i])->name,
				       rcu_dereference_raw(pdt[i]), i);
	}

	*eof = 1;
	return len;
}

static int ppesched_procfs_write(struct file *file, const char __user *buffer,
				 unsigned long count, void *data)
{
	int ret, res;
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
	res = simple_strtol(discipline, NULL, 10);
	if (res >= MAX_SCHED || res < -1) {
		ret = -EINVAL;
		goto out;
	}
	if (res >= 0) {
		if (!pdt[res]) {
			ret = -EINVAL;
			goto out;
		}
	}
	if (pc != -1)
		module_put(pdt[pc]->owner);
	pc = res;
	barrier();
	if (pc != -1)
		__module_get(pdt[pc]->owner);
	ret = len;
out:
	kfree(discipline);
	return ret;
}

int init_ppesched_system(void)
{
	int i;
	for (i = 0; i < MAX_SCHED; ++i)
		pdt[i] = NULL;

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

