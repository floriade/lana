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
#include <linux/rcupdate.h>
#include <linux/module.h>

#include "xt_sched.h"

#define MAX_SCHED 32

static volatile int pc = -1;
struct ppesched_discipline *pdt[MAX_SCHED];

extern struct proc_dir_entry *lana_proc_dir;
static struct proc_dir_entry *ppesched_proc;

int ppesched_init(void)
{
	if (unlikely(pc == -1))
		return -ENOENT;
	if (rcu_dereference_raw(pdt[pc])->ops->discipline_init)
		return rcu_dereference_raw(pdt[pc])->ops->discipline_init();
	return 0;
}
EXPORT_SYMBOL_GPL(ppesched_init);

int ppesched_sched(struct sk_buff *skb, enum path_type dir)
{
	if (unlikely(pc == -1)) {
		kfree_skb(skb);
		return -EIO;
	}
	return rcu_dereference_raw(pdt[pc])->ops->discipline_sched(skb, dir);
}
EXPORT_SYMBOL_GPL(ppesched_sched);

void ppesched_cleanup(void)
{
	if (rcu_dereference_raw(pdt[pc])->ops->discipline_cleanup)
		rcu_dereference_raw(pdt[pc])->ops->discipline_cleanup();
}
EXPORT_SYMBOL_GPL(ppesched_cleanup);

int ppesched_discipline_register(struct ppesched_discipline *pd)
{
	int i;
	for (i = 0; i < MAX_SCHED; ++i) {
		if (!rcu_dereference_raw(pdt[i])) {
			rcu_assign_pointer(pdt[i], pd);
			if (unlikely(pc == -1)) {
				pc = i;
				smp_wmb();
				__module_get(pd->owner);
			}
			return 0;
		}
	}
	return -ENOMEM;
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
				smp_wmb();
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
		if (rcu_dereference_raw(pdt[i]))
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
	int ret = count, res;
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

	if (res >= 0 && !rcu_dereference_raw(pdt[res])) {
		ret = -EINVAL;
		goto out;
	}
	if (pc != -1)
		module_put(rcu_dereference_raw(pdt[pc])->owner);
	pc = res;
	if (pc != -1)
		__module_get(rcu_dereference_raw(pdt[res])->owner);
	smp_wmb();
out:
	kfree(discipline);
	return ret;
}

int init_ppesched_system(void)
{
	memset(pdt, 0,
	       sizeof(pdt));
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

