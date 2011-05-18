/*
 * Lightweight Autonomic Network Architecture
 *
 * Single CPU scheduler.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cache.h>
#include <linux/cpumask.h>
#include <linux/spinlock.h>

#include "xt_sched.h"
#include "xt_engine.h"

extern struct proc_dir_entry *sched_proc_dir;
static struct proc_dir_entry *ppesched_cpu_proc;
static volatile unsigned long cpu = 0;

static int ppe_single_sched(struct sk_buff *skb, enum path_type dir)
{
#ifdef __MIGRATE
        if (cpu != USERSPACECPU)
	        enqueue_on_engine(skb, cpu, dir);
	else
		kfree_skb(skb);
#else
	enqueue_on_engine(skb, cpu, dir);
#endif /* __MIGRATE */
	return PPE_SUCCESS;
}

static struct ppesched_discipline_ops ppe_single_ops __read_mostly = {
	.discipline_sched = ppe_single_sched,
};

static struct ppesched_discipline ppe_single __read_mostly = {
	.name = "singlecpu",
	.ops = &ppe_single_ops,
	.owner = THIS_MODULE,
};

static int ppe_single_procfs_read(char *page, char **start, off_t offset,
				  int count, int *eof, void *data)
{
	off_t len = 0;
	len += sprintf(page + len, "%lu\n", cpu);
	*eof = 1;
	return len;
}

static int ppe_single_procfs_write(struct file *file, const char __user *buffer,
				   unsigned long count, void *data)
{
	int ret = count, res;
	size_t len;
	char *dst_cpu;

	if (count > 64)
		return -EINVAL;
	len = count;
	dst_cpu = kmalloc(len, GFP_KERNEL);
	if (!dst_cpu)
		return -ENOMEM;
	memset(dst_cpu, 0, len);
	if (copy_from_user(dst_cpu, buffer, len)) {
		ret = -EFAULT;
		goto out;
	}
	dst_cpu[len - 1] = 0;
	res = simple_strtol(dst_cpu, NULL, 10);
	if (res >= num_online_cpus() || res < 0) {
		ret = -EINVAL;
		goto out;
	}
	cpu = res;
	barrier();
	ret = len;
out:
	kfree(dst_cpu);
	return ret;
}

static int __init init_ppe_single_module(void)
{
	int ret;
	ret = ppesched_discipline_register(&ppe_single);
	if (ret != 0)
		return ret;
	ppesched_cpu_proc = create_proc_entry("sched_cpu", 0666,
					      sched_proc_dir);
	if (!ppesched_cpu_proc) {
		ppesched_discipline_unregister(&ppe_single);
		return -ENOMEM;
	}
	ppesched_cpu_proc->read_proc = ppe_single_procfs_read;
	ppesched_cpu_proc->write_proc = ppe_single_procfs_write;
	ppesched_cpu_proc->data = NULL;
	return 0;
}

static void __exit cleanup_ppe_single_module(void)
{
	remove_proc_entry("sched_cpu", sched_proc_dir);
	ppesched_discipline_unregister(&ppe_single);
}

module_init(init_ppe_single_module);
module_exit(cleanup_ppe_single_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA single CPU scheduler");

