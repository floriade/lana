/*
 * Lightweight Autonomic Network Architecture
 *
 * Migration function for tasks. Tasks will be rescheduled with another
 * CPU affinity, so that PPEs are the only users on a CPU. Usefull for
 * Appliances like Routers.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/security.h>
#include <linux/cpuset.h>

#include "xt_migrate.h"

#ifdef __MIGRATE
void try_migrate_procs_to(unsigned long cpu)
{
	int retval;
	unsigned int count = 0;
	struct task_struct *p;
	struct cpumask in_mask;
	cpumask_var_t new_mask;

	if (num_online_cpus() == 1 || cpu >= num_online_cpus())
		return;

	cpumask_clear(&in_mask);
	cpumask_set_cpu(cpu, &in_mask);

	for_each_process(p) {
		get_online_cpus();
		get_task_struct(p);
		if (!alloc_cpumask_var(&new_mask, GFP_KERNEL))
			goto try_next;
		cpumask_copy(new_mask, &in_mask);
		retval = set_cpus_allowed_ptr(p, new_mask);
		if (!retval)
			count++;
		free_cpumask_var(new_mask);
try_next:
		put_task_struct(p);
		put_online_cpus();
	}
	printk(KERN_INFO "[lana] %u processes migrated to CPU%lu!\n",
	       count, cpu);
}
#else
void try_migrate_procs_to(unsigned long cpu) { }
#endif /* __MIGRATE */
EXPORT_SYMBOL(try_migrate_procs_to);

