/*
 * Lightweight Autonomic Network Architecture
 *
 * LANA packet processing engines (ppe).
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/percpu.h>
#include <linux/cache.h>
#include <linux/proc_fs.h>

#include "xt_engine.h"
#include "xt_skb.h"
#include "xt_fblock.h"

struct engine_iostats {
	unsigned long long bytes;
	unsigned long long pkts;
	unsigned long long fblocks;
} ____cacheline_aligned;

static struct engine_iostats __percpu *iostats;

extern struct proc_dir_entry *lana_proc_dir;
static struct proc_dir_entry *engine_proc;

static inline void engine_inc_pkts_stats(void)
{
	this_cpu_inc(iostats->pkts);
}

static inline void engine_inc_fblock_stats(void)
{
	this_cpu_inc(iostats->pkts);
}

static inline void engine_add_bytes_stats(unsigned long bytes)
{
	this_cpu_add(iostats->bytes, bytes);
}

/* Main function, must be called in rcu_read_lock context */
int process_packet(struct sk_buff *skb, enum path_type dir)
{
	int ret = PPE_ERROR;
	idp_t cont;
	struct fblock *fb;

	engine_inc_pkts_stats();
	engine_add_bytes_stats(skb->len);

	while ((cont = read_next_idp_from_skb(skb))) {
		fb = __search_fblock(cont);
		if (unlikely(!fb)) {
			ret = PPE_ERROR;
			break;
		}
		ret = fb->netfb_rx(fb, skb, &dir);
		put_fblock(fb);
		engine_inc_fblock_stats();
		if (ret == PPE_DROPPED) {
			ret = PPE_DROPPED;
			break;
		}
	}

	return ret;
}
EXPORT_SYMBOL_GPL(process_packet);

static int engine_procfs(char *page, char **start, off_t offset,
			 int count, int *eof, void *data)
{
	unsigned int cpu;
	off_t len = 0;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct engine_iostats *iostats_cpu;
		iostats_cpu = per_cpu_ptr(iostats, cpu);
		len += sprintf(page + len, "CPU%u:\t%llu\t%llu\t%llu\n",
			       cpu, iostats_cpu->pkts, iostats_cpu->bytes,
			       iostats_cpu->fblocks);
	}
	put_online_cpus();

        /* FIXME: fits in page? */
        *eof = 1;
        return len;
}

int init_engine(void)
{
	unsigned int cpu;
	iostats = alloc_percpu(struct engine_iostats);
	if (!iostats)
		return -ENOMEM;
	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct engine_iostats *iostats_cpu;
		iostats_cpu = per_cpu_ptr(iostats, cpu);
		iostats_cpu->bytes = 0;
		iostats_cpu->pkts = 0;
		iostats_cpu->fblocks = 0;
	}
	put_online_cpus();
	engine_proc = create_proc_read_entry("ppe", 0400, lana_proc_dir,
					     engine_procfs, NULL);
	if (!engine_proc) {
		free_percpu(iostats);
		return -ENOMEM;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(init_engine);

void cleanup_engine(void)
{
	if (iostats)
		free_percpu(iostats);
	remove_proc_entry("ppe", lana_proc_dir);
}
EXPORT_SYMBOL_GPL(cleanup_engine);

