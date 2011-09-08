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
#include <linux/rcupdate.h>

#include "xt_engine.h"
#include "xt_skb.h"
#include "xt_fblock.h"

struct engine_iostats {
	unsigned long long bytes;
	unsigned long long pkts;
	unsigned long long fblocks;
} ____cacheline_aligned;

struct engine_disc {
	struct sk_buff_head ppe_backlog_queue;
} ____cacheline_aligned;

static struct engine_iostats __percpu *iostats;
static struct engine_disc __percpu *emdiscs;

extern struct proc_dir_entry *lana_proc_dir;
static struct proc_dir_entry *engine_proc;

static inline void engine_inc_pkts_stats(void)
{
	this_cpu_inc(iostats->pkts);
}

static inline void engine_inc_fblock_stats(void)
{
	this_cpu_inc(iostats->fblocks);
}

static inline void engine_add_bytes_stats(unsigned long bytes)
{
	this_cpu_add(iostats->bytes, bytes);
}

void engine_backlog_tail(struct sk_buff *skb, enum path_type dir)
{
	write_path_to_skb(skb, dir);
	skb_queue_tail(&(this_cpu_ptr(emdiscs)->ppe_backlog_queue), skb);
}
EXPORT_SYMBOL(engine_backlog_tail);

static inline struct sk_buff *engine_backlog_test_reduce(enum path_type *dir)
{
	struct sk_buff *skb = NULL;
	if ((skb = skb_dequeue(&(this_cpu_ptr(emdiscs)->ppe_backlog_queue))))
		(*dir) = read_path_from_skb(skb);
	return skb;
}

/* Main function, must be called in rcu_read_lock context */
int process_packet(struct sk_buff *skb, enum path_type dir)
{
	int ret;
	idp_t cont;
	struct fblock *fb;

	BUG_ON(!rcu_read_lock_held());
pkt:
	ret = PPE_ERROR;
	engine_inc_pkts_stats();
	engine_add_bytes_stats(skb->len);

	while ((cont = read_next_idp_from_skb(skb))) {
		fb = __search_fblock(cont);
		if (unlikely(!fb)) {
			/* We free the skb since the fb doesn't exist! */
			kfree_skb(skb);
			ret = PPE_ERROR;
			break;
		}

		ret = fb->netfb_rx(fb, skb, &dir);
		/* The FB frees the skb or not depending on its binding
		 * and we must not touch it! */
		put_fblock(fb);
		engine_inc_fblock_stats();
		if (ret == PPE_DROPPED) {
			ret = PPE_DROPPED;
			break;
		}
	}
	if ((skb = engine_backlog_test_reduce(&dir)))
		goto pkt;
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
		struct engine_disc *emdisc_cpu;
		iostats_cpu = per_cpu_ptr(iostats, cpu);
		emdisc_cpu = per_cpu_ptr(emdiscs, cpu);
		len += sprintf(page + len, "CPU%u:\t%llu\t%llu\t%llu\t%u\n",
			       cpu, iostats_cpu->pkts, iostats_cpu->bytes,
			       iostats_cpu->fblocks,
			       skb_queue_len(&emdisc_cpu->ppe_backlog_queue));
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

	emdiscs = alloc_percpu(struct engine_disc);
	if (!emdiscs)
		goto err;
	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct engine_disc *emdisc_cpu;
		emdisc_cpu = per_cpu_ptr(emdiscs, cpu);
		skb_queue_head_init(&emdisc_cpu->ppe_backlog_queue);
	}
	put_online_cpus();

	engine_proc = create_proc_read_entry("ppe", 0400, lana_proc_dir,
					     engine_procfs, NULL);
	if (!engine_proc)
		goto err1;

	return 0;
err1:
	free_percpu(emdiscs);
err:
	free_percpu(iostats);
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(init_engine);

void cleanup_engine(void)
{
	unsigned int cpu;
	if (iostats)
		free_percpu(iostats);
	if (emdiscs) {
		get_online_cpus();
		for_each_online_cpu(cpu) {
			struct engine_disc *emdisc_cpu;
			emdisc_cpu = per_cpu_ptr(emdiscs, cpu);
			skb_queue_purge(&emdisc_cpu->ppe_backlog_queue);
		}
		put_online_cpus();
		free_percpu(emdiscs);
	}
	remove_proc_entry("ppe", lana_proc_dir);
}
EXPORT_SYMBOL_GPL(cleanup_engine);

