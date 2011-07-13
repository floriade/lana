/*
 * Lightweight Autonomic Network Architecture
 *
 * Packet counter module.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/notifier.h>
#include <linux/rcupdate.h>
#include <linux/seqlock.h>
#include <linux/percpu.h>
#include <linux/prefetch.h>
#include <linux/u64_stats_sync.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "xt_fblock.h"
#include "xt_builder.h"
#include "xt_idp.h"
#include "xt_skb.h"
#include "xt_engine.h"
#include "xt_builder.h"

struct fb_counter_priv {
	idp_t port[2];
	seqlock_t lock;
	u64 packets;
	u64 bytes;
	struct u64_stats_sync syncp;
};

static int fb_counter_netrx(const struct fblock * const fb,
			    struct sk_buff * const skb,
			    enum path_type * const dir)
{
	int drop = 0;
	unsigned int seq;
	struct fb_counter_priv __percpu *fb_priv_cpu;

	fb_priv_cpu = this_cpu_ptr(rcu_dereference_raw(fb->private_data));
#ifdef __DEBUG
	printk("Got skb on %p on ppe%d!\n", fb, smp_processor_id());
#endif
	prefetchw(skb->cb);
	do {
		seq = read_seqbegin(&fb_priv_cpu->lock);
		write_next_idp_to_skb(skb, fb->idp, fb_priv_cpu->port[*dir]);
		if (fb_priv_cpu->port[*dir] == IDP_UNKNOWN)
			drop = 1;
	} while (read_seqretry(&fb_priv_cpu->lock, seq));

	u64_stats_update_begin(&fb_priv_cpu->syncp);
	fb_priv_cpu->packets++;
	fb_priv_cpu->bytes += skb->len;
	u64_stats_update_end(&fb_priv_cpu->syncp);

	if (drop) {
		kfree_skb(skb);
		return PPE_DROPPED;
	}
	return PPE_SUCCESS;
}

static int fb_counter_event(struct notifier_block *self, unsigned long cmd,
			    void *args)
{
	int ret = NOTIFY_OK;
	unsigned int cpu;
	struct fblock *fb;
	struct fb_counter_priv __percpu *fb_priv;

	rcu_read_lock();
	fb = rcu_dereference_raw(container_of(self, struct fblock_notifier, nb)->self);
	fb_priv = (struct fb_counter_priv __percpu *) rcu_dereference_raw(fb->private_data);
	rcu_read_unlock();

#ifdef __DEBUG
	printk("Got event %lu on %p!\n", cmd, fb);
#endif

	switch (cmd) {
	case FBLOCK_BIND_IDP: {
		int bound = 0;
		struct fblock_bind_msg *msg = args;
		get_online_cpus();
		for_each_online_cpu(cpu) {
			struct fb_counter_priv *fb_priv_cpu;
			fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
			if (fb_priv_cpu->port[msg->dir] == IDP_UNKNOWN) {
				write_seqlock(&fb_priv_cpu->lock);
				fb_priv_cpu->port[msg->dir] = msg->idp;
				write_sequnlock(&fb_priv_cpu->lock);
				bound = 1;
			} else {
				ret = NOTIFY_BAD;
				break;
			}
		}
		put_online_cpus();
		if (bound)
			printk(KERN_INFO "[%s::%s] port %s bound to IDP%u\n",
			       fb->name, fb->factory->type,
			       path_names[msg->dir], msg->idp);
		} break;
	case FBLOCK_UNBIND_IDP: {
		int unbound = 0;
		struct fblock_bind_msg *msg = args;
		get_online_cpus();
		for_each_online_cpu(cpu) {
			struct fb_counter_priv *fb_priv_cpu;
			fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
			if (fb_priv_cpu->port[msg->dir] == msg->idp) {
				write_seqlock(&fb_priv_cpu->lock);
				fb_priv_cpu->port[msg->dir] = IDP_UNKNOWN;
				write_sequnlock(&fb_priv_cpu->lock);
				unbound = 1;
			} else {
				ret = NOTIFY_BAD;
				break;
			}
		}
		put_online_cpus();
		if (unbound)
			printk(KERN_INFO "[%s::%s] port %s unbound\n",
			       fb->name, fb->factory->type,
			       path_names[msg->dir]);
		} break;
	case FBLOCK_SET_OPT: {
		struct fblock_opt_msg *msg = args;
		printk("Set option %s to %s!\n", msg->key, msg->val);
		} break;
	default:
		break;
	}

	return ret;
}

static int fb_counter_proc_show(struct seq_file *m, void *v)
{
	u64 pkts_sum = 0, bytes_sum = 0;
	unsigned int cpu;
	char sline[256];
	struct fblock *fb = (struct fblock *) m->private;
	struct fb_counter_priv __percpu *fb_priv;

	rcu_read_lock();
	fb_priv = (struct fb_counter_priv __percpu *) rcu_dereference_raw(fb->private_data);
	rcu_read_unlock();

	get_online_cpus();
	for_each_online_cpu(cpu) {
		unsigned int start;
		struct fb_counter_priv *fb_priv_cpu;
		fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
		do {
			start = u64_stats_fetch_begin(&fb_priv_cpu->syncp);
			pkts_sum += fb_priv_cpu->packets;
			bytes_sum += fb_priv_cpu->bytes;
		} while (u64_stats_fetch_retry(&fb_priv_cpu->syncp, start));
	}
	put_online_cpus();

	memset(sline, 0, sizeof(sline));
	snprintf(sline, sizeof(sline), "%llu %llu\n", pkts_sum, bytes_sum);
	seq_puts(m, sline);

	return 0;
}

static int fb_counter_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, fb_counter_proc_show, PDE(inode)->data);
}

static const struct file_operations fb_counter_proc_fops = {
	.owner = THIS_MODULE,
	.open = fb_counter_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static struct fblock *fb_counter_ctor(char *name)
{
	int ret = 0;
	unsigned int cpu;
	struct fblock *fb;
	struct fb_counter_priv __percpu *fb_priv;
	struct proc_dir_entry *fb_proc;

	fb = alloc_fblock(GFP_ATOMIC);
	if (!fb)
		return NULL;

	fb_priv = alloc_percpu(struct fb_counter_priv);
	if (!fb_priv)
		goto err;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct fb_counter_priv *fb_priv_cpu;
		fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
		seqlock_init(&fb_priv_cpu->lock);
		fb_priv_cpu->port[0] = IDP_UNKNOWN;
		fb_priv_cpu->port[1] = IDP_UNKNOWN;
		fb_priv_cpu->packets = 0;
		fb_priv_cpu->bytes = 0;
	}
	put_online_cpus();

	ret = init_fblock(fb, name, fb_priv);
	if (ret)
		goto err2;
	fb->netfb_rx = fb_counter_netrx;
	fb->event_rx = fb_counter_event;

	fb_proc = proc_create_data(fb->name, 0444, fblock_proc_dir,
				   &fb_counter_proc_fops,
				   (void *)(long) fb);
	if (!fb_proc)
		goto err3;

	ret = register_fblock_namespace(fb);
	if (ret)
		goto err4;

	__module_get(THIS_MODULE);
	return fb;
err4:
	remove_proc_entry(fb->name, fblock_proc_dir);
err3:
	cleanup_fblock_ctor(fb);
err2:
	free_percpu(fb_priv);
err:
	kfree_fblock(fb);
	return NULL;
}

static void fb_counter_dtor(struct fblock *fb)
{
	free_percpu(rcu_dereference_raw(fb->private_data));
	remove_proc_entry(fb->name, fblock_proc_dir);
	module_put(THIS_MODULE);
}

static struct fblock_factory fb_counter_factory = {
	.type = "counter",
	.mode = MODE_DUAL,
	.ctor = fb_counter_ctor,
	.dtor = fb_counter_dtor,
	.owner = THIS_MODULE,
};

static int __init init_fb_counter_module(void)
{
	return register_fblock_type(&fb_counter_factory);
}

static void __exit cleanup_fb_counter_module(void)
{
	unregister_fblock_type(&fb_counter_factory);
}

module_init(init_fb_counter_module);
module_exit(cleanup_fb_counter_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA packet counter module");
