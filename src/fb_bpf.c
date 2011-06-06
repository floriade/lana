/*
 * Lightweight Autonomic Network Architecture
 *
 * LANA Berkeley Packet Filter (BPF) module using the BPF JIT compiler.
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
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/percpu.h>
#include <linux/prefetch.h>
#include <linux/filter.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#include "xt_fblock.h"
#include "xt_builder.h"
#include "xt_idp.h"
#include "xt_skb.h"
#include "xt_engine.h"
#include "xt_builder.h"

struct fb_bpf_priv {
	idp_t port[2];
	struct sk_filter *filter;
	spinlock_t flock;
};

static int fb_bpf_init_filter(struct fb_bpf_priv __percpu *fb_priv_cpu,
			      struct sock_fprog *fprog, unsigned int cpu)
{
	int err;
	struct sk_filter *sf, *sfold;
	unsigned int fsize;
	unsigned long flags;

	if (fprog->filter == NULL)
		return -EINVAL;

	fsize = sizeof(struct sock_filter) * fprog->len;

	sf = kmalloc_node(fsize + sizeof(*sf), GFP_KERNEL, cpu_to_node(cpu));
	if (!sf)
		return -ENOMEM;

	memcpy(sf->insns, fprog->filter, fsize);
	atomic_set(&sf->refcnt, 1);
	sf->len = fprog->len;
	sf->bpf_func = sk_run_filter;

	err = sk_chk_filter(sf->insns, sf->len);
	if (err) {
		kfree(sf);
		return err;
	}

	bpf_jit_compile(sf);

	spin_lock_irqsave(&fb_priv_cpu->flock, flags);
	sfold = fb_priv_cpu->filter;
	fb_priv_cpu->filter = sf;
	spin_unlock_irqrestore(&fb_priv_cpu->flock, flags);

	if (sfold) {
		bpf_jit_free(sfold);
		kfree(sfold);
	}

	return 0;
}

static int fb_bpf_init_filter_cpus(struct fblock *fb, struct sock_fprog *fprog)
{
	int err = 0;
	unsigned int cpu;
	struct fb_bpf_priv __percpu *fb_priv;

	if (!fprog || !fb)
		return -EINVAL;

	rcu_read_lock();
	fb_priv = (struct fb_bpf_priv __percpu *) rcu_dereference_raw(fb->private_data);
	rcu_read_unlock();

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct fb_bpf_priv *fb_priv_cpu;
		fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
		err = fb_bpf_init_filter(fb_priv_cpu, fprog, cpu);
		if (err != 0) {
			printk(KERN_ERR "[%s::%s] fb_bpf_init_filter error: %d\n",
			       fb->name, fb->factory->type, err);
			break;
		}
	}
	put_online_cpus();

	return err;
}

static void fb_bpf_cleanup_filter(struct fb_bpf_priv __percpu *fb_priv_cpu)
{
	unsigned long flags;
	struct sk_filter *sfold;

	spin_lock_irqsave(&fb_priv_cpu->flock, flags);
	sfold = fb_priv_cpu->filter;
	fb_priv_cpu->filter = NULL;
	spin_unlock_irqrestore(&fb_priv_cpu->flock, flags);

	if (sfold) {
		bpf_jit_free(sfold);
		kfree(sfold);
	}
}

static void fb_bpf_cleanup_filter_cpus(struct fblock *fb)
{
	unsigned int cpu;
	struct fb_bpf_priv __percpu *fb_priv;

	if (!fb)
		return;

	rcu_read_lock();
	fb_priv = (struct fb_bpf_priv __percpu *) rcu_dereference_raw(fb->private_data);
	rcu_read_unlock();

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct fb_bpf_priv *fb_priv_cpu;
		fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
		fb_bpf_cleanup_filter(fb_priv_cpu);
	}
	put_online_cpus();
}

static int fb_bpf_netrx(const struct fblock * const fb,
			struct sk_buff * const skb,
			enum path_type * const dir)
{
	int drop = 0;
	unsigned int pkt_len;
	unsigned long flags;
	struct fb_bpf_priv __percpu *fb_priv_cpu;

	fb_priv_cpu = this_cpu_ptr(rcu_dereference_raw(fb->private_data));

	spin_lock_irqsave(&fb_priv_cpu->flock, flags);
	if (fb_priv_cpu->filter) {
		pkt_len = SK_RUN_FILTER(fb_priv_cpu->filter, skb);
		/* No snap, either drop or pass */
		if (pkt_len < skb->len) {
			spin_unlock_irqrestore(&fb_priv_cpu->flock, flags);
			kfree_skb(skb);
			return PPE_DROPPED;
		}
	}
	write_next_idp_to_skb(skb, fb->idp, fb_priv_cpu->port[*dir]);
	if (fb_priv_cpu->port[*dir] == IDP_UNKNOWN)
		drop = 1;
	spin_unlock_irqrestore(&fb_priv_cpu->flock, flags);
	if (drop) {
		kfree_skb(skb);
		return PPE_DROPPED;
	}

	return PPE_SUCCESS;
}

static int fb_bpf_event(struct notifier_block *self, unsigned long cmd,
			void *args)
{
	int ret = NOTIFY_OK;
	unsigned int cpu;
	struct fblock *fb;
	struct fb_bpf_priv __percpu *fb_priv;

	rcu_read_lock();
	fb = rcu_dereference_raw(container_of(self, struct fblock_notifier, nb)->self);
	fb_priv = (struct fb_bpf_priv __percpu *) rcu_dereference_raw(fb->private_data);
	rcu_read_unlock();

	switch (cmd) {
	case FBLOCK_BIND_IDP: {
		int bound = 0;
		struct fblock_bind_msg *msg = args;
		get_online_cpus();
		for_each_online_cpu(cpu) {
			struct fb_bpf_priv *fb_priv_cpu;
			fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
			spin_lock(&fb_priv_cpu->flock);
			if (fb_priv_cpu->port[msg->dir] == IDP_UNKNOWN) {
				fb_priv_cpu->port[msg->dir] = msg->idp;
				bound = 1;
			} else {
				ret = NOTIFY_BAD;
				spin_unlock(&fb_priv_cpu->flock);
				break;
			}
			spin_unlock(&fb_priv_cpu->flock);
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
			struct fb_bpf_priv *fb_priv_cpu;
			fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
			spin_lock(&fb_priv_cpu->flock);
			if (fb_priv_cpu->port[msg->dir] == msg->idp) {
				fb_priv_cpu->port[msg->dir] = IDP_UNKNOWN;
				unbound = 1;
			} else {
				ret = NOTIFY_BAD;
				spin_unlock(&fb_priv_cpu->flock);
				break;
			}
			spin_unlock(&fb_priv_cpu->flock);
		}
		put_online_cpus();
		if (unbound)
			printk(KERN_INFO "[%s::%s] port %s unbound\n",
			       fb->name, fb->factory->type,
			       path_names[msg->dir]);
		} break;
	default:
		break;
	}

	return ret;
}

static int fb_bpf_proc_show_filter(struct seq_file *seq, void *v)
{
	unsigned long flags;
	struct fblock *fb = v;
	struct fb_bpf_priv __percpu *fb_priv;
	struct fb_bpf_priv *fb_priv_cpu;
	struct sk_filter *sf;

	rcu_read_lock();
	fb_priv = this_cpu_ptr(rcu_dereference_raw(fb->private_data));
	rcu_read_unlock();

	get_online_cpus();
	fb_priv_cpu = per_cpu_ptr(fb_priv, smp_processor_id());
	spin_lock_irqsave(&fb_priv_cpu->flock, flags);

	sf = fb_priv_cpu->filter;
	if (sf) {
		unsigned int i;
		if (sf->bpf_func == sk_run_filter)
			seq_puts(seq, "bpf jit: 0\n");
		else
			seq_puts(seq, "bpf jit: 1\n");
		seq_puts(seq, "code:\n");
		for (i = 0; i < sf->len; ++i) {
			char sline[32];
			memset(sline, 0, sizeof(sline));
			snprintf(sline, sizeof(sline),
				 "0x%x %d %d 0x%x\n",
				 sf->insns[i].code,
				 sf->insns[i].jt,
				 sf->insns[i].jf,
				 sf->insns[i].k);
			sline[sizeof(sline) - 1] = 0;
			seq_puts(seq, sline);
		}
	}

	spin_unlock_irqrestore(&fb_priv_cpu->flock, flags);
	put_online_cpus();

	return 0;
}

static int fb_bpf_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, fb_bpf_proc_show_filter, PDE(inode)->data);
}

static ssize_t fb_bpf_proc_write(struct file *file, const char __user * user_buffer,
				 size_t count, loff_t * offset)
{
	/* TODO: Parse struct sock_fprog and init filter */
	return 0;
}

static const struct file_operations fb_bpf_proc_fops = {
	.owner   = THIS_MODULE,
	.open    = fb_bpf_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.write   = fb_bpf_proc_write,
	.release = single_release,
};

static struct fblock *fb_bpf_ctor(char *name)
{
	int ret = 0;
	unsigned int cpu;
	struct fblock *fb;
	struct fb_bpf_priv __percpu *fb_priv;
	struct proc_dir_entry *fb_proc;

	fb = alloc_fblock(GFP_ATOMIC);
	if (!fb)
		return NULL;

	fb_priv = alloc_percpu(struct fb_bpf_priv);
	if (!fb_priv)
		goto err;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct fb_bpf_priv *fb_priv_cpu;
		fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
		spin_lock_init(&fb_priv_cpu->flock);
		fb_priv_cpu->port[0] = IDP_UNKNOWN;
		fb_priv_cpu->port[1] = IDP_UNKNOWN;
		fb_priv_cpu->filter = NULL;
	}
	put_online_cpus();

	ret = init_fblock(fb, name, fb_priv);
	if (ret)
		goto err2;

	fb->netfb_rx = fb_bpf_netrx;
	fb->event_rx = fb_bpf_event;

	fb_proc = proc_create_data(fb->name, 0444, fblock_proc_dir,
				   &fb_bpf_proc_fops, fb);
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

static void fb_bpf_dtor(struct fblock *fb)
{
	free_percpu(rcu_dereference_raw(fb->private_data));
	remove_proc_entry(fb->name, fblock_proc_dir);
	module_put(THIS_MODULE);
}

static struct fblock_factory fb_bpf_factory = {
	.type = "bpf",
	.mode = MODE_DUAL,
	.ctor = fb_bpf_ctor,
	.dtor = fb_bpf_dtor,
	.owner = THIS_MODULE,
};

static int __init init_fb_bpf_module(void)
{
	return register_fblock_type(&fb_bpf_factory);
}

static void __exit cleanup_fb_bpf_module(void)
{
	unregister_fblock_type(&fb_bpf_factory);
}

module_init(init_fb_bpf_module);
module_exit(cleanup_fb_bpf_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA Berkeley Packet Filter module");
