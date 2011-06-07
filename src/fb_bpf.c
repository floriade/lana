/*
 * Lightweight Autonomic Network Architecture
 *
 * LANA Berkeley Packet Filter (BPF) module.
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

struct sock_fprog_kern {
	unsigned short len;
	struct sock_filter *filter;
};

/*
 * Note:
 *  To use the BPF JIT compiler, you need to export symbols from
 *  /arch/x86/net/ so that they can be used from a module. Then,
 *  recompile your kernel with CONFIG_BPF_JIT=y and change symbols
 *  within this file from fb_bpf_jit_<x> to bpf_jit_<x> and the macro
 *  FB_SK_RUN_FILTER to SK_RUN_FILTER.
 */

static inline void fb_bpf_jit_compile(struct sk_filter *fp)
{
}

static inline void fb_bpf_jit_free(struct sk_filter *fp)
{
}

#define FB_SK_RUN_FILTER(FILTER, SKB) sk_run_filter(SKB, FILTER->insns)

static int fb_bpf_init_filter(struct fb_bpf_priv __percpu *fb_priv_cpu,
			      struct sock_fprog_kern *fprog, unsigned int cpu)
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

	fb_bpf_jit_compile(sf);

	spin_lock_irqsave(&fb_priv_cpu->flock, flags);
	sfold = fb_priv_cpu->filter;
	fb_priv_cpu->filter = sf;
	spin_unlock_irqrestore(&fb_priv_cpu->flock, flags);

	if (sfold) {
		fb_bpf_jit_free(sfold);
		kfree(sfold);
	}

	return 0;
}

static int fb_bpf_init_filter_cpus(struct fblock *fb,
				   struct sock_fprog_kern *fprog)
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
		fb_bpf_jit_free(sfold);
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
		pkt_len = FB_SK_RUN_FILTER(fb_priv_cpu->filter, skb);
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

static int fb_bpf_proc_show_filter(struct seq_file *m, void *v)
{
	unsigned long flags;
	struct fblock *fb = (struct fblock *) m->private;
	struct fb_bpf_priv *fb_priv_cpu;
	struct sk_filter *sf;

	get_online_cpus();
	rcu_read_lock();
	fb_priv_cpu = this_cpu_ptr(rcu_dereference_raw(fb->private_data));
	rcu_read_unlock();

	spin_lock_irqsave(&fb_priv_cpu->flock, flags);
	sf = fb_priv_cpu->filter;
	if (sf) {
		unsigned int i;
		if (sf->bpf_func == sk_run_filter)
			seq_puts(m, "bpf jit: 0\n");
		else
			seq_puts(m, "bpf jit: 1\n");
		seq_puts(m, "code:\n");
		for (i = 0; i < sf->len; ++i) {
			char sline[32];
			memset(sline, 0, sizeof(sline));
			snprintf(sline, sizeof(sline),
				 "0x%x, %u, %u, 0x%x\n",
				 sf->insns[i].code,
				 sf->insns[i].jt,
				 sf->insns[i].jf,
				 sf->insns[i].k);
			sline[sizeof(sline) - 1] = 0;
			seq_puts(m, sline);
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

#define MAX_BUFF_SIZ	16384
#define MAX_INSTR_SIZ	512

static ssize_t fb_bpf_proc_write(struct file *file, const char __user * ubuff,
				 size_t count, loff_t * offset)
{
	int i;
	ssize_t ret = 0;
	char *code, *ptr1, *ptr2;
	size_t len = MAX_BUFF_SIZ;
	struct sock_fprog_kern *fp;
	struct fblock *fb = PDE(file->f_path.dentry->d_inode)->data;

	if (count > MAX_BUFF_SIZ)
		return -EINVAL;
	if (count < MAX_BUFF_SIZ)
		len = count;

	code = kmalloc(len, GFP_KERNEL);
	if (!code)
		return -ENOMEM;
	fp = kmalloc(sizeof(*fp), GFP_KERNEL);
	if (!fp)
		goto err;
	fp->filter = kmalloc(MAX_INSTR_SIZ * sizeof(struct sock_filter), GFP_KERNEL);
	if (!fp->filter)
		goto err2;
	memset(code, 0, len);
	if (copy_from_user(code, ubuff, len)) {
		ret = -EFAULT;
		goto err3;
	}

	ptr1 = code;
	ptr2 = NULL;
	fp->len = 0;

	while (fp->len < MAX_INSTR_SIZ && (char *) (code + len) > ptr1) {
		while (ptr1 && *ptr1 == ' ')
			ptr1++;
		fp->filter[fp->len].code = (__u16) simple_strtoul(ptr1, &ptr2, 16);
		while (ptr2 && (*ptr2 == ' ' || *ptr2 == ','))
			ptr2++;
		fp->filter[fp->len].jt = (__u8) simple_strtoul(ptr2, &ptr1, 10);
		while (ptr1 && (*ptr1 == ' ' || *ptr1 == ','))
			ptr1++;
		fp->filter[fp->len].jf = (__u8) simple_strtoul(ptr1, &ptr2, 10);
		while (ptr2 && (*ptr2 == ' ' || *ptr2 == ','))
			ptr2++;
		fp->filter[fp->len].k = (__u32) simple_strtoul(ptr2, &ptr1, 16);
		while (ptr1 && (*ptr1 == ' ' || *ptr1 == ',' || *ptr1 == '\n'))
			ptr1++;
		fp->len++;
	}

	if (fp->len == MAX_INSTR_SIZ) {
		printk(KERN_ERR "[%s::%s] Maximun instruction size exeeded!\n",
		       fb->name, fb->factory->type);
		goto err3;
	}

	printk(KERN_ERR "[%s::%s] Parsed code:\n", fb->name, fb->factory->type);
	for (i = 0; i < fp->len; ++i) {
		printk(KERN_INFO "[%s::%s] %d: c:0x%x jt:%u jf:%u k:0x%x\n",
		       fb->name, fb->factory->type, i,
		       fp->filter[i].code, fp->filter[i].jt, fp->filter[i].jf,
		       fp->filter[i].k);
	}

	fb_bpf_cleanup_filter_cpus(fb);
	ret = fb_bpf_init_filter_cpus(fb, fp);
	if (!ret)
		printk(KERN_INFO "[%s::%s] Filter injected!\n",
		       fb->name, fb->factory->type);
	else {
		printk(KERN_ERR "[%s::%s] Filter injection error: %ld!\n",
		       fb->name, fb->factory->type, ret);
		fb_bpf_cleanup_filter_cpus(fb);
	}

	kfree(code);
	kfree(fp->filter);
	kfree(fp);

	return count;
err3:
	kfree(fp->filter);
err2:
	kfree(fp);
err:
	kfree(code);
	return !ret ? -ENOMEM : ret;

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
				   &fb_bpf_proc_fops, (void *)(long) fb);
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
	fb_bpf_cleanup_filter_cpus(fb);
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
