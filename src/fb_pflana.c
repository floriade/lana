/*
 * Lightweight Autonomic Network Architecture
 *
 * PF_LANA userspace module.
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

#include "xt_fblock.h"
#include "xt_builder.h"
#include "xt_idp.h"
#include "xt_skb.h"
#include "xt_engine.h"
#include "xt_builder.h"

struct fb_pflana_priv {
	idp_t port[NUM_TYPES];
	seqlock_t lock;
};

static int fb_pflana_netrx(const struct fblock * const fb,
			   struct sk_buff * const skb,
			   enum path_type * const dir)
{
	return PPE_SUCCESS;
}

static int fb_pflana_event(struct notifier_block *self, unsigned long cmd,
			   void *args)
{
	return 0;
}

static void cleanup_fb_pflana(void)
{
}

static int init_fb_pflana(void)
{
	return 0;
}

static struct fblock *fb_pflana_ctor(char *name)
{
	int i, ret = 0;
	unsigned int cpu;
	struct fblock *fb;
	struct fb_pflana_priv __percpu *fb_priv;

		return NULL;
	fb = alloc_fblock(GFP_ATOMIC);
	if (!fb)
		return NULL;

	fb_priv = alloc_percpu(struct fb_pflana_priv);
	if (!fb_priv)
		goto err;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct fb_pflana_priv *fb_priv_cpu;
		fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
		seqlock_init(&fb_priv_cpu->lock);
		for (i = 0; i < NUM_TYPES; ++i)
			fb_priv_cpu->port[i] = IDP_UNKNOWN;
	}
	put_online_cpus();

	ret = init_fblock(fb, name, fb_priv);
	if (ret)
		goto err2;
	fb->netfb_rx = fb_pflana_netrx;
	fb->event_rx = fb_pflana_event;
	ret = register_fblock_namespace(fb);
	if (ret)
		goto err3;
	__module_get(THIS_MODULE);
	return fb;
err3:
	cleanup_fblock_ctor(fb);
err2:
	free_percpu(fb_priv);
err:
	kfree_fblock(fb);
	fb = NULL;
	return NULL;
}

static void fb_pflana_dtor(struct fblock *fb)
{
	free_percpu(rcu_dereference_raw(fb->private_data));
	module_put(THIS_MODULE);
}

static struct fblock_factory fb_pflana_factory = {
	.type = "pflana",
	.mode = MODE_SINK,
	.ctor = fb_pflana_ctor,
	.dtor = fb_pflana_dtor,
	.owner = THIS_MODULE,
};

static int __init init_fb_pflana_module(void)
{
	int ret;
	ret = init_fb_pflana();
	if (ret)
		return ret;
	ret = register_fblock_type(&fb_pflana_factory);
	if (ret)
		cleanup_fb_pflana();
	return ret;
}

static void __exit cleanup_fb_pflana_module(void)
{
	cleanup_fb_pflana();
	unregister_fblock_type(&fb_pflana_factory);
}

module_init(init_fb_pflana_module);
module_exit(cleanup_fb_pflana_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA PF_LANA module");
