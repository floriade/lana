/*
 * Lightweight Autonomic Network Architecture
 *
 * Dummy test module.
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

#include "xt_fblock.h"
#include "xt_builder.h"
#include "xt_idp.h"
#include "xt_skb.h"
#include "xt_engine.h"

struct fb_dummy_priv {
	idp_t port[NUM_TYPES];
	spinlock_t lock;
};

static struct fblock_ops fb_dummy_ops;

static int fb_dummy_netrx(struct fblock *fb, struct sk_buff *skb,
			  enum path_type *dir)
{
	unsigned long flags;
	struct fb_dummy_priv *fb_priv;

	rcu_read_lock();
	fb_priv = rcu_dereference_raw(fb->private_data);

	printk("Got skb on %p on ppe%d!\n", fb, smp_processor_id());

	spin_lock_irqsave(&fb_priv->lock, flags);
	write_next_idp_to_skb(skb, fb->idp, fb_priv->port[*dir]);
	spin_unlock_irqrestore(&fb_priv->lock, flags);

	rcu_read_unlock();
	return PPE_SUCCESS;
}

static int fb_dummy_event(struct notifier_block *self, unsigned long cmd,
			  void *args)
{
	int ret = NOTIFY_OK;
	unsigned long flags;
	struct fblock *fb;
	struct fb_dummy_priv *fb_priv;

	rcu_read_lock();
	fb = rcu_dereference_raw(container_of(self, struct fblock_notifier, nb)->self);
	fb_priv = rcu_dereference_raw(fb->private_data);

	printk("Got event %lu on %p!\n", cmd, fb);

	switch (cmd) {
	case FBLOCK_BIND_IDP: {
		struct fblock_bind_msg *msg = args;
		spin_lock_irqsave(&fb_priv->lock, flags);
		if (fb_priv->port[msg->dir] == IDP_UNKNOWN)
			fb_priv->port[msg->dir] = msg->idp;
		else
			ret = NOTIFY_BAD;
		spin_unlock_irqrestore(&fb_priv->lock, flags);
		} break;
	case FBLOCK_UNBIND_IDP: {
		struct fblock_bind_msg *msg = args;
		spin_lock_irqsave(&fb_priv->lock, flags);
		if (fb_priv->port[msg->dir] == msg->idp)
			fb_priv->port[msg->dir] = IDP_UNKNOWN;
		else
			ret = NOTIFY_BAD;
		spin_unlock_irqrestore(&fb_priv->lock, flags);
		} break;
	case FBLOCK_SET_OPT: {
		struct fblock_opt_msg *msg = args;
		printk("Set option %s to %s!\n", msg->key, msg->val);
		} break;
	default:
		break;
	}

	rcu_read_unlock();
	return ret;
}

static struct fblock *fb_dummy_ctor(char *name)
{
	int i, ret = 0;
	struct fblock *fb;
	struct fb_dummy_priv *fb_priv;

	fb = alloc_fblock(GFP_ATOMIC);
	if (!fb)
		return NULL;
	fb_priv = kmalloc(sizeof(*fb_priv), GFP_ATOMIC);
	if (!fb_priv)
		goto err;
	for (i = 0; i < NUM_TYPES; ++i)
		fb_priv->port[i] = IDP_UNKNOWN;
	spin_lock_init(&fb_priv->lock);
	ret = init_fblock(fb, name, fb_priv, &fb_dummy_ops);
	if (ret)
		goto err2;
	ret = register_fblock_namespace(fb);
	if (ret)
		goto err3;
	__module_get(THIS_MODULE);
	return fb;
err3:
	cleanup_fblock_ctor(fb);
err2:
	kfree(fb_priv);
err:
	kfree_fblock(fb);
	return NULL;
}

static void fb_dummy_dtor(struct fblock *fb)
{
	kfree(rcu_dereference_raw(fb->private_data));
	module_put(THIS_MODULE);
}

static struct fblock_ops fb_dummy_ops = {
	.netfb_rx = fb_dummy_netrx,
	.event_rx = fb_dummy_event,
};

static struct fblock_factory fb_dummy_factory = {
	.type = "dummy",
	.ctor = fb_dummy_ctor,
	.dtor = fb_dummy_dtor,
	.owner = THIS_MODULE,
};

static int __init init_fb_dummy_module(void)
{
	return register_fblock_type(&fb_dummy_factory);
}

static void __exit cleanup_fb_dummy_module(void)
{
	unregister_fblock_type(&fb_dummy_factory);
}

module_init(init_fb_dummy_module);
module_exit(cleanup_fb_dummy_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA dummy/test module");
