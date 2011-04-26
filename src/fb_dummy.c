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

#include "xt_fblock.h"
#include "xt_builder.h"
#include "xt_idp.h"
#include "xt_skb.h"
#include "xt_engine.h"

struct fb_test_priv {
	idp_t port[NUM_TYPES];
	spinlock_t lock;
};

static struct fblock_ops fb_test_ops;

static int fb_test_netrx(struct fblock *fb, struct sk_buff *skb,
			 enum path_type *dir)
{
	unsigned long flags;
	struct fb_test_priv *fb_priv = fb->private_data;

	printk("Got skb on %p!\n", fb);

	spin_lock_irqsave(&fb_priv->lock, flags);
	write_next_idp_to_skb(skb, fb->idp, fb_priv->port[*dir]);
	spin_unlock_irqrestore(&fb_priv->lock, flags);

	return PPE_SUCCESS;
}

static int fb_test_event(struct notifier_block *self, unsigned long cmd,
			 void *args)
{
	unsigned long flags;
	struct fblock_bind_msg *msg;
	struct fblock *fb = container_of(self, struct fblock_notifier, nb)->self;
	struct fb_test_priv *fb_priv = fb->private_data;

	printk("Got event %lu on %p!\n", cmd, fb);

	switch (cmd) {
	case FBLOCK_BIND_IDP:
		msg = args;
		spin_lock_irqsave(&fb_priv->lock, flags);
		if (fb_priv->port[msg->dir] == IDP_UNKNOWN)
			fb_priv->port[msg->dir] = msg->idp;
		spin_unlock_irqrestore(&fb_priv->lock, flags);
		printk("[lana] Bound fb %p to %u!\n", fb, msg->idp);
	case FBLOCK_UNBIND_IDP:
		msg = args;
		spin_lock_irqsave(&fb_priv->lock, flags);
		if (fb_priv->port[msg->dir] == msg->idp)
			fb_priv->port[msg->dir] = IDP_UNKNOWN;
		spin_unlock_irqrestore(&fb_priv->lock, flags);
		printk("[lana] Unbound fb %p to %u!\n", fb, msg->idp);
	case FBLOCK_XCHG_IDP:
		msg = args;
		spin_lock_irqsave(&fb_priv->lock, flags);
		fb_priv->port[msg->dir] = msg->idp;
		spin_unlock_irqrestore(&fb_priv->lock, flags);
		printk("[lana] Xchg fb %p to %u!\n", fb, msg->idp);
	default:
		break;
	}
	return 0;
}

static struct fblock *fb_test_ctor(char *name)
{
	int i, ret = 0;
	struct fblock *fb;
	struct fb_test_priv *fb_priv;

	fb = alloc_fblock(GFP_ATOMIC);
	if (!fb)
		return NULL;
	fb_priv = kmalloc(sizeof(*fb_priv), GFP_KERNEL);
	if (!fb_priv)
		goto err;
	for (i = 0; i < NUM_TYPES; ++i)
		fb_priv->port[i] = IDP_UNKNOWN;
	spin_lock_init(&fb_priv->lock);
	ret = init_fblock(fb, name, fb_priv, &fb_test_ops);
	if (ret)
		goto err2;
	register_fblock_namespace(fb);

	return fb;
err2:
	kfree(fb_priv);
err:
	kfree_fblock(fb);
	return NULL;
}

static void fb_test_dtor(struct fblock *fb)
{
	kfree(fb->private_data);
}

static struct fblock_ops fb_test_ops = {
	.netfb_rx = fb_test_netrx,
	.event_rx = fb_test_event,
};

static struct fblock_factory fb_test_factory = {
	.type = "test",
	.ctor = fb_test_ctor,
	.dtor = fb_test_dtor,
	.owner = THIS_MODULE,
};

static int __init init_fb_test_module(void)
{
	return register_fblock_type(&fb_test_factory);
}

static void __exit cleanup_fb_test_module(void)
{
	unregister_fblock_type(&fb_test_factory);
}

module_init(init_fb_test_module);
module_exit(cleanup_fb_test_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA dummy/test module");
