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

#include "xt_fblock.h"
#include "xt_builder.h"
#include "xt_idp.h"
#include "xt_skb.h"

struct fb_test_priv {
	idp_t ingress;
	idp_t egress;
};

static struct fblock_ops fb_test_ops;

static int fb_test_netrx(struct fblock *fb, struct sk_buff *skb,
			 enum path_type *dir)
{
	struct fb_test_priv *fb_priv = fb->private_data;

	printk("Got skb on %p!\n", fb);
	write_next_idp_to_skb(skb, fb->idp, *dir == TYPE_INGRESS ?
			      fb_priv->ingress : fb_priv->egress);
	return 0;
}

static int fb_test_event(struct notifier_block *self, unsigned long cmd,
			 void *args)
{
	struct fblock *fb = container_of(self, struct fblock_notifier, nb)->self;
	printk("Got event on %p!\n", fb);
	return 0;
}

static struct fblock *fb_test_ctor(char *name)
{
	int ret = 0;
	struct fblock *fb;
	struct fb_test_priv *fb_priv;

	fb = alloc_fblock(GFP_ATOMIC);
	if (!fb)
		return NULL;
	fb_priv = kmalloc(sizeof(*fb_priv), GFP_KERNEL);
	if (!fb_priv)
		goto err;
	fb_priv->ingress = IDP_UNKNOWN;
	fb_priv->egress = IDP_UNKNOWN;
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
