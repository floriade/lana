/*
 * Lightweight Autonomic Network Architecture
 *
 * Dummy test module.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include "xt_fblock.h"
#include "xt_builder.h"

static struct fblock_ops fb_test_ops;

static int fb_test_netrx(struct fblock *fb, struct sk_buff *skb)
{
	printk("Got skb!\n");
	return 0;
}

static int fb_test_event(struct notifier_block *self, unsigned long cmd,
			 void *args)
{
	printk("Got event!\n");
	return 0;
}

static struct fblock *fb_test_ctor(char *name, unsigned long flags)
{
	int ret = 0;
	struct fblock *fb;

	fb = alloc_fblock(GFP_ATOMIC);
	if (!fb)
		return NULL;
	ret = init_fblock(fb, name, NULL, &fb_test_ops);
	if (ret)
		goto err;
	register_fblock_namespace(fb);

	return fb;
err:
	kfree_fblock(fb);
	return NULL;
}

static void fb_test_dtor(struct fblock *fb)
{
}

static struct fblock_ops fb_test_ops = {
	.netfb_rx = fb_test_netrx,
	.event_rx = fb_test_event,
};

static struct fblock_factory_ops fb_test_fops = {
	.type = "test",
	.ctor = fb_test_ctor,
	.dtor = fb_test_dtor,
};

static int __init init_fb_test_module(void)
{
	return register_fblock_type(&fb_test_fops);
}

static void __exit cleanup_fb_test_module(void)
{
	unregister_fblock_type(&fb_test_fops);
}

module_init(init_fb_test_module);
module_exit(cleanup_fb_test_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA dummy/test module");
