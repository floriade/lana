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
#include "xt_critbit.h"

int fb_test_netrx(struct sk_buff *skb)
{
	printk("Got skb!\n");
	return 0;
}

static struct fblock_ops fb_test_ops = {
	.netrx = fb_test_netrx,
};

static struct fblock *fb_test_block;

static int __init init_fb_test_module(void)
{
	fb_test_block = alloc_fblock(GFP_ATOMIC);
	fb_test_block->ops = &fb_test_ops;
	strlcpy(fb_test_block->name, "fb1", sizeof(fb_test_block->name));

	register_fblock_namespace(fb_test_block);
	printk(KERN_INFO "[lana] Dummy/test loaded!\n");
	return 0;
}

static void __exit cleanup_fb_test_module(void)
{
	unregister_fblock_namespace(fb_test_block);
	printk(KERN_INFO "[lana] Dummy/test removed!\n");
}

module_init(init_fb_test_module);
module_exit(cleanup_fb_test_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA dummy/test module");
