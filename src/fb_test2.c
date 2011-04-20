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

int fb_test2_netrx(struct sk_buff *skb)
{
	printk("Got skb 2!\n");
	return 0;
}

static struct fblock_ops fb_test2_ops = {
	.netrx = fb_test2_netrx,
};

static struct fblock *fb_test2_block;

static int __init init_fb_test2_module(void)
{
	int ret;

	fb_test2_block = alloc_fblock(GFP_ATOMIC);
	fb_test2_block->ops = &fb_test2_ops;
	strlcpy(fb_test2_block->name, "fb2", sizeof(fb_test2_block->name));

	ret = register_fblock_namespace(fb_test2_block);
	if (ret)
		return ret;

	printk(KERN_INFO "idp1: %u, idp2: %u\n",
	       get_fblock_namespace_mapping("fb1"),
	       get_fblock_namespace_mapping("fb2"));

	printk(KERN_INFO "[lana] Dummy/test 2 loaded!\n");
	return 0;
}

static void __exit cleanup_fb_test2_module(void)
{
	unregister_fblock_namespace(fb_test2_block);

	printk(KERN_INFO "[lana] Dummy/test 2 removed!\n");
}

module_init(init_fb_test2_module);
module_exit(cleanup_fb_test2_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA dummy/test 2 module");
