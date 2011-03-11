/*
 * Lightweight Autonomic Network Architecture
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/notifier.h>
#include <linux/netdevice.h>

struct fb_eth_dev {
	struct net_device *dev;
	struct net_device *real_dev;
};

/*
 * The virtual device ingress path to the upper ANA layer.
 */
static struct sk_buff *fb_eth_vlink_handle_frame(struct sk_buff *skb)
{
	return NULL;
}

static int fb_eth_vlink_device_event(struct notifier_block *this,
				      unsigned long event, void *ptr)
{
	return NOTIFY_DONE;
}

static struct notifier_block fb_eth_vlink_notifier __read_mostly = {
	.notifier_call	= fb_eth_vlink_device_event,
};

static int __init init_fb_eth_vlink_module(void)
{
	register_netdevice_notifier(&fb_eth_vlink_notifier);
	printk(KERN_INFO "eth vlink init done\n");
	return 0;
}

static void __exit cleanup_fb_eth_vlink_module(void)
{
	unregister_netdevice_notifier(&fb_eth_vlink_notifier);
	printk(KERN_INFO "eth vlink cleanup done\n");
}

module_init(init_fb_eth_vlink_module);
module_exit(cleanup_fb_eth_vlink_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("ANA Ethernet virtual link layer driver");

