/*
 * Lightweight Autonomic Network Architecture
 *
 * Eth/PHY layer. Redirects all traffic into the LANA stack.
 * Singleton object.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/if.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/seqlock.h>

#include "xt_idp.h"
#include "xt_engine.h"
#include "xt_skb.h"
#include "xt_fblock.h"
#include "xt_builder.h"
#include "xt_vlink.h"

#define IFF_VLINK_MAS	0x20000
#define IFF_VLINK_DEV	0x40000
#define IFF_IS_BRIDGED  0x60000

struct fb_eth_priv {
	idp_t port[2];
	seqlock_t lock;
	struct net_device *dev; /* Must never change after setup! */
};

static LIST_HEAD(fb_eth_devs);
static DEFINE_SPINLOCK(fb_eth_devs_lock);

struct fb_eth_dev_node {
	struct list_head list;
	struct fblock *fb;
	struct net_device *dev;
};

static inline int fb_eth_dev_is_bridged(struct net_device *dev)
{
	return (dev->priv_flags & IFF_IS_BRIDGED) == IFF_IS_BRIDGED;
}

static inline int fb_ethvlink_real_dev_is_hooked(struct net_device *dev)
{
	return (dev->priv_flags & IFF_VLINK_MAS) == IFF_VLINK_MAS;
}

static inline void fb_eth_make_dev_bridged(struct net_device *dev)
{
	dev->priv_flags |= IFF_IS_BRIDGED;
}

static inline void fb_eth_make_dev_unbridged(struct net_device *dev)
{
	dev->priv_flags &= ~IFF_IS_BRIDGED;
}

static rx_handler_result_t fb_eth_handle_frame(struct sk_buff **pskb)
{
	unsigned int seq;
	struct sk_buff *skb = *pskb;
	struct fb_eth_dev_node *node;
	struct fblock *fb = NULL;
	struct fb_eth_priv __percpu *fb_priv_cpu;

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return RX_HANDLER_PASS;
	if (unlikely(!is_valid_ether_addr(eth_hdr(skb)->h_source)))
		goto drop;
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb))
		return RX_HANDLER_CONSUMED;

	list_for_each_entry_rcu(node, &fb_eth_devs, list)
		if (skb->dev == node->dev)
			fb = node->fb;
	if (!fb)
		goto drop;

	fb_priv_cpu = this_cpu_ptr(rcu_dereference(fb->private_data));
	if (fb_priv_cpu->port[TYPE_INGRESS] == IDP_UNKNOWN)
		goto drop;

	do {
		seq = read_seqbegin(&fb_priv_cpu->lock);
		write_next_idp_to_skb(skb, fb->idp,
				      fb_priv_cpu->port[TYPE_INGRESS]);
	} while (read_seqretry(&fb_priv_cpu->lock, seq));

	process_packet(skb, TYPE_INGRESS);

	return RX_HANDLER_CONSUMED;
drop:
	kfree_skb(skb);
	return RX_HANDLER_CONSUMED;
}

static int fb_eth_netrx(const struct fblock * const fb,
			struct sk_buff * const skb,
			enum path_type * const dir)
{
	struct fb_eth_priv __percpu *fb_priv_cpu;
	fb_priv_cpu = this_cpu_ptr(rcu_dereference(fb->private_data));
	write_next_idp_to_skb(skb, fb->idp, IDP_UNKNOWN);
	skb->dev = fb_priv_cpu->dev;
	dev_queue_xmit(skb);
	return PPE_DROPPED;
}

static int fb_eth_event(struct notifier_block *self, unsigned long cmd,
			void *args)
{
	int ret = NOTIFY_OK;
	unsigned int cpu;
	struct fblock *fb;
	struct fb_eth_priv __percpu *fb_priv;

	rcu_read_lock();
	fb = rcu_dereference_raw(container_of(self, struct fblock_notifier, nb)->self);
	fb_priv = (struct fb_eth_priv __percpu *) rcu_dereference_raw(fb->private_data);
	rcu_read_unlock();

	switch (cmd) {
	case FBLOCK_BIND_IDP: {
		int bound = 0;
		struct fblock_bind_msg *msg = args;
		get_online_cpus();
		for_each_online_cpu(cpu) {
			struct fb_eth_priv *fb_priv_cpu;
			fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
			if (fb_priv_cpu->port[msg->dir] == IDP_UNKNOWN) {
				write_seqlock(&fb_priv_cpu->lock);
				fb_priv_cpu->port[msg->dir] = msg->idp;
				write_sequnlock(&fb_priv_cpu->lock);
				bound = 1;
			} else {
				ret = NOTIFY_BAD;
				break;
			}
		}
		put_online_cpus();
		if (bound)
			printk(KERN_INFO "[%s::vlink] port %s bound to IDP%u\n",
			       fb->name, path_names[msg->dir], msg->idp);
		} break;
	case FBLOCK_UNBIND_IDP: {
		int unbound = 0;
		struct fblock_bind_msg *msg = args;
		get_online_cpus();
		for_each_online_cpu(cpu) {
			struct fb_eth_priv *fb_priv_cpu;
			fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
			if (fb_priv_cpu->port[msg->dir] == msg->idp) {
				write_seqlock(&fb_priv_cpu->lock);
				fb_priv_cpu->port[msg->dir] = IDP_UNKNOWN;
				write_sequnlock(&fb_priv_cpu->lock);
				unbound = 1;
			} else {
				ret = NOTIFY_BAD;
				break;
			}
		}
		put_online_cpus();
		if (unbound)
			printk(KERN_INFO "[%s::vlink] port %s unbound\n",
			       fb->name, path_names[msg->dir]);
		} break;
	default:
		break;
	}

	return ret;
}

static void cleanup_fb_eth(struct net_device *dev)
{
	rtnl_lock();
	if (fb_eth_dev_is_bridged(dev)) {
		netdev_rx_handler_unregister(dev);
		fb_eth_make_dev_unbridged(dev);
	}
	rtnl_unlock();
}

static int init_fb_eth(struct net_device *dev)
{
	int ret = 0;
	rtnl_lock();
	ret = netdev_rx_handler_register(dev, fb_eth_handle_frame, NULL);
	if (ret)
		ret = -EIO;
	else
		fb_eth_make_dev_bridged(dev);
	rtnl_unlock();
	return ret;
}

static struct fblock *fb_eth_build_fblock(struct net_device *dev)
{
	int ret = 0;
	unsigned int cpu;
	struct fblock *fb;
	struct fb_eth_priv __percpu *fb_priv;

	fb = alloc_fblock(GFP_ATOMIC);
	if (!fb)
		return NULL;

	fb_priv = alloc_percpu(struct fb_eth_priv);
	if (!fb_priv)
		goto err;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct fb_eth_priv *fb_priv_cpu;
		fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
		seqlock_init(&fb_priv_cpu->lock);
		fb_priv_cpu->port[0] = IDP_UNKNOWN;
		fb_priv_cpu->port[1] = IDP_UNKNOWN;
		fb_priv_cpu->dev = dev;
	}
	put_online_cpus();

	ret = init_fblock(fb, dev->name, fb_priv);
	if (ret)
		goto err2;

	fb->netfb_rx = fb_eth_netrx;
	fb->event_rx = fb_eth_event;
	fb->factory = NULL;

	ret = register_fblock_namespace(fb);
	if (ret)
		goto err3;
	ret = init_fb_eth(dev);
	if (ret)
		goto err4;
	__module_get(THIS_MODULE);
	smp_wmb();
	return fb;
err4:
	unregister_fblock_namespace_no_rcu(fb);
err3:
	cleanup_fblock_ctor(fb);
err2:
	free_percpu(fb_priv);
err:
	kfree_fblock(fb);
	fb = NULL;
	return NULL;
}

static void fb_eth_destroy_fblock(struct fblock *fb)
{
	struct fb_eth_priv __percpu *fb_priv_cpu;

	rcu_read_lock();
	fb_priv_cpu = this_cpu_ptr(rcu_dereference(fb->private_data));
	cleanup_fb_eth(fb_priv_cpu->dev);
	rcu_read_unlock();

	unregister_fblock_namespace_no_rcu(fb);
	cleanup_fblock(fb);
	free_percpu(rcu_dereference_raw(fb->private_data));
	kfree_fblock(fb);
	module_put(THIS_MODULE);
}

static struct vlink_subsys fb_eth_sys __read_mostly = {
	.name = "eth",
	.owner = THIS_MODULE,
	.type = VLINKNLGRP_ETHERNET,
	.rwsem = __RWSEM_INITIALIZER(fb_eth_sys.rwsem),
};

static int fb_eth_start_hook_dev(struct vlinknlmsg *vhdr, struct nlmsghdr *nlh)
{
	unsigned long flags;
	struct net_device *dev;
	struct fb_eth_dev_node *node;

	if (vhdr->cmd != VLINKNLCMD_START_HOOK_DEVICE)
		return NETLINK_VLINK_RX_NXT;

	dev = dev_get_by_name(&init_net, vhdr->real_name);
	if (dev && (dev->priv_flags & IFF_VLINK_DEV) == IFF_VLINK_DEV)
		goto err;
	else if (!dev)
		return NETLINK_VLINK_RX_EMERG;

	if (fb_eth_dev_is_bridged(dev))
		goto out;
	if (fb_ethvlink_real_dev_is_hooked(dev)) /* need to check this, too */
		goto out;

	node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		goto out;
	node->dev = dev;
	node->fb = fb_eth_build_fblock(dev);
	if (!node->fb) {
		kfree(node);
		goto out;
	}

	spin_lock_irqsave(&fb_eth_devs_lock, flags);
	list_add_rcu(&node->list, &fb_eth_devs);
	spin_unlock_irqrestore(&fb_eth_devs_lock, flags);

	printk(KERN_INFO "[lana] hook attached to carrier %s\n",
	       vhdr->real_name);
out:
	dev_put(dev);
	return NETLINK_VLINK_RX_STOP;
err:
	dev_put(dev);
	return NETLINK_VLINK_RX_EMERG;
}

static int fb_eth_stop_hook_dev(struct vlinknlmsg *vhdr, struct nlmsghdr *nlh)
{
	unsigned long flags;
	struct fblock *fb = NULL;
	struct net_device *dev;
	struct fb_eth_dev_node *node;

	if (vhdr->cmd != VLINKNLCMD_STOP_HOOK_DEVICE)
		return NETLINK_VLINK_RX_NXT;

	dev = dev_get_by_name(&init_net, vhdr->real_name);
	if (!dev)
		return NETLINK_VLINK_RX_EMERG;
	if (!fb_eth_dev_is_bridged(dev))
		goto err_put;
	if ((dev->flags & IFF_RUNNING) == IFF_RUNNING)
		goto err_put;

	spin_lock_irqsave(&fb_eth_devs_lock, flags);
	list_for_each_entry_rcu(node, &fb_eth_devs, list) {
		if (dev == node->dev) {
			fb = node->fb;
			break;
		}
	}
	spin_unlock_irqrestore(&fb_eth_devs_lock, flags);

	if (!fb)
		goto err_put;
	if (atomic_read(&fb->refcnt) > 2) {
		printk(KERN_INFO "Cannot remove vlink dev! Still in use by "
		       "others!\n");
		goto err_put;
	}

	spin_lock_irqsave(&fb_eth_devs_lock, flags);
	list_del_rcu(&node->list);
	spin_unlock_irqrestore(&fb_eth_devs_lock, flags);

	fb_eth_destroy_fblock(fb);
	synchronize_rcu();
	kfree(node);

	printk(KERN_INFO "[lana] hook detached from carrier %s\n",
	       vhdr->real_name);

	dev_put(dev);
	return NETLINK_VLINK_RX_STOP;
err_put:
	dev_put(dev);
	return NETLINK_VLINK_RX_EMERG;
}

static struct vlink_callback fb_eth_start_hook_dev_cb =
	VLINK_CALLBACK_INIT(fb_eth_start_hook_dev, NETLINK_VLINK_PRIO_HIGH);
static struct vlink_callback fb_eth_stop_hook_dev_cb =
	VLINK_CALLBACK_INIT(fb_eth_stop_hook_dev, NETLINK_VLINK_PRIO_HIGH);

static int __init init_fb_eth_module(void)
{
	int ret = 0;
	ret = vlink_subsys_register(&fb_eth_sys);
	if (ret)
		return ret;

	vlink_add_callback(&fb_eth_sys, &fb_eth_start_hook_dev_cb);
        vlink_add_callback(&fb_eth_sys, &fb_eth_stop_hook_dev_cb);

	printk(KERN_INFO "[lana] Ethernet vlink layer loaded!\n");
	return ret;
}

static void __exit cleanup_fb_eth_module(void)
{
	vlink_subsys_unregister_batch(&fb_eth_sys);
	printk(KERN_INFO "[lana] Ethernet vlink layer removed!\n");
}

module_init(init_fb_eth_module);
module_exit(cleanup_fb_eth_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("Ethernet virtual link layer driver");

