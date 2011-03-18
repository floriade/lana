/*
 * Lightweight Autonomic Network Architecture
 *
 * Ethernet vlink layer. This module allows to operate virtual LANA Ethernet
 * devices which are configurable via ifconfig et. al. and bound to a real
 * underlying device. Similar to VLANs, multiple virtual devices can be
 * bound to a real network device. Multiplexing and demultiplexing happens
 * within this driver.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/if.h>
#include <linux/list.h>
#include <linux/u64_stats_sync.h>
#include <net/rtnetlink.h>

#include "nl_vlink.h"

#define IFF_VLINK_MAS 0x20000 /* Master device */
#define IFF_VLINK_DEV 0x40000 /* Slave device */

/* Ethernet LANA packet with 10 Bit port ID */
#define ETH_P_LANA    0xAC00

struct pcpu_dstats {
	u64 rx_packets;
	u64 rx_bytes;
	u64 rx_multicast;
	u64 tx_packets;
	u64 tx_bytes;
	struct u64_stats_sync syncp;
	u32 rx_errors;
	u32 tx_dropped;
};

static struct net_device_ops fb_ethvlink_netdev_ops __read_mostly;
static struct rtnl_link_ops fb_ethvlink_rtnl_ops __read_mostly;
static struct ethtool_ops fb_ethvlink_ethtool_ops __read_mostly;
static struct header_ops fb_ethvlink_header_ops __read_mostly;

static LIST_HEAD(fb_ethvlink_vdevs);
static DEFINE_SPINLOCK(fb_ethvlink_vdevs_lock);

struct fb_ethvlink_private {
	u16 port;
	struct list_head list;
	struct net_device *self;
	struct net_device *real_dev;
	int (*netvif_rx)(struct sk_buff *skb, struct net_device *dev);
};

static int fb_ethvlink_init(struct net_device *dev)
{
	dev->dstats = alloc_percpu(struct pcpu_dstats);
	if (!dev->dstats)
		return -ENOMEM;
	return 0;
}

static void fb_ethvlink_uninit(struct net_device *dev)
{
	free_percpu(dev->dstats);
}

static int fb_ethvlink_open(struct net_device *dev)
{
	struct fb_ethvlink_private *dev_priv = netdev_priv(dev);

	netif_start_queue(dev);
	if (netif_carrier_ok(dev_priv->real_dev)) {
		netif_tx_lock_bh(dev);
		netif_carrier_on(dev);
		netif_tx_unlock_bh(dev);
	}

	return 0;
}

static int fb_ethvlink_stop(struct net_device *dev)
{
	netif_tx_lock_bh(dev);
	netif_carrier_off(dev);
	netif_tx_unlock_bh(dev);
	netif_stop_queue(dev);

	return 0;
}

static inline int fb_ethvlink_real_dev_is_hooked(struct net_device *dev)
{
	return (dev->priv_flags & IFF_VLINK_MAS) == IFF_VLINK_MAS;
}

static inline void fb_ethvlink_make_real_dev_hooked(struct net_device *dev)
{
	dev->priv_flags |= IFF_VLINK_MAS;
}

static inline void fb_ethvlink_make_real_dev_unhooked(struct net_device *dev)
{
	dev->priv_flags &= ~IFF_VLINK_MAS;
}

static int fb_ethvlink_queue_xmit(struct sk_buff *skb,
				  struct net_device *dev)
{
	struct fb_ethvlink_private *dev_priv = netdev_priv(dev);

	/* Exit the lana stack here, egress path */
	netdev_printk(KERN_DEBUG, dev, "tx'ed packet!\n");
	skb_set_dev(skb, dev_priv->real_dev);
	return dev_queue_xmit(skb);
}

/*
 * Egress path. This is fairly easy, since we enter with our virtual
 * device and just need to lookup the real networking device, reset the
 * skb to the real device and enqueue it. Done!
 */
netdev_tx_t fb_ethvlink_start_xmit(struct sk_buff *skb,
				   struct net_device *dev)
{
	int ret;
	struct pcpu_dstats *dstats;

	dstats = this_cpu_ptr(dev->dstats);
	ret = fb_ethvlink_queue_xmit(skb, dev);
	if (likely(ret == NET_XMIT_SUCCESS || ret == NET_XMIT_CN)) {
		u64_stats_update_begin(&dstats->syncp);
		dstats->tx_packets++;
		dstats->tx_bytes += skb->len;
		u64_stats_update_end(&dstats->syncp);
	} else 
		this_cpu_inc(dstats->tx_dropped);

	return ret;
}

int fb_ethvlink_handle_frame_virt(struct sk_buff *skb,
				  struct net_device *dev)
{
	/* Enter the lana stack here, ingress path */
	netdev_printk(KERN_DEBUG, dev, "rx'ed packet!\n");
	return NET_RX_SUCCESS;
}

/*
 * Origin __netif_receive_skb, with rcu_read_lock! We're at a point
 * where bridging code and macvlan code is usually invoked, so we're
 * in fast-path on our real device (not virtual!) before all the usual
 * stack is being processed by deliver_skb! This means we return NULL
 * if our lana stack processed the packet, so that the rcu_read_lock
 * gets unlocked and we're done. On the other hand, if we want packages
 * to be processed by the kernel network stack, we go out by delivering
 * the valid pointer to the skb. Basically, here's the point where we
 * demultiplex the ingress path to registered virtual lana devices.
 */
static struct sk_buff *fb_ethvlink_handle_frame(struct sk_buff *skb)
{
	int ret;
	u16 vport;
	struct net_device *dev;
	struct fb_ethvlink_private *vdev;
	struct pcpu_dstats *dstats;

	dev = skb->dev;
	if (unlikely(!(dev->flags & IFF_UP)))
		goto drop;

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		goto normstack;

	if (unlikely(!is_valid_ether_addr(eth_hdr(skb)->h_source)))
		goto drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb))
		return NULL;

	if ((eth_hdr(skb)->h_proto & htons(ETH_P_LANA)) !=
	    htons(ETH_P_LANA))
		goto normstack;

	vport = ntohs(eth_hdr(skb)->h_proto &
		      ~htons(ETH_P_LANA));

	list_for_each_entry_rcu(vdev, &fb_ethvlink_vdevs, list) {
		if (vport == vdev->port) {
			if (dev == vdev->real_dev) {
				dstats = this_cpu_ptr(vdev->self->dstats);
				ret = vdev->netvif_rx(skb, vdev->self);
				if (ret == NET_RX_SUCCESS) {
					u64_stats_update_begin(&dstats->syncp);
					dstats->rx_packets++;
					dstats->rx_bytes += skb->len;
					u64_stats_update_end(&dstats->syncp);
				} else
					this_cpu_inc(dstats->rx_errors);
				break;
			}
		}
	}

	kfree_skb(skb);
	return NULL;
normstack:
	return skb;
drop:
	kfree_skb(skb);
	return NULL;
}

static void fb_ethvlink_ethtool_get_drvinfo(struct net_device *dev,
					    struct ethtool_drvinfo *drvinfo)
{
	snprintf(drvinfo->driver, 32, "ethvlink");
	snprintf(drvinfo->version, 32, "0.1");
}

static u32 fb_ethvlink_ethtool_get_rx_csum(struct net_device *dev)
{
	const struct fb_ethvlink_private *vdev = netdev_priv(dev);
	return dev_ethtool_get_rx_csum(vdev->real_dev);
}

static int fb_ethvlink_ethtool_get_settings(struct net_device *dev,
					struct ethtool_cmd *cmd)
{
	const struct fb_ethvlink_private *vdev = netdev_priv(dev);
	return dev_ethtool_get_settings(vdev->real_dev, cmd);
}

static u32 fb_ethvlink_ethtool_get_flags(struct net_device *dev)
{
	const struct fb_ethvlink_private *vdev = netdev_priv(dev);
	return dev_ethtool_get_flags(vdev->real_dev);
}

static void fb_ethvlink_dev_setup(struct net_device *dev)
{
	ether_setup(dev);

	dev->ethtool_ops = &fb_ethvlink_ethtool_ops;
	dev->netdev_ops = &fb_ethvlink_netdev_ops;
	dev->rtnl_link_ops = &fb_ethvlink_rtnl_ops;
	dev->header_ops = &fb_ethvlink_header_ops;
	dev->destructor	= free_netdev;
	dev->tx_queue_len = 0;
	dev->priv_flags	&= ~IFF_XMIT_DST_RELEASE;
	dev->destructor = free_netdev;

	random_ether_addr(dev->dev_addr);
	memset(dev->broadcast, 0, ETH_ALEN);
}

static int fb_ethvlink_validate(struct nlattr **tb, struct nlattr **data)
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}

	return 0;
}

static int fb_ethvlink_create_header(struct sk_buff *skb,
				     struct net_device *dev,
				     unsigned short type, const void *daddr,
				     const void *saddr, unsigned len)
{
	const struct fb_ethvlink_private *vdev = netdev_priv(dev);
	return dev_hard_header(skb, vdev->real_dev, type, daddr,
			       saddr ? : dev->dev_addr, len);
}

static struct rtnl_link_stats64 *
fb_ethvlink_get_stats64(struct net_device *dev,
			 struct rtnl_link_stats64 *stats)
{
	int i;

	for_each_possible_cpu(i) {
		u64 tbytes, tpackets, rbytes, rpackets;
		unsigned int start;
		const struct pcpu_dstats *dstats;

		dstats = per_cpu_ptr(dev->dstats, i);

		do {
			start = u64_stats_fetch_begin(&dstats->syncp);
			tbytes = dstats->tx_bytes;
			tpackets = dstats->tx_packets;
			rbytes = dstats->rx_bytes;
			rpackets = dstats->rx_packets;
		} while (u64_stats_fetch_retry(&dstats->syncp, start));

		stats->tx_bytes += tbytes;
		stats->tx_packets += tpackets;
		stats->rx_bytes += rbytes;
		stats->rx_packets += rpackets;
	}

	return stats;
}

static int fb_ethvlink_add_dev(struct vlinknlmsg *vhdr,
			       struct nlmsghdr *nlh)
{
	int ret;
	unsigned long flags;
	struct net_device *dev;
	struct net_device *root;
	struct fb_ethvlink_private *dev_priv, *vdev;

	if (vhdr->cmd != VLINKNLCMD_ADD_DEVICE)
		return NETLINK_VLINK_RX_NXT;

	root = dev_get_by_name(&init_net, vhdr->virt_name);
	if (root)
		goto err_put;

	root = dev_get_by_name(&init_net, vhdr->real_name);
	if (root && (root->priv_flags & IFF_VLINK_DEV) == IFF_VLINK_DEV)
		goto err_put;
	else if (!root)
		goto err;

	vhdr->port &= 0x3FF;

	rcu_read_lock();
	list_for_each_entry_rcu(vdev, &fb_ethvlink_vdevs, list) {
		if (vdev->port == vhdr->port) {
			rcu_read_unlock();
			goto err_put;
		}
	}
	rcu_read_unlock();

	dev = alloc_netdev(sizeof(struct fb_ethvlink_private),
			   vhdr->virt_name, fb_ethvlink_dev_setup);
	if (!dev)
		goto err_put;

	ret = dev_alloc_name(dev, dev->name);
	if (ret)
		goto err_free;

	ret = register_netdev(dev);
	if (ret)
		goto err_free;

	dev->priv_flags |= vhdr->flags;
	dev->priv_flags |= IFF_VLINK_DEV;
	dev_priv = netdev_priv(dev);
	dev_priv->port = vhdr->port;
	dev_priv->self = dev;
	dev_priv->real_dev = root;
	dev_priv->netvif_rx = fb_ethvlink_handle_frame_virt;

	netif_stacked_transfer_operstate(dev_priv->real_dev, dev);

	dev_put(dev_priv->real_dev);

	spin_lock_irqsave(&fb_ethvlink_vdevs_lock, flags);
	list_add_rcu(&dev_priv->list, &fb_ethvlink_vdevs);
	spin_unlock_irqrestore(&fb_ethvlink_vdevs_lock, flags);

	netif_tx_lock_bh(dev);
	netif_carrier_off(dev);
	netif_tx_unlock_bh(dev);

	printk(KERN_INFO "[lana] %s registered to link master %s:%u\n",
	       vhdr->virt_name, vhdr->real_name, dev_priv->port);
	return NETLINK_VLINK_RX_STOP;

err_free:
	dev_put(root);
	free_netdev(dev);
err:
	return NETLINK_VLINK_RX_EMERG;
err_put:
	dev_put(root);
	goto err;
}

static int fb_ethvlink_start_hook_dev(struct vlinknlmsg *vhdr,
				      struct nlmsghdr *nlh)
{
	int ret;
	struct net_device *root;

	if (vhdr->cmd != VLINKNLCMD_START_HOOK_DEVICE)
		return NETLINK_VLINK_RX_NXT;

	root = dev_get_by_name(&init_net, vhdr->real_name);
	if (root && (root->priv_flags & IFF_VLINK_DEV) == IFF_VLINK_DEV)
		goto err;
	else if (!root)
		return NETLINK_VLINK_RX_EMERG;

	if (fb_ethvlink_real_dev_is_hooked(root))
		goto out;

	rtnl_lock();
	ret = netdev_rx_handler_register(root, fb_ethvlink_handle_frame,
					 NULL);
	rtnl_unlock();
	if (ret)
		goto err;

	fb_ethvlink_make_real_dev_hooked(root);
	printk(KERN_INFO "[lana] hook attached to %s\n", vhdr->real_name);
out:
	dev_put(root);
	return NETLINK_VLINK_RX_STOP;
err:
	dev_put(root);
	return NETLINK_VLINK_RX_EMERG;
}

static int fb_ethvlink_stop_hook_dev(struct vlinknlmsg *vhdr,
				     struct nlmsghdr *nlh)
{
	struct net_device *root;

	if (vhdr->cmd != VLINKNLCMD_STOP_HOOK_DEVICE)
		return NETLINK_VLINK_RX_NXT;

	root = dev_get_by_name(&init_net, vhdr->real_name);
	if (root && (root->priv_flags & IFF_VLINK_DEV) == IFF_VLINK_DEV)
		goto err;
	else if (!root)
		return NETLINK_VLINK_RX_EMERG;

	if (!fb_ethvlink_real_dev_is_hooked(root))
		goto out;

	rtnl_lock();
	netdev_rx_handler_unregister(root);
	rtnl_unlock();

	fb_ethvlink_make_real_dev_unhooked(root);
	printk(KERN_INFO "[lana] hook detached from %s\n", vhdr->real_name);
out:
	dev_put(root);
	return NETLINK_VLINK_RX_STOP;
err:
	dev_put(root);
	return NETLINK_VLINK_RX_EMERG;
}

static void fb_ethvlink_rm_dev_common(struct net_device *dev)
{
	netif_tx_lock_bh(dev);
	netif_carrier_off(dev);
	netif_tx_unlock_bh(dev);

	printk(KERN_INFO "[lana] %s unregistered\n", dev->name);

	rtnl_lock();
	unregister_netdevice(dev);
	rtnl_unlock();
}

static int fb_ethvlink_rm_dev(struct vlinknlmsg *vhdr, struct nlmsghdr *nlh)
{
	unsigned long flags;
	struct fb_ethvlink_private *dev_priv;
	struct net_device *dev;

	if (vhdr->cmd != VLINKNLCMD_RM_DEVICE)
		return NETLINK_VLINK_RX_NXT;

	dev = dev_get_by_name(&init_net, vhdr->virt_name);
	if (!dev)
		return NETLINK_VLINK_RX_EMERG;
	if ((dev->priv_flags & IFF_VLINK_DEV) != IFF_VLINK_DEV)
		goto err_put;
	if ((dev->flags & IFF_RUNNING) == IFF_RUNNING)
		goto err_put;

	dev_put(dev);
	dev_priv = netdev_priv(dev);

	spin_lock_irqsave(&fb_ethvlink_vdevs_lock, flags);
	list_del_rcu(&dev_priv->list);
	spin_unlock_irqrestore(&fb_ethvlink_vdevs_lock, flags);

	fb_ethvlink_rm_dev_common(dev);

	return NETLINK_VLINK_RX_STOP;

err_put:
	dev_put(dev);
	return NETLINK_VLINK_RX_EMERG;
}

static int fb_ethvlink_dev_event(struct notifier_block *unused,
				 unsigned long event, void *ptr)
{
//	struct net_device *dev = ptr;

	switch (event) {
	case NETDEV_CHANGE:
		break;
	case NETDEV_FEAT_CHANGE:
		break;
	case NETDEV_UNREGISTER:
		break;
	case NETDEV_PRE_TYPE_CHANGE:
		return NOTIFY_BAD;
	}

	return NOTIFY_DONE;
}

static struct ethtool_ops fb_ethvlink_ethtool_ops __read_mostly = {
	.get_link            = ethtool_op_get_link,
	.get_settings        = fb_ethvlink_ethtool_get_settings,
	.get_rx_csum         = fb_ethvlink_ethtool_get_rx_csum,
	.get_drvinfo         = fb_ethvlink_ethtool_get_drvinfo,
	.get_flags           = fb_ethvlink_ethtool_get_flags,
};

static struct net_device_ops fb_ethvlink_netdev_ops __read_mostly = {
	.ndo_init            = fb_ethvlink_init,
	.ndo_uninit          = fb_ethvlink_uninit,
	.ndo_open            = fb_ethvlink_open,
	.ndo_stop            = fb_ethvlink_stop,
	.ndo_start_xmit      = fb_ethvlink_start_xmit,
	.ndo_get_stats64     = fb_ethvlink_get_stats64,
	.ndo_change_mtu      = eth_change_mtu,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_validate_addr   = eth_validate_addr,
};

static struct header_ops fb_ethvlink_header_ops __read_mostly = {
	.create              = fb_ethvlink_create_header,
	.rebuild             = eth_rebuild_header,
	.parse               = eth_header_parse,
	.cache               = eth_header_cache,
	.cache_update        = eth_header_cache_update,
};

static struct rtnl_link_ops fb_ethvlink_rtnl_ops __read_mostly = {
	.kind                = "lana",
	.priv_size           = sizeof(struct fb_ethvlink_private),
	.setup               = fb_ethvlink_dev_setup,
	.validate            = fb_ethvlink_validate,
};

static struct nl_vlink_subsys fb_ethvlink_sys __read_mostly = {
	.name                = "ethvlink",
	.type                = VLINKNLGRP_ETHERNET,
	.rwsem               = __RWSEM_INITIALIZER(fb_ethvlink_sys.rwsem),
};

static struct notifier_block fb_ethvlink_notifier_block __read_mostly = {
	.notifier_call       = fb_ethvlink_dev_event,
};

static struct nl_vlink_callback fb_ethvlink_add_dev_cb =
	NL_VLINK_CALLBACK_INIT(fb_ethvlink_add_dev, NETLINK_VLINK_PRIO_NORM);
static struct nl_vlink_callback fb_ethvlink_rm_dev_cb =
	NL_VLINK_CALLBACK_INIT(fb_ethvlink_rm_dev, NETLINK_VLINK_PRIO_NORM);
static struct nl_vlink_callback fb_ethvlink_start_hook_dev_cb =
	NL_VLINK_CALLBACK_INIT(fb_ethvlink_start_hook_dev, NETLINK_VLINK_PRIO_HIGH);
static struct nl_vlink_callback fb_ethvlink_stop_hook_dev_cb =
	NL_VLINK_CALLBACK_INIT(fb_ethvlink_stop_hook_dev, NETLINK_VLINK_PRIO_HIGH);

static int __init init_fb_ethvlink_module(void)
{
	int ret = 0;

	ret = rtnl_link_register(&fb_ethvlink_rtnl_ops);
	if (ret)	
		return ret;

	register_netdevice_notifier(&fb_ethvlink_notifier_block);

	ret = nl_vlink_subsys_register(&fb_ethvlink_sys);
	if (ret)
		goto err;

	ret = nl_vlink_add_callbacks(&fb_ethvlink_sys,
				     &fb_ethvlink_add_dev_cb,
				     &fb_ethvlink_rm_dev_cb,
				     &fb_ethvlink_start_hook_dev_cb,
				     &fb_ethvlink_stop_hook_dev_cb);
	if (ret)
		goto err_unr;

	printk(KERN_INFO "[lana] Ethernet vlink layer loaded!\n");
	return 0;

err_unr:
	nl_vlink_subsys_unregister_batch(&fb_ethvlink_sys);
err:
	rtnl_link_unregister(&fb_ethvlink_rtnl_ops);
	unregister_netdevice_notifier(&fb_ethvlink_notifier_block);
	return ret;
}

static void __exit cleanup_fb_ethvlink_module(void)
{
	struct fb_ethvlink_private *vdev;

	rcu_read_lock();
	list_for_each_entry_rcu(vdev, &fb_ethvlink_vdevs, list) {
		if (fb_ethvlink_real_dev_is_hooked(vdev->real_dev)) {
			rtnl_lock();
			netdev_rx_handler_unregister(vdev->real_dev);
			rtnl_unlock();

			fb_ethvlink_make_real_dev_unhooked(vdev->real_dev);
			printk(KERN_INFO "[lana] hook detached from %s\n",
			       vdev->real_dev->name);
		}

		fb_ethvlink_rm_dev_common(vdev->self);
	}
	rcu_read_unlock();

	rtnl_link_unregister(&fb_ethvlink_rtnl_ops);
	unregister_netdevice_notifier(&fb_ethvlink_notifier_block);
	nl_vlink_subsys_unregister_batch(&fb_ethvlink_sys);

	printk(KERN_INFO "[lana] Ethernet vlink layer removed!\n");
}

module_init(init_fb_ethvlink_module);
module_exit(cleanup_fb_ethvlink_module);

MODULE_ALIAS_RTNL_LINK("lana");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("Ethernet virtual link layer driver");

