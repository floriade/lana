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
#include <linux/if_arp.h>
#include <linux/if.h>
#include <linux/u64_stats_sync.h>
#include <net/rtnetlink.h>

#include "nl_vlink.h"

#define IFF_VLINK_MAS 0x20000 /* Master device */
#define IFF_VLINK_DEV 0x40000 /* Slave device */

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

struct fb_ethvlink_private {
	u16 port;
	struct net_device *real_dev;
	int (*net_rx)(struct sk_buff *skb);
	int (*net_tx)(struct net_device *dev, struct sk_buff *skb);
};

static int fb_ethvlink_init(struct net_device *dev)
{
//	dev->state = (dev->state &
//		      ~((1 << __LINK_STATE_NOCARRIER) |
//			(1 << __LINK_STATE_DORMANT))) |
//		     (dev_priv->real_dev->state &
//		      ~((1 << __LINK_STATE_NOCARRIER) |
//                      (1 << __LINK_STATE_DORMANT)));
//	dev->features = dev_priv->real_dev->features;
//	dev->gso_max_size = dev_priv->real_dev->gso_max_size;
//	dev->iflink = dev_priv->real_dev->ifindex;
//	dev->hard_header_len = dev_priv->real_dev->hard_header_len;
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
	netif_start_queue(dev);
	return 0;
}

static int fb_ethvlink_stop(struct net_device *dev)
{
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

static int fb_ethvlink_queue_xmit(struct sk_buff *skb,
				  struct net_device *dev)
{
	struct fb_ethvlink_private *dev_priv = netdev_priv(dev);

	skb_set_dev(skb, dev_priv->real_dev);
	return dev_queue_xmit(skb);
}

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
	} else {
		this_cpu_inc(dstats->tx_dropped);
	}

	return ret;
}

/*
 * Origin __netif_receive_skb, with rcu_read_lock!
 * Furthermore we're in fast-path and we're on the real dev!
 */
static struct sk_buff *fb_ethvlink_handle_frame(struct sk_buff *skb)
{
	struct net_device *dev;
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

	goto normstack; /* For the moment! */
#if 0
	dstats = this_cpu_ptr(dev->dstats);

	u64_stats_update_begin(&dstats->syncp);
	dstats->rx_packets++;
	dstats->rx_bytes += skb->len;
	u64_stats_update_end(&dstats->syncp);
//todo !!!
#endif

lanastack: /* Unlocks rcu and done! */
	kfree_skb(skb); /* XXX */
	return NULL;
normstack: /* Continues with deliver_skb to the protos */
	return skb;
drop:
	kfree_skb(skb);
	return NULL;
}

static void fb_ethvlink_dev_setup(struct net_device *dev)
{
	ether_setup(dev);

//	dev->ethtool_ops = &fb_ethvlink_ethtool_ops;
//	dev->header_ops = &fb_ethvlink_header_ops;
	dev->netdev_ops = &fb_ethvlink_netdev_ops;
	dev->rtnl_link_ops = &fb_ethvlink_rtnl_ops;
	dev->destructor	= free_netdev;
	dev->tx_queue_len = 0;
	dev->priv_flags	&= ~IFF_XMIT_DST_RELEASE;
	dev->destructor = free_netdev;

	random_ether_addr(dev->dev_addr);
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
	struct net_device *dev;
	struct net_device *root;
	struct fb_ethvlink_private *dev_priv;

	if (vhdr->cmd != VLINKNLCMD_ADD_DEVICE)
		return NETLINK_VLINK_RX_NXT;

	root = dev_get_by_name(&init_net, vhdr->virt_name);
	if (root) {
		dev_put(root);
		goto err;
	}

	root = dev_get_by_name(&init_net, vhdr->real_name);
	if (root && (root->priv_flags & IFF_VLINK_DEV) == IFF_VLINK_DEV) {
		dev_put(root);
		goto err;
	} else if (!root)
		goto err;

	dev = alloc_netdev(sizeof(struct fb_ethvlink_private),
			   vhdr->virt_name, fb_ethvlink_dev_setup);
	if (!dev)
		goto err;

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
	dev_priv->real_dev = root;

	if (!fb_ethvlink_real_dev_is_hooked(dev_priv->real_dev)) {
		rtnl_lock();
		ret = netdev_rx_handler_register(dev_priv->real_dev,
						 fb_ethvlink_handle_frame,
						 NULL);
		rtnl_unlock();
		if (ret)
			goto err_put;
		fb_ethvlink_make_real_dev_hooked(dev_priv->real_dev);
	}

	netif_stacked_transfer_operstate(dev_priv->real_dev, dev);

	netif_tx_lock_bh(dev);
	netif_carrier_off(dev);
	netif_tx_unlock_bh(dev);

	dev_put(dev_priv->real_dev);

	return NETLINK_VLINK_RX_STOP;
err_put:
	dev_put(dev_priv->real_dev);
err_free:
	free_netdev(dev);
err:
	return NETLINK_VLINK_RX_EMERG;
}

static int fb_ethvlink_rm_dev(struct vlinknlmsg *vhdr, struct nlmsghdr *nlh)
{
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

	netif_tx_lock_bh(dev);
	netif_carrier_off(dev);
	netif_tx_unlock_bh(dev);

	dev_put(dev);

	rtnl_lock();
// Well when to release? Todo
//	netdev_rx_handler_unregister(dev_priv->real_dev);
// if never our kernel fucks up! ;-)
	unregister_netdevice(dev);
	rtnl_unlock();

	return NETLINK_VLINK_RX_STOP;
err_put:
	dev_put(dev);
	return NETLINK_VLINK_RX_EMERG;
}

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

static struct rtnl_link_ops fb_ethvlink_rtnl_ops __read_mostly = {
	.kind                = "lana",
	.priv_size           = sizeof(struct fb_ethvlink_private),
	.setup               = fb_ethvlink_dev_setup,
	.validate            = fb_ethvlink_validate,
};

static struct nl_vlink_subsys fb_ethvlink_sys = {
	.name                = "ethvlink",
	.type                = VLINKNLGRP_ETHERNET,
	.rwsem               = __RWSEM_INITIALIZER(fb_ethvlink_sys.rwsem),
};

static struct nl_vlink_callback fb_ethvlink_add_dev_cb =
	NL_VLINK_CALLBACK_INIT(fb_ethvlink_add_dev, NETLINK_VLINK_PRIO_HIGH);
static struct nl_vlink_callback fb_ethvlink_rm_dev_cb =
	NL_VLINK_CALLBACK_INIT(fb_ethvlink_rm_dev, NETLINK_VLINK_PRIO_HIGH);

static int __init init_fb_ethvlink_module(void)
{
	int ret = 0;

	ret = rtnl_link_register(&fb_ethvlink_rtnl_ops);
	if (ret)	
		return ret;
	ret = nl_vlink_subsys_register(&fb_ethvlink_sys);
	if (ret)
		goto err;
	ret = nl_vlink_add_callbacks(&fb_ethvlink_sys,
				     &fb_ethvlink_add_dev_cb,
				     &fb_ethvlink_rm_dev_cb);
	if (ret)
		goto err_unr;

	printk(KERN_INFO "[lana] Ethernet vlink layer loaded!\n");
	return 0;

err_unr:
	nl_vlink_subsys_unregister_batch(&fb_ethvlink_sys);
err:
	rtnl_link_unregister(&fb_ethvlink_rtnl_ops);
	return ret;
}

static void __exit cleanup_fb_ethvlink_module(void)
{
	rtnl_link_unregister(&fb_ethvlink_rtnl_ops);
	nl_vlink_subsys_unregister_batch(&fb_ethvlink_sys);

	printk(KERN_INFO "[lana] Ethernet vlink layer removed!\n");
}

module_init(init_fb_ethvlink_module);
module_exit(cleanup_fb_ethvlink_module);

MODULE_ALIAS_RTNL_LINK("lana");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("Ethernet virtual link layer driver");

