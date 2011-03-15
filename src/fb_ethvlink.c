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
#include <linux/u64_stats_sync.h>
#include <net/rtnetlink.h>

#include "nl_vlink.h"

static struct net_device_ops fb_ethvlink_netdev_ops __read_mostly;
static struct rtnl_link_ops fb_ethvlink_rtnl_ops __read_mostly;

struct pcpu_dstats {
	u64                   rx_packets;
	u64                   rx_bytes;
	u64                   rx_multicast;
	u64                   tx_packets;
	u64                   tx_bytes;
	struct u64_stats_sync syncp; /* sync point for 64bit counters */
	u32                   rx_errors;
	u32                   tx_dropped;
};

struct fb_ethvlink_dev {
	struct net_device *dev;
	struct net_device *realdev;
	struct pcpu_dstats __percpu *pcpu_stats;
	int (*process_rx)(struct sk_buff *skb);
	int (*process_tx)(struct net_device *dev, struct sk_buff *skb);
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
	free_netdev(dev);
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

static int fb_ethvlink_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct pcpu_dstats *dstats = this_cpu_ptr(dev->dstats);

	u64_stats_update_begin(&dstats->syncp);
	dstats->tx_packets++;
	dstats->tx_bytes += skb->len;
	u64_stats_update_end(&dstats->syncp);

	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static void fb_ethvlink_dev_setup(struct net_device *dev)
{
	ether_setup(dev);

//	dev->ethtool_ops = &fb_ethvlink_ethtool_ops;
//	dev->header_ops = &fb_ethvlink_header_ops;
	dev->netdev_ops = &fb_ethvlink_netdev_ops;
	dev->destructor = fb_ethvlink_uninit;
	dev->rtnl_link_ops = &fb_ethvlink_rtnl_ops;

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
		u64 tbytes, tpackets;
		unsigned int start;
		const struct pcpu_dstats *dstats;

		dstats = per_cpu_ptr(dev->dstats, i);

		do {
			start = u64_stats_fetch_begin(&dstats->syncp);
			tbytes = dstats->tx_bytes;
			tpackets = dstats->tx_packets;
		} while (u64_stats_fetch_retry(&dstats->syncp, start));

		stats->tx_bytes += tbytes;
		stats->tx_packets += tpackets;
	}

	return stats;
}

static int rxtest1(struct vlinknlmsg *vhdr, struct nlmsghdr *nlh)
{
	printk("hello world1!\n");
	return NETLINK_VLINK_RX_OK;
}

static int rxtest2(struct vlinknlmsg *vhdr, struct nlmsghdr *nlh)
{
	printk("hello world2!\n");
	return NETLINK_VLINK_RX_OK;
}

static struct net_device_ops fb_ethvlink_netdev_ops __read_mostly = {
	.ndo_init            = fb_ethvlink_init,
//	.ndo_uninit          = fb_ethvlink_uninit,
	.ndo_open            = fb_ethvlink_open,
	.ndo_stop            = fb_ethvlink_stop,
	.ndo_start_xmit      = fb_ethvlink_start_xmit,
	.ndo_get_stats64     = fb_ethvlink_get_stats64,
	.ndo_change_mtu      = eth_change_mtu,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_validate_addr   = eth_validate_addr,
};

static struct rtnl_link_ops fb_ethvlink_rtnl_ops __read_mostly = {
	.kind                = "ana",
	.setup               = fb_ethvlink_dev_setup,
	.validate            = fb_ethvlink_validate,
};

static struct nl_vlink_subsys fb_ethvlink_sys = {
	.name = "ethvlink",
	.type = VLINKNLGRP_ETHERNET,
	.rwsem = __RWSEM_INITIALIZER(fb_ethvlink_sys.rwsem),
};

static struct nl_vlink_callback fb_ethvlink_add_dev_cb =
		NL_VLINK_CALLBACK_INIT(rxtest1, NETLINK_VLINK_PRIO_HIGH);
static struct nl_vlink_callback fb_ethvlink_rm_dev_cb =
		NL_VLINK_CALLBACK_INIT(rxtest2, NETLINK_VLINK_PRIO_HIGH);

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

	printk(KERN_INFO "LANA eth vlink layer loaded!\n");
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

	printk(KERN_INFO "LANA eth vlink layer removed!\n");
}

module_init(init_fb_ethvlink_module);
module_exit(cleanup_fb_ethvlink_module);

MODULE_ALIAS_RTNL_LINK("ana");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("Ethernet virtual link layer driver");

#if 0
	struct net_device *dev;
	dev = alloc_netdev(0, "ana%d", fb_ethvlink_dev_setup);
	if (!dev) {
		ret = -ENOMEM;
		goto err;
	}

	ret = dev_alloc_name(dev, dev->name);
	if (ret)
		goto err_free;

	ret = register_netdev(dev);
	if (ret)
		goto err_free;
#endif

