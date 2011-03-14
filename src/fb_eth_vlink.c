/*
 * Lightweight Autonomic Network Architecture
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

static struct net_device_ops fb_eth_vlink_netdev_ops __read_mostly;
static struct rtnl_link_ops fb_eth_vlink_rtnl_ops __read_mostly;

struct pcpu_dstats {
	u64                   tx_packets;
	u64                   tx_bytes;
	struct u64_stats_sync syncp;
};

static int fb_eth_vlink_init(struct net_device *dev)
{
	dev->dstats = alloc_percpu(struct pcpu_dstats);
	if (!dev->dstats)
		return -ENOMEM;
	return 0;
}

static void fb_eth_vlink_uninit(struct net_device *dev)
{
	free_percpu(dev->dstats);
	free_netdev(dev);
}

static int fb_eth_vlink_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

static int fb_eth_vlink_stop(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

static int fb_eth_vlink_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct pcpu_dstats *dstats = this_cpu_ptr(dev->dstats);

	u64_stats_update_begin(&dstats->syncp);
	dstats->tx_packets++;
	dstats->tx_bytes += skb->len;
	u64_stats_update_end(&dstats->syncp);

	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static void fb_eth_vlink_dev_setup(struct net_device *dev)
{
	ether_setup(dev);

//	dev->ethtool_ops = &fb_eth_vlink_ethtool_ops;
//	dev->header_ops = &fb_eth_vlink_header_ops;
	dev->netdev_ops = &fb_eth_vlink_netdev_ops;
	dev->destructor = fb_eth_vlink_uninit;
	dev->rtnl_link_ops = &fb_eth_vlink_rtnl_ops;

	dev->tx_queue_len = 0;
	dev->priv_flags	&= ~IFF_XMIT_DST_RELEASE;
	dev->destructor = free_netdev;

	random_ether_addr(dev->dev_addr);
}

static int fb_eth_vlink_validate(struct nlattr **tb, struct nlattr **data)
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
fb_eth_vlink_get_stats64(struct net_device *dev,
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

static struct net_device_ops fb_eth_vlink_netdev_ops __read_mostly = {
	.ndo_init            = fb_eth_vlink_init,
//	.ndo_uninit          = fb_eth_vlink_uninit,
	.ndo_open            = fb_eth_vlink_open,
	.ndo_stop            = fb_eth_vlink_stop,
	.ndo_start_xmit      = fb_eth_vlink_start_xmit,
	.ndo_get_stats64     = fb_eth_vlink_get_stats64,
	.ndo_change_mtu      = eth_change_mtu,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_validate_addr   = eth_validate_addr,
};

static struct rtnl_link_ops fb_eth_vlink_rtnl_ops __read_mostly = {
	.kind                = "ana",
	.setup               = fb_eth_vlink_dev_setup,
	.validate            = fb_eth_vlink_validate,
};

static int __init init_fb_eth_vlink_module(void)
{
	int ret = 0;
	struct net_device *dev;

	ret = rtnl_link_register(&fb_eth_vlink_rtnl_ops);
	if (ret)	
		return ret;

	dev = alloc_netdev(0, "ana", fb_eth_vlink_dev_setup);
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


	printk(KERN_INFO "eth vlink init done\n");
	return 0;

err_free:
	free_netdev(dev);
err:
	rtnl_link_unregister(&fb_eth_vlink_rtnl_ops);
	return ret;
}

static void __exit cleanup_fb_eth_vlink_module(void)
{
	rtnl_link_unregister(&fb_eth_vlink_rtnl_ops);
	printk(KERN_INFO "eth vlink cleanup done\n");
}

module_init(init_fb_eth_vlink_module);
module_exit(cleanup_fb_eth_vlink_module);

MODULE_ALIAS_RTNL_LINK("ana");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("ANA Ethernet virtual link layer driver");

