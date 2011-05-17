/*
 * Lightweight Autonomic Network Architecture
 *
 * Eth/PHY layer. Redirects all traffic into the LANA stack.
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

#include "xt_fblock.h"

static int fb_ethvlink_queue_xmit(struct sk_buff *skb,
				  struct net_device *dev)
{
	struct fb_ethvlink_private *dev_priv = netdev_priv(dev);

	/* Exit the lana stack here, egress path */
	netdev_printk(KERN_DEBUG, dev, "tx'ed packet!\n");
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
	} else 
		this_cpu_inc(dstats->tx_dropped);

	return ret;
}

static rx_handler_result_t fb_eth_handle_frame(struct sk_buff **pskb)
{
	int ret;
	struct sk_buff *skb = *pskb;
	struct net_device *dev;

	dev = skb->dev;
	if (unlikely((dev->flags & IFF_UP) != IFF_UP))
		goto drop;

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return RX_HANDLER_PASS;

	if (unlikely(!is_valid_ether_addr(eth_hdr(skb)->h_source)))
		goto drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb))
		return RX_HANDLER_CONSUMED;

	if ((eth_hdr(skb)->h_proto & __constant_htons(ETH_P_ARP)) ==
	    __constant_htons(ETH_P_ARP))
		return RX_HANDLER_PASS; /* Let OS handle ARP */

	printk("got pkt!\n");
	/* enqueue! */
drop:
	kfree_skb(skb);
	return RX_HANDLER_CONSUMED;
}

static int __init init_fb_eth_module(void)
{
	int ret;
	struct net_device *dev;
	rtnl_lock();
	for_each_netdev(&init_net, dev)	{
		ret = netdev_rx_handler_register(dev, fb_eth_handle_frame,
						 NULL);
		if (ret)
			break; // error!
	}
	rtnl_unlock();
	printk(KERN_INFO "[lana] Ethernet/PHY layer loaded!\n");
	return 0;
}

static void __exit cleanup_fb_eth_module(void)
{
	rtnl_lock();
	netdev_rx_handler_unregister(vdev->real_dev);
	rtnl_unlock();
	printk(KERN_INFO "[lana] Ethernet/PHY layer removed!\n");
}

module_init(init_fb_eth_module);
module_exit(cleanup_fb_eth_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("Ethernet/PHY link layer bridge driver");

