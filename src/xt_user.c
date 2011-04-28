/*
 * Lightweight Autonomic Network Architecture
 *
 * LANA NETLINK handler for Functional Block userspace control.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/sock.h>

#include "xt_user.h"

static struct sock *userctl_sock = NULL;

static int __userctl_rcv(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct lananlmsg *lmsg;

	if (security_netlink_recv(skb, CAP_NET_ADMIN))
		return -EPERM;
	if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct lananlmsg)))
		return 0;

	lmsg = NLMSG_DATA(nlh);

	switch (lmsg->cmd) {
	case NETLINK_USERCTL_CMD_ADD: {
			struct lananlmsg_add *msg = (struct lananlmsg_add *) lmsg->buff;
			printk(KERN_INFO "[lana] Adding %s::%s!\n",
			       msg->name, msg->type);
		} break;
	case NETLINK_USERCTL_CMD_SET: {
			struct lananlmsg_set *msg = (struct lananlmsg_set *) lmsg->buff;
			printk(KERN_INFO "[lana] Setting %s -> %s!\n",
			       msg->name, msg->option);
		} break;
	case NETLINK_USERCTL_CMD_RM: {
			struct lananlmsg_rm *msg = (struct lananlmsg_rm *) lmsg->buff;
			printk(KERN_INFO "[lana] Removing %s!\n", msg->name);
		} break;
	case NETLINK_USERCTL_CMD_BIND: {
			struct lananlmsg_bind *msg = (struct lananlmsg_bind *) lmsg->buff;
			printk(KERN_INFO "[lana] Binding %s >=< %s!\n",
			       msg->name1, msg->name2);
		} break;
	case NETLINK_USERCTL_CMD_UNBIND: {
			struct lananlmsg_unbind *msg = (struct lananlmsg_unbind *) lmsg->buff;
			printk(KERN_INFO "[lana] Unbinding %s >|< %s!\n",
			       msg->name1, msg->name2);
		} break;
	default:
		printk("[lana] Unknown command!\n");
		break;
	}

	return 0;
}

static void userctl_rcv(struct sk_buff *skb)
{
	netlink_rcv_skb(skb, &__userctl_rcv);
}

int init_userctl_system(void)
{
	userctl_sock = netlink_kernel_create(&init_net, NETLINK_USERCTL,
					     USERCTLGRP_MAX, userctl_rcv,
					     NULL, THIS_MODULE);
	if (!userctl_sock)
		return -ENOMEM;
	return 0;
}
EXPORT_SYMBOL_GPL(init_userctl_system);

void cleanup_userctl_system(void)
{
	netlink_kernel_release(userctl_sock);
}
EXPORT_SYMBOL_GPL(cleanup_userctl_system);

