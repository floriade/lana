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

#include "xt_idp.h"
#include "xt_user.h"
#include "xt_fblock.h"
#include "xt_builder.h"

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
			struct fblock *fb;
			struct lananlmsg_add *msg =
				(struct lananlmsg_add *) lmsg->buff;
			fb = build_fblock_object(msg->type, msg->name);
			if (!fb)
				return -ENOMEM;
		} break;
	case NETLINK_USERCTL_CMD_SET: {
			//struct lananlmsg_set *msg =
			//	(struct lananlmsg_set *) lmsg->buff;
		} break;
	case NETLINK_USERCTL_CMD_REPLACE: {
			//struct lananlmsg_replace *msg =
			//	(struct lananlmsg_set *) lmsg->buff;
		} break;
	case NETLINK_USERCTL_CMD_SUBSCRIBE: {
			//struct lananlmsg_subscribe *msg = 
			//	(struct lananlmsg_set *) lmsg->buff;
		} break;
	case NETLINK_USERCTL_CMD_UNSUBSCRIBE: {
			//struct lananlmsg_unsubscribe *msg = 
			//	(struct lananlmsg_set *) lmsg->buff;
		} break;
	case NETLINK_USERCTL_CMD_RM: {
			struct fblock *fb;
			struct lananlmsg_rm *msg =
				(struct lananlmsg_rm *) lmsg->buff;
			fb = search_fblock_n(msg->name);
			if (!fb)
				return -EINVAL;
			if (atomic_read(&fb->refcnt) > 2) {
				/* Still in use by others */
				put_fblock(fb);
				return -EBUSY;
			}
			unregister_fblock_namespace(fb);
			put_fblock(fb);
		} break;
	case NETLINK_USERCTL_CMD_BIND: {
			int ret;
			struct fblock *fb1, *fb2;
			struct lananlmsg_bind *msg =
				(struct lananlmsg_bind *) lmsg->buff;
			fb1 = search_fblock_n(msg->name1);
			if (!fb1)
				return -EINVAL;
			fb2 = search_fblock_n(msg->name2);
			if (!fb2) {
				put_fblock(fb1);
				return -EINVAL;
			}
			ret = fblock_bind(fb1, fb2);
			if (ret) {
				put_fblock(fb1);
				put_fblock(fb2);
				return ret;
			}
			put_fblock(fb1);
			put_fblock(fb2);
		} break;
	case NETLINK_USERCTL_CMD_UNBIND: {
			int ret;
			struct fblock *fb1, *fb2;
			struct lananlmsg_unbind *msg =
				(struct lananlmsg_unbind *) lmsg->buff;
			fb1 = search_fblock_n(msg->name1);
			if (!fb1)
				return -EINVAL;
			fb2 = search_fblock_n(msg->name2);
			if (!fb2) {
				put_fblock(fb1);
				return -EINVAL;
			}
			ret = fblock_unbind(fb1, fb2);
			if (ret) {
				put_fblock(fb1);
				put_fblock(fb2);
				return ret;
			}
			put_fblock(fb1);
			put_fblock(fb2);
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

