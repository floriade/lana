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
#include <linux/rcupdate.h>
#include <net/netlink.h>
#include <net/sock.h>

#include "xt_idp.h"
#include "xt_user.h"
#include "xt_fblock.h"
#include "xt_builder.h"

static struct sock *userctl_sock = NULL;

static int userctl_add(struct lananlmsg *lmsg)
{
	struct fblock *fb;
	struct lananlmsg_add *msg = (struct lananlmsg_add *) lmsg->buff;

	fb = search_fblock_n(msg->name);
	if (fb) {
		put_fblock(fb);
		return -EINVAL;
	}

	fb = build_fblock_object(msg->type, msg->name);

	return !fb ? -ENOMEM : 0;
}

static int userctl_set(struct lananlmsg *lmsg)
{
	int ret;
	struct fblock *fb;
	struct lananlmsg_set *msg = (struct lananlmsg_set *) lmsg->buff;

	fb = search_fblock_n(msg->name);
	if (!fb)
		return -EINVAL;

	ret = fblock_set_option(fb, msg->option);

	put_fblock(fb);

	return ret;
}

static int userctl_replace(struct lananlmsg *lmsg)
{
	int ret;
	struct fblock *fb1, *fb2;
	struct lananlmsg_replace *msg =	(struct lananlmsg_replace *) lmsg->buff;

	/*
	 * XXX: vlink blocks may not be replaced during runtime, since they
	 * are directly bound to hardware. Fuckup? Yes or no? Too many side
	 * effects. These blocks should not be changed anyway.
	 */

	fb1 = search_fblock_n(msg->name1);
	if (!fb1 || !fb1->factory)
		return -EINVAL;

	fb2 = search_fblock_n(msg->name2);
	if (!fb2 || !fb2->factory) {
		put_fblock(fb1);
		return -EINVAL;
	}

	if (atomic_read(&fb2->refcnt) > 2) {
		/* Still in use by others */
		printk(KERN_ERR "[lana] %s is still in use by others. "
		       "Drop refs first!\n", fb2->name);
		put_fblock(fb1);
		put_fblock(fb2);
		return -EBUSY;
	}

	unregister_fblock_namespace_no_rcu(fb2);

	if (!strncmp(fb1->factory->type, fb2->factory->type,
		     sizeof(fb1->factory->type)) && !msg->drop_priv)
		fblock_migrate_p(fb2, fb1);
	fblock_migrate_r(fb2, fb1);

	unregister_fblock(fb1);

	ret = register_fblock(fb2, fb2->idp);

	put_fblock(fb1);
	put_fblock(fb2);

	return ret;
}

static int userctl_subscribe(struct lananlmsg *lmsg)
{
	int ret;
	struct fblock *fb1, *fb2;
	struct lananlmsg_tuple *msg = (struct lananlmsg_tuple *) lmsg->buff;

	fb1 = search_fblock_n(msg->name1);
	if (!fb1)
		return -EINVAL;

	fb2 = search_fblock_n(msg->name2);
	if (!fb2) {
		put_fblock(fb1);
		return -EINVAL;
	}
	/*
	 * fb1 is remote block, fb2 is the one that
	 * wishes to be notified.
	 */
	ret = subscribe_to_remote_fblock(fb2, fb1);

	put_fblock(fb1);
	put_fblock(fb2);

	return ret;
}

static int userctl_unsubscribe(struct lananlmsg *lmsg)
{
	struct fblock *fb1, *fb2;
	struct lananlmsg_tuple *msg = (struct lananlmsg_tuple *) lmsg->buff;

	fb1 = search_fblock_n(msg->name1);
	if (!fb1)
		return -EINVAL;

	fb2 = search_fblock_n(msg->name2);
	if (!fb2) {
		put_fblock(fb1);
		return -EINVAL;
	}

	unsubscribe_from_remote_fblock(fb2, fb1);

	put_fblock(fb1);
	put_fblock(fb2);

	return 0;
}

static int userctl_remove(struct lananlmsg *lmsg)
{
	struct fblock *fb;
	struct lananlmsg_rm *msg = (struct lananlmsg_rm *) lmsg->buff;

	fb = search_fblock_n(msg->name);
	if (!fb)
		return -EINVAL;
	if (!fb->factory) {
		/* vlink types have no factory */
		put_fblock(fb);
		return -EINVAL;
	}

	if (atomic_read(&fb->refcnt) > 2) {
		/* Still in use by others */
		put_fblock(fb);
		return -EBUSY;
	}

	unregister_fblock_namespace(fb);
	put_fblock(fb);

	return 0;
}

static int userctl_bind(struct lananlmsg *lmsg)
{
	int ret;
	struct fblock *fb1, *fb2;
	struct lananlmsg_tuple *msg = (struct lananlmsg_tuple *) lmsg->buff;

	fb1 = search_fblock_n(msg->name1);
	if (!fb1)
		return -EINVAL;

	fb2 = search_fblock_n(msg->name2);
	if (!fb2) {
		put_fblock(fb1);
		return -EINVAL;
	}

	ret = fblock_bind(fb1, fb2);

	put_fblock(fb1);
	put_fblock(fb2);

	return ret;
}

static int userctl_unbind(struct lananlmsg *lmsg)
{
	int ret;
	struct fblock *fb1, *fb2;
	struct lananlmsg_tuple *msg = (struct lananlmsg_tuple *) lmsg->buff;

	fb1 = search_fblock_n(msg->name1);
	if (!fb1)
		return -EINVAL;

	fb2 = search_fblock_n(msg->name2);
	if (!fb2) {
		put_fblock(fb1);
		return -EINVAL;
	}

	ret = fblock_unbind(fb1, fb2);

	put_fblock(fb1);
	put_fblock(fb2);

	return ret;
}

static int __userctl_rcv(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int ret = 0;
	struct lananlmsg *lmsg;

	if (security_netlink_recv(skb, CAP_NET_ADMIN))
		return -EPERM;
	if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct lananlmsg)))
		return 0;

	lmsg = NLMSG_DATA(nlh);

	switch (lmsg->cmd) {
	case NETLINK_USERCTL_CMD_ADD:
		ret = userctl_add(lmsg);
		break;
	case NETLINK_USERCTL_CMD_SET:
		ret = userctl_set(lmsg);
		break;
	case NETLINK_USERCTL_CMD_REPLACE:
		ret = userctl_replace(lmsg);
		break;
	case NETLINK_USERCTL_CMD_SUBSCRIBE:
		ret = userctl_subscribe(lmsg);
		break;
	case NETLINK_USERCTL_CMD_UNSUBSCRIBE:
		ret = userctl_unsubscribe(lmsg);
		break;
	case NETLINK_USERCTL_CMD_RM:
		ret = userctl_remove(lmsg);
		break;
	case NETLINK_USERCTL_CMD_BIND:
		ret = userctl_bind(lmsg);
		break;
	case NETLINK_USERCTL_CMD_UNBIND:
		ret = userctl_unbind(lmsg);
		break;
	default:
		printk(KERN_INFO "[lana] Unknown command!\n");
		ret = -ENOENT;
		break;
	}

	return ret;
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
	return !userctl_sock ? -ENOMEM : 0;
}
EXPORT_SYMBOL_GPL(init_userctl_system);

void cleanup_userctl_system(void)
{
	netlink_kernel_release(userctl_sock);
}
EXPORT_SYMBOL_GPL(cleanup_userctl_system);

