/*
 * Lightweight Autonomic Network Architecture
 *
 * LANA vlink control messages via netlink socket. This allows userspace
 * applications like 'vlink' to control the whole LANA vlink layer. Each
 * vlink type (e.g. Ethernet, Bluetooth, ...) gets its own subsystem with
 * its operations. Access via a single socket type (NETLINK_VLINK). We are
 * furthermore not in fast-path here.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/sock.h>

#include "nl_vlink.h"

static DEFINE_MUTEX(nl_vlink_mutex);
static struct sock *nl_vlink_sock = NULL;
static struct nl_vlink_subsys **vlink_subsystem_table = NULL;

void nl_vlink_lock(void)
{
	mutex_lock(&nl_vlink_mutex);
}
EXPORT_SYMBOL_GPL(nl_vlink_lock);

void nl_vlink_unlock(void)
{
	mutex_unlock(&nl_vlink_mutex);
}
EXPORT_SYMBOL_GPL(nl_vlink_unlock);

int nl_vlink_subsys_register(struct nl_vlink_subsys *n)
{
	int i, slot;
	struct nl_vlink_subsys *vs;

	if (!n)
		return -EINVAL;

	nl_vlink_lock();

	for (i = 0, slot = -1; i < MAX_VLINK_SUBSYSTEMS; ++i) {
		if (!vlink_subsystem_table[i] && slot == -1)
			slot = i;
		else if (!vlink_subsystem_table[i])
			continue;
		else {
			vs = vlink_subsystem_table[i];
			if (n->type == vs->type) {
				nl_vlink_unlock();
				/* We already have this subsystem loaded! */
				return -EBUSY;
			}
		}
	}

	if (slot != -1) {
		n->id = slot;
		vlink_subsystem_table[slot] = n;
	}

	nl_vlink_unlock();

	return slot == -1 ? -ENOMEM : 0;
}
EXPORT_SYMBOL_GPL(nl_vlink_subsys_register);

int nl_vlink_subsys_unregister(struct nl_vlink_subsys *n)
{
	int i, gotit;

	if (!n)
		return -EINVAL;

	nl_vlink_lock();

	for (i = gotit = 0; i < MAX_VLINK_SUBSYSTEMS; ++i) {
		if (vlink_subsystem_table[i] == n && i == n->id) {
			vlink_subsystem_table[i] = NULL;
			n->id = 0;
			gotit = 1;
		}
	}

	nl_vlink_unlock();

	return gotit ? 0 : -ENOENT;
}
EXPORT_SYMBOL_GPL(nl_vlink_subsys_unregister);

static int __nl_vlink_rcv(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	if (security_netlink_recv(skb, CAP_NET_ADMIN))
		return -EPERM;

	printk("hello tiny world\n");
	return 0;
}

static void nl_vlink_rcv(struct sk_buff *skb)
{
	nl_vlink_lock();
	netlink_rcv_skb(skb, &__nl_vlink_rcv);
	nl_vlink_unlock();
}

static int __init init_nl_vlink_module(void)
{
	int ret;

	vlink_subsystem_table = kzalloc(sizeof(*vlink_subsystem_table) *
					MAX_VLINK_SUBSYSTEMS, GFP_KERNEL);
	if (!vlink_subsystem_table)
		return -ENOMEM;

	nl_vlink_sock = netlink_kernel_create(&init_net, NETLINK_VLINK,
					      VLINKNLGRP_MAX, nl_vlink_rcv,
					      NULL, THIS_MODULE);
	if (!nl_vlink_sock) {
		ret = -ENOMEM;
		goto err;
	}

	printk(KERN_INFO "LANA netlink vlink layer loaded!\n");
	return 0;

err:
	kfree(vlink_subsystem_table);
	return ret;
}

static void __exit cleanup_nl_vlink_module(void)
{
	netlink_kernel_release(nl_vlink_sock);
	kfree(vlink_subsystem_table);

	printk(KERN_INFO "LANA netlink vlink layer removed!\n");
}

module_init(init_nl_vlink_module);
module_exit(cleanup_nl_vlink_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("Netlink subsystem for LANA virtual link layer drivers");

