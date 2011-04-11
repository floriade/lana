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

#include "xt_vlink.h"

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
		smp_wmb();
		vlink_subsystem_table[slot] = n;
	}

	nl_vlink_unlock();

	return slot == -1 ? -ENOMEM : 0;
}
EXPORT_SYMBOL_GPL(nl_vlink_subsys_register);

void nl_vlink_subsys_unregister(struct nl_vlink_subsys *n)
{
	int i;

	if (!n)
		return;

	nl_vlink_lock();

	for (i = 0; i < MAX_VLINK_SUBSYSTEMS; ++i) {
		if (vlink_subsystem_table[i] == n && i == n->id) {
			vlink_subsystem_table[i] = NULL;
			n->id = 0;
			break;
		}
	}

	nl_vlink_unlock();
}
EXPORT_SYMBOL_GPL(nl_vlink_subsys_unregister);

static struct nl_vlink_subsys *__nl_vlink_subsys_find(u16 type)
{
	int i;

	for (i = 0; i < MAX_VLINK_SUBSYSTEMS; ++i)
		if (vlink_subsystem_table[i])
			if (vlink_subsystem_table[i]->type == type)
				return vlink_subsystem_table[i];
	return NULL;
}

struct nl_vlink_subsys *nl_vlink_subsys_find(u16 type)
{
	struct nl_vlink_subsys *ret;

	nl_vlink_lock();
	ret = __nl_vlink_subsys_find(type);
	nl_vlink_unlock();

	return ret;
}
EXPORT_SYMBOL_GPL(nl_vlink_subsys_find);

static int __nl_vlink_add_callback(struct nl_vlink_subsys *n,
				   struct nl_vlink_callback *cb)
{
	struct nl_vlink_callback **hb;

	if (!cb)
		return -EINVAL;

	hb = &n->head;
	while (*hb != NULL) {
		if (cb->priority > (*hb)->priority)
			break;
		hb = &((*hb)->next);
	}

	cb->next = *hb;
	smp_wmb();
	*hb = cb;

	return 0;
}

int nl_vlink_add_callback(struct nl_vlink_subsys *n,
			  struct nl_vlink_callback *cb)
{
	int ret;

	if (!n)
		return -EINVAL;

	down_write(&n->rwsem);
	ret = __nl_vlink_add_callback(n, cb);
	up_write(&n->rwsem);

	return ret;
}
EXPORT_SYMBOL_GPL(nl_vlink_add_callback);

int nl_vlink_add_callbacks_va(struct nl_vlink_subsys *n,
			      struct nl_vlink_callback *cb, va_list ap)
{
	int ret = 0;
	struct nl_vlink_callback *arg;

	arg = cb;
	while (arg) {
		ret = nl_vlink_add_callback(n, arg);
		if (ret)
			break;
		arg = va_arg(ap, struct nl_vlink_callback *);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(nl_vlink_add_callbacks_va);

int nl_vlink_add_callbacks(struct nl_vlink_subsys *n,
			   struct nl_vlink_callback *cb, ...)
{
	int ret;
	va_list vl;

	va_start(vl, cb);
	ret = nl_vlink_add_callbacks_va(n, cb, vl);
	va_end(vl);

	return ret;
}
EXPORT_SYMBOL_GPL(nl_vlink_add_callbacks);

static int __nl_vlink_rm_callback(struct nl_vlink_subsys *n,
				  struct nl_vlink_callback *cb)
{
	struct nl_vlink_callback **hb;

	if (!cb)
		return -EINVAL;

	hb = &n->head;
	while (*hb != NULL) {
		if (*hb == cb) {
			smp_wmb();
			*hb = cb->next;
			return 0;
		}
		hb = &((*hb)->next);
	}

	return -ENOENT;
}

int nl_vlink_rm_callback(struct nl_vlink_subsys *n,
			 struct nl_vlink_callback *cb)
{
	int ret;

	if (!n)
		return -EINVAL;

	down_write(&n->rwsem);
	ret = __nl_vlink_rm_callback(n, cb);
	up_write(&n->rwsem);

	return ret;
}
EXPORT_SYMBOL_GPL(nl_vlink_rm_callback);

void nl_vlink_subsys_unregister_batch(struct nl_vlink_subsys *n)
{
	int i;

	if (!n)
		return;

	nl_vlink_lock();

	for (i = 0; i < MAX_VLINK_SUBSYSTEMS; ++i) {
		if (vlink_subsystem_table[i] == n && i == n->id) {
			vlink_subsystem_table[i] = NULL;
			n->id = 0;
			break;
		}
	}

	nl_vlink_unlock();

	/* Now, we cannot be invoked anymore */
	while (n-> head != NULL)
		nl_vlink_rm_callback(n, n->head);
}
EXPORT_SYMBOL_GPL(nl_vlink_subsys_unregister_batch);

static int __nl_vlink_invoke(struct nl_vlink_subsys *n,
			     struct vlinknlmsg *vmsg,
			     struct nlmsghdr *nlh)
{
	int ret;
	struct nl_vlink_callback *hb, *hn;

	smp_read_barrier_depends();
	hb = n->head;

	while (hb) {
		smp_read_barrier_depends();
		hn = hb->next;

		ret = hb->rx(vmsg, nlh);
		if ((ret & NETLINK_VLINK_RX_EMERG) ==
		    NETLINK_VLINK_RX_EMERG ||
		    (ret & NETLINK_VLINK_RX_STOP) ==
		    NETLINK_VLINK_RX_STOP)
			break;
		hb = hn;
	}

	return ret;
}

static int __nl_vlink_rcv(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int ret;
	struct vlinknlmsg *vmsg;
	struct nl_vlink_subsys *sys;

	if (security_netlink_recv(skb, CAP_NET_ADMIN))
		return -EPERM;

	if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct vlinknlmsg)))
		return 0;

	sys = __nl_vlink_subsys_find(nlh->nlmsg_type);
	if (!sys)
		return -EINVAL;

	vmsg = NLMSG_DATA(nlh);

	down_read(&sys->rwsem);
	ret = __nl_vlink_invoke(sys, vmsg, nlh);
	up_read(&sys->rwsem);

	return ret;
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

	printk(KERN_INFO "[lana] NETLINK vlink layer loaded!\n");
	return 0;

err:
	kfree(vlink_subsystem_table);
	return ret;
}

static void __exit cleanup_nl_vlink_module(void)
{
	netlink_kernel_release(nl_vlink_sock);
	kfree(vlink_subsystem_table);

	printk(KERN_INFO "[lana] NETLINK vlink layer removed!\n");
}

module_init(init_nl_vlink_module);
module_exit(cleanup_nl_vlink_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("Netlink subsystem for LANA virtual link layer drivers");

