/*
 * Lightweight Autonomic Network Architecture
 *
 * LANA vlink control messages via netlink socket. This allows userspace
 * applications like 'vlink' to control the whole LANA vlink layer. Each
 * vlink type (e.g. Ethernet, Bluetooth, ...) gets its own subsystem with
 * its operations. Access via a single socket type (NETLINK_VLINK).
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/module.h>
#include <linux/kernel.h>

#include "nl_vlink.h"

static DEFINE_MUTEX(nl_vlink_mutex);
static struct sock *nl_vlink_sock; /* Fixme! */

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

int nl_vlink_subsys_register(const struct nl_vlink_subsys *n)
{
	nl_vlink_lock();
	/* Link in */
	nl_vlink_unlock();

	return 0;
}
EXPORT_SYMBOL_GPL(nl_vlink_subsys_register);

int nl_vlink_subsys_unregister(const struct nl_vlink_subsys *n)
{
	nl_vlink_lock();
	/* Link out */
	nl_vlink_unlock();

	return 0;
}
EXPORT_SYMBOL_GPL(nl_vlink_subsys_unregister);

static int __nl_vlink_rcv(struct sk_buff *skb, struct nlmsghdr *nlh)
{
}

static void nl_vlink_rcv(struct sk_buff *skb)
{
	nl_vlink_lock();
	netlink_rcv_skb(skb, &__nl_vlink_rcv);
	nl_vlink_unlock();
}

static int __net_init nl_vlink_net_init(struct net *net)
{
	nl_vlink_sock = netlink_kernel_create(net, NETLINK_VLINK, 0,
					      nl_vlink_rcv, NULL, THIS_MODULE);
	if (!nl_vlink_sock)
		return -ENOMEM;
	return 0;
}

static void __net_exit nl_vlink_net_exit_batch(struct list_head *net_exit_list)
{
	struct net *net;

	list_for_each_entry(net, net_exit_list, exit_list)
		netlink_kernel_release(net->nfnl_stash);
}

static struct pernet_operations nl_vlink_net_ops = {
	.init       = nl_vlink_net_init,
	.exit_batch = nl_vlink_net_exit_batch,
};

static int __init init_nl_vlink_module(void)
{
	printk(KERN_INFO "LANA netlink vlink layer loaded!\n");
	return register_pernet_subsys(&nl_vlink_net_ops);
}

static void __exit cleanup_nl_vlink_module(void)
{
	unregister_pernet_subsys(&nl_vlink_net_ops);
	printk(KERN_INFO "LANA netlink vlink layer removed!\n");
}

module_init(init_nl_vlink_module);
module_exit(cleanup_nl_vlink_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("Netlink subsystem for LANA virtual link layer drivers");

