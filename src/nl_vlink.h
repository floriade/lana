/*
 * Lightweight Autonomic Network Architecture
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#ifndef NL_VLINK
#define NL_VLINK

#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/rwsem.h>

#define NETLINK_VLINK_RX_OK     0  /* Receive went okay, notify next */
#define NETLINK_VLINK_RX_BAD    1  /* Receive failed, notify next */
#define NETLINK_VLINK_RX_EMERG  2  /* Receive failed, do not notify next */

#define NETLINK_VLINK_PRIO_LOW  0  /* Low priority callbacks */
#define NETLINK_VLINK_PRIO_NORM 1  /* Normal priority callbacks */
#define NETLINK_VLINK_PRIO_HIGH 2  /* High priority callbacks */

#endif /* __KERNEL__ */

#define NETLINK_VLINK           0xCAFE /* This is what holds us together! */

/* Can be OR'ed from userspace for addressing several subsystems */
#define VLINK_ETHERNET          1  /* Vlink Ethernet type */
#define VLINK_BLUETOOTH         2  /* Vlink Bluetooth type */
#define VLINK_INFINIBAND        4  /* Vlink InfiniBand type */
#define VLINK_I2C               8  /* Vlink I^2C type */

#ifdef __KERNEL__

struct nl_vlink_callback {
	int priority;
	int (*rx)(struct sk_buff *skb, int cmd, struct nlmsghdr *nlh);
	struct nl_vlink_callback *next;
};

#define NL_VLINK_CALLBACK_INIT(fct, prio) {			\
	.rx = (fct),						\
	.priority = (prio),					\
	.next = NULL, }

struct nl_vlink_subsys {
	char *name;
	u16 type;
	u8 __id;
	u8 __count;
	struct rw_semaphore __rwsem;
	struct nl_vlink_callback *__head;
};

#define NL_VLINK_SUBSYS_INIT(varname, sysname, type) {		\
	.name = (sysname),					\
	.type = (type),						\
	.__count = 0,						\
	.__rwsem = __RWSEM_INITIALIZER((varname).__rwsem),	\
	.__head = NULL, }

extern void nl_vlink_lock(void);
extern void nl_vlink_unlock(void);

extern int nl_vlink_subsys_register(const struct nl_vlink_subsys *n);
extern int nl_vlink_subsys_unregister(const struct nl_vlink_subsys *n);

#endif /* __KERNEL__ */
#endif /* NL_VLINK */

