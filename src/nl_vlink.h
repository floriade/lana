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
#include <linux/netlink.h>
#include <linux/if.h>

#define NETLINK_VLINK_RX_OK     0  /* Receive went okay, notify next     */
#define NETLINK_VLINK_RX_NXT    1  /* Receive is not for us, notify next */
#define NETLINK_VLINK_RX_BAD    2  /* Receive failed, notify next        */
#define NETLINK_VLINK_RX_EMERG  3  /* Receive failed, do not notify next */
#define NETLINK_VLINK_RX_STOP   4  /* Receive went okay, but still stop  */

#define NETLINK_VLINK_PRIO_LOW  0  /* Low priority callbacks             */
#define NETLINK_VLINK_PRIO_NORM 1  /* Normal priority callbacks          */
#define NETLINK_VLINK_PRIO_HIGH 2  /* High priority callbacks            */

#endif /* __KERNEL__ */

#define NETLINK_VLINK          23  /* Netlink hook type                  */

enum nl_vlink_groups {
	VLINKNLGRP_NONE = NLMSG_MIN_TYPE, /* Reserved                    */
#define VLINKNLGRP_NONE         VLINKNLGRP_NONE
	VLINKNLGRP_ETHERNET,       /* To vlink Ethernet type             */
#define VLINKNLGRP_ETHERNET     VLINKNLGRP_ETHERNET
	VLINKNLGRP_BLUETOOTH,      /* To vlink Bluetooth type            */
#define VLINKNLGRP_BLUETOOTH    VLINKNLGRP_BLUETOOTH
	VLINKNLGRP_INFINIBAND,     /* To vlink InfiniBand type           */
#define VLINKNLGRP_INFINIBAND   VLINKNLGRP_INFINIBAND
	VLINKNLGRP_I2C,            /* To vlink I^2C type                 */
#define VLINKNLGRP_I2C          VLINKNLGRP_I2C
	__VLINKNLGRP_MAX
};
#define VLINKNLGRP_MAX          (__VLINKNLGRP_MAX - 1)

enum nl_vlink_cmd {
	VLINKNLCMD_ADD_DEVICE,
	VLINKNLCMD_RM_DEVICE,
	VLINKNLCMD_BIND_DEVICE,
	/* ... */
};

struct vlinknlmsg {
	uint8_t cmd;
	uint8_t flags;
	uint8_t type;
	uint8_t virt_name[IFNAMSIZ];
	uint8_t real_name[IFNAMSIZ];
	/* ... */
};

#ifdef __KERNEL__

#define MAX_VLINK_SUBSYSTEMS  256

struct nl_vlink_callback {
	int priority;
	int (*rx)(struct vlinknlmsg *vhdr, struct nlmsghdr *nlh);
	struct nl_vlink_callback *next;
};

#define NL_VLINK_CALLBACK_INIT(fct, prio) {		\
	.rx = (fct),					\
	.priority = (prio),				\
	.next = NULL, }

struct nl_vlink_subsys {
	char *name;
	u32 type:16,
	    id:16;
	struct rw_semaphore rwsem;
	struct nl_vlink_callback *head;
};

#define NL_VLINK_SUBSYS_INIT(varname, sysname, gtype) {	\
	.name = (sysname),				\
	.type = (gtype),				\
	.rwsem = __RWSEM_INITIALIZER((varname).rwsem),	\
	.head = NULL, }

extern void nl_vlink_lock(void);
extern void nl_vlink_unlock(void);

extern int nl_vlink_subsys_register(struct nl_vlink_subsys *n);
extern void nl_vlink_subsys_unregister(struct nl_vlink_subsys *n);
extern void nl_vlink_subsys_unregister_batch(struct nl_vlink_subsys *n);
extern struct nl_vlink_subsys *nl_vlink_subsys_find(u16 type);
extern int nl_vlink_add_callback(struct nl_vlink_subsys *n,
				 struct nl_vlink_callback *cb);
extern int nl_vlink_add_callbacks(struct nl_vlink_subsys *n,
				  struct nl_vlink_callback *cb, ...);
extern int nl_vlink_add_callbacks_va(struct nl_vlink_subsys *n,
				     struct nl_vlink_callback *cb,
				     va_list ap);
extern int nl_vlink_rm_callback(struct nl_vlink_subsys *n,
				struct nl_vlink_callback *cb);

#endif /* __KERNEL__ */
#endif /* NL_VLINK */

