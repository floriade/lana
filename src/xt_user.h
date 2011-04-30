/*
 * Lightweight Autonomic Network Architecture
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#ifndef XT_USER_H
#define XT_USER_H

#include <linux/types.h>

#include "xt_vlink.h"
#include "xt_fblock.h"

#define NETLINK_USERCTL 24

enum userctl_groups {
	USERCTLGRP_NONE = VLINKNLGRP_MAX, /* Reserved */
#define USERCTLGRP_NONE		USERCTLGRP_NONE
	USERCTLGRP_CONF,
#define USERCTLGRP_CONF		USERCTLGRP_CONF
	 __USERCTLGRP_MAX
};

#define USERCTLGRP_MAX		(__USERCTLGRP_MAX - 1)
#define USERCTL_BUF_LEN         1500

#define NETLINK_USERCTL_CMD_ADD		1
#define NETLINK_USERCTL_CMD_SET		2
#define NETLINK_USERCTL_CMD_RM		3
#define NETLINK_USERCTL_CMD_BIND	4
#define NETLINK_USERCTL_CMD_UNBIND	5
#define NETLINK_USERCTL_CMD_REPLACE	6
#define NETLINK_USERCTL_CMD_SUBSCRIBE	7
#define NETLINK_USERCTL_CMD_UNSUBSCRIBE	8

struct lananlmsg_add {
	char name[FBNAMSIZ];
	char type[TYPNAMSIZ];
};

struct lananlmsg_rm {
	char name[FBNAMSIZ];
};

struct lananlmsg_set {
	char name[FBNAMSIZ];
	/* 0-terminated string, e.g. "myip=192.168.1.111" */
	char option[USERCTL_BUF_LEN - FBNAMSIZ];
};

struct lananlmsg_bind {
	char name1[FBNAMSIZ];
	char name2[FBNAMSIZ];
};

struct lananlmsg_unbind {
	char name1[FBNAMSIZ];
	char name2[FBNAMSIZ];
};

struct lananlmsg_replace {
	char name1[FBNAMSIZ];
	char name2[FBNAMSIZ];
	int drop_priv;
};

struct lananlmsg_subscribe {
	char name1[FBNAMSIZ];
	char name2[FBNAMSIZ];
};

struct lananlmsg_unsubscribe {
	char name1[FBNAMSIZ];
	char name2[FBNAMSIZ];
};

extern int init_userctl_system(void);
extern void cleanup_userctl_system(void);

struct lananlmsg {
	uint32_t cmd;
	uint8_t buff[USERCTL_BUF_LEN];
};

#endif /* XT_USER_H */

