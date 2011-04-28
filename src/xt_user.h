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

#define NETLINK_USERCTL 24

enum userctl_groups {
	USERCTLGRP_NONE = VLINKNLGRP_MAX, /* Reserved                    */
#define USERCTLGRP_NONE		USERCTLGRP_NONE
	USERCTLGRP_CONF,
#define USERCTLGRP_CONF		USERCTLGRP_CONF
	 __USERCTLGRP_MAX
};

#define USERCTLGRP_MAX		(__USERCTLGRP_MAX - 1)

struct lananlmsg {
	u32 cmd;
	char buff[1500];
};

extern int init_userctl_system(void);
extern void cleanup_userctl_system(void);

#endif /* XT_USER_H */

