/*
 * Lightweight Autonomic Network Architecture
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#ifndef XT_ENGINE_H
#define XT_ENGINE_H

#include <linux/skbuff.h>
#include "xt_fblock.h"

#define PPE_SUCCESS             0
#define PPE_DROPPED             1
#define PPE_ERROR               2

extern int process_packet(struct sk_buff *skb, enum path_type dir);

#endif /* XT_ENGINE_H */

