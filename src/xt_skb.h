/*
 * Lightweight Autonomic Network Architecture
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#ifndef XT_SKB
#define XT_SKB

#include <linux/skbuff.h>
#include "xt_idp.h"

static inline void write_next_idp_to_skb(struct sk_buff *skb, idp_t idp)
{
	memcpy(&skb->cb[sizeof(skb->cb) - sizeof(idp) - 1], &idp, sizeof(idp));
}

static inline idp_t read_next_idp_from_skb(struct sk_buff *skb)
{
	idp_t idp;
	memcpy(&idp, &skb->cb[sizeof(skb->cb) - sizeof(idp) - 1], sizeof(idp));
	return idp;
}

#endif /* XT_SKB */

