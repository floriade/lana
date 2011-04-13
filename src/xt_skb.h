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

struct sock_lana_inf {
	idp_t   idp_dst;
	idp_t   idp_src;
	__u32   flags;
	__u32   errno;
};

#define SKB_LANA_INF(skb) ((struct sock_lana_inf *) ((skb)->cb))

static inline void write_next_idp_to_skb(struct sk_buff *skb, idp_t from,
					 idp_t to)
{
	struct sock_lana_inf *sli = SKB_LANA_INF(skb);
	sli->idp_dst = to;
	sli->idp_src = from;
}

static inline idp_t read_next_idp_from_skb(struct sk_buff *skb)
{
	return SKB_LANA_INF(skb)->idp_dst;
}

#endif /* XT_SKB */

