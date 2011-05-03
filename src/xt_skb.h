/*
 * Lightweight Autonomic Network Architecture
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#ifndef XT_SKB_H
#define XT_SKB_H

#include <linux/skbuff.h>
#include "xt_idp.h"

#define MARKER_TIME_MARKED_FIRST	(1 << 0)
#define MARKER_TIME_MARKED_LAST		(1 << 1)

struct sock_lana_inf {
	idp_t   idp_dst;
	idp_t   idp_src;
	__u32   flags;
	__u32   errno;
	__u32   marker;
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

static inline void time_mark_skb_last(struct sk_buff *skb)
{
	struct sock_lana_inf *sli = SKB_LANA_INF(skb);
	sli->marker |= MARKER_TIME_MARKED_LAST;
}

static inline int skb_is_time_marked_last(struct sk_buff *skb)
{
	return (SKB_LANA_INF(skb)->marker &
		MARKER_TIME_MARKED_LAST) == MARKER_TIME_MARKED_LAST;
}

static inline void time_mark_skb_first(struct sk_buff *skb)
{
	struct sock_lana_inf *sli = SKB_LANA_INF(skb);
	sli->marker |= MARKER_TIME_MARKED_FIRST;
}

static inline int skb_is_time_marked_first(struct sk_buff *skb)
{
	return (SKB_LANA_INF(skb)->marker &
		MARKER_TIME_MARKED_FIRST) == MARKER_TIME_MARKED_FIRST;
}

#endif /* XT_SKB_H */

