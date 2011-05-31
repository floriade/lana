/*
 * Lightweight Autonomic Network Architecture
 *
 * LANA packet processing engines. Incoming packtes are scheduled onto one
 * of the CPU-affine engines and processed on the Functional Block stack.
 * There are two queues where packets can be added, one from PHY direction
 * for incoming packets (ingress) and one from the socket handler direction
 * for outgoing packets (egress). Support for NUMA-affinity added.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/kernel.h>
#include <linux/skbuff.h>

#include "xt_engine.h"
#include "xt_skb.h"
#include "xt_fblock.h"

/* Main function, must be called in rcu_read_lock context */
int process_packet(struct sk_buff *skb, enum path_type dir)
{
	int ret = PPE_ERROR;
	idp_t cont;
	struct fblock *fb;
	while ((cont = read_next_idp_from_skb(skb))) {
		fb = __search_fblock(cont);
		if (unlikely(!fb)) {
			ret = PPE_ERROR;
			break;
		}
		ret = fb->netfb_rx(fb, skb, &dir);
		put_fblock(fb);
		if (ret == PPE_DROPPED) {
			ret = PPE_DROPPED;
			break;
		}
	}
	return ret;
}
EXPORT_SYMBOL_GPL(process_packet);

