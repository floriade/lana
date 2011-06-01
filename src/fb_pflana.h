/*
 * Lightweight Autonomic Network Architecture
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#ifndef FB_PFLANA_H
#define FB_PFLANA_H

#define AF_LANA         27      /* For now.. */
#define PF_LANA         AF_LANA

/* LANA protocol types on top of the PF_LANA family */
#define LANA_PROTO_RAW  0
#define LANA_NPROTO     1

#ifdef __KERNEL__

/* Protocols in LANA family */
struct lana_protocol {
	int proto;
	const struct proto_ops *ops;
	struct proto *prot;
};

extern int pflana_proto_register(int proto, struct lana_protocol *lp);
extern void pflana_proto_unregister(struct lana_protocol *lp);

#endif /* __KERNEL__ */
#endif /* FB_PFLANA_H */

