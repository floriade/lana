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
#define LANA_PROTO_AUTO	0
#define LANA_PROTO_RAW  1
#define LANA_NPROTO     2

#ifdef __KERNEL__

/* Protocols in LANA family */
struct lana_protocol {
	int protocol;
	const struct proto_ops *ops;
	struct proto *proto;
	struct module *owner;
};

extern int pflana_proto_register(int proto, struct lana_protocol *lp);
extern void pflana_proto_unregister(struct lana_protocol *lp);

extern int lana_common_release(struct socket *sock);
extern int lana_common_stream_recvmsg(struct kiocb *iocb, struct socket *sock,
				      struct msghdr *msg, size_t len, int flags);

#endif /* __KERNEL__ */
#endif /* FB_PFLANA_H */

