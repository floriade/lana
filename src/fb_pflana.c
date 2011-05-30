/*
 * Lightweight Autonomic Network Architecture
 *
 * PF_LANA userspace module.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/notifier.h>
#include <linux/rcupdate.h>
#include <linux/seqlock.h>
#include <linux/percpu.h>
#include <linux/prefetch.h>
#include <net/sock.h>

#include "xt_fblock.h"
#include "xt_builder.h"
#include "xt_idp.h"
#include "xt_skb.h"
#include "xt_engine.h"
#include "xt_builder.h"

#define AF_LANA		27	/* For now.. */
#define PF_LANA		AF_LANA

struct fb_pflana_priv {
	idp_t port[NUM_TYPES];
	seqlock_t lock;
	struct lana_sock *sock_self; /* Only set on init, never changed! */
};

struct lana_sock {
	/* struct sock must be the first member of lana_sock */
	struct sock sk;
	struct fblock *fb;
	int bound;
	u32 copied_seq;
};

static struct fblock_factory fb_pflana_factory;
static struct proto lana_proto;
static const struct proto_ops lana_ui_ops;
static struct fblock *fb_pflana_ctor(char *name);
static int lana_ui_backlog_rcv(struct sock *sk, struct sk_buff *skb);

static int fb_pflana_netrx(const struct fblock * const fb,
			   struct sk_buff * const skb,
			   enum path_type * const dir)
{
	struct sock *sk;
	struct fb_pflana_priv __percpu *fb_priv_cpu;
	fb_priv_cpu = this_cpu_ptr(rcu_dereference_raw(fb->private_data));
	sk = (struct sock *) fb_priv_cpu->sock_self;
	sk_receive_skb(sk, skb, 0);
	return PPE_SUCCESS;
}

static int fb_pflana_event(struct notifier_block *self, unsigned long cmd,
			   void *args)
{
	return 0;
}

static struct fblock *get_bound_fblock(struct fblock *self, enum path_type dir)
{
	idp_t fbidp;
	unsigned int seq;
	struct fb_pflana_priv __percpu *fb_priv_cpu;
	fb_priv_cpu = this_cpu_ptr(rcu_dereference_raw(self->private_data));
	do {
		seq = read_seqbegin(&fb_priv_cpu->lock);
                fbidp = fb_priv_cpu->port[dir];
	} while (read_seqretry(&fb_priv_cpu->lock, seq));
	return search_fblock(fbidp);
}

static inline struct lana_sock *to_lana_sk(const struct sock *sk)
{
	return (struct lana_sock *) sk;
}

static void lana_ui_sk_init(struct socket *sock, struct sock *sk)
{
	sock_graft(sk, sock);
	sk->sk_type = sock->type;
	sock->ops = &lana_ui_ops;
}

static int lana_sk_init(struct sock* sk)
{
	int cpu;
	char name[256];
	struct lana_sock *lana = to_lana_sk(sk);

	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "%p", &lana->sk);
	lana->bound = 0;
	lana->copied_seq = 0;
	lana->fb = fb_pflana_ctor(name);
	if (!lana->fb)
		return -ENOMEM;
	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct fb_pflana_priv *fb_priv_cpu;
		fb_priv_cpu = per_cpu_ptr(lana->fb->private_data, cpu);
		fb_priv_cpu->sock_self = lana;
	}
	put_online_cpus();
	sk->sk_backlog_rcv = lana_ui_backlog_rcv;
	return 0;
}

static struct sock *lana_sk_alloc(struct net *net, int family, gfp_t priority,
				  struct proto *prot)
{
	struct sock *sk = sk_alloc(net, family, priority, prot);
	if (!sk)
		return NULL;
	if (lana_sk_init(sk) < 0) {
		sock_put(sk);
		return NULL;
	}
	sock_init_data(NULL, sk);
	return sk;
}

static void lana_sk_free(struct sock *sk)
{
	struct fblock *fb_bound;
	struct lana_sock *lana = to_lana_sk(sk);

	fb_bound = get_bound_fblock(lana->fb, TYPE_INGRESS);
	if (fb_bound) {
		fblock_unbind(fb_bound, lana->fb);
		put_fblock(fb_bound);
	}

	fb_bound = get_bound_fblock(lana->fb, TYPE_EGRESS);
	if (fb_bound) {
		fblock_unbind(lana->fb, fb_bound);
		put_fblock(fb_bound);
	}

	skb_queue_purge(&sk->sk_receive_queue);
	skb_queue_purge(&sk->sk_write_queue);
	sock_put(sk);
	unregister_fblock_namespace(lana->fb);
}

static int lana_ui_create(struct net *net, struct socket *sock, int protocol,
			  int kern)
{
	struct sock *sk;
	int rc = -ESOCKTNOSUPPORT;

	if (!net_eq(net, &init_net))
		return -EAFNOSUPPORT;
	if (likely(sock->type == SOCK_DGRAM ||
		   sock->type == SOCK_STREAM)) {
		rc = -ENOMEM;
		sk = lana_sk_alloc(net, PF_LANA, GFP_KERNEL, &lana_proto);
		if (sk) {
			rc = 0;
			lana_ui_sk_init(sock, sk);
		}
	}
	return rc;
}

int lana_ui_recvmsg(struct kiocb *iocb, struct socket *sock,
		    struct msghdr *msg, size_t len, int flags)
{
	int err;
	struct sk_buff *skb = NULL;
	struct sock *sk = sock->sk;
	size_t copied = 0;

	if (flags & (MSG_OOB))
		return -EOPNOTSUPP;
	skb = skb_recv_datagram(sk, flags, flags & MSG_DONTWAIT, &err);
	if (!skb) {
		if (sk->sk_shutdown & RCV_SHUTDOWN)
			return 0;
		return err;
	}
	msg->msg_namelen = 0;
	copied = skb->len;
	if (len < copied) {
		msg->msg_flags |= MSG_TRUNC;
		copied = len;
	}
	skb_reset_transport_header(skb);
	err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);
	if (err == 0)
		sock_recv_ts_and_drops(msg, sk, skb);
	skb_free_datagram(sk, skb);
	return err ? : copied;
}

static int lana_ui_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	int err;
	err = sock_queue_rcv_skb(sk, skb);
	if (err < 0)
		kfree_skb(skb);
	return err ? NET_RX_DROP : NET_RX_SUCCESS;
}

static int lana_ui_stream_recvmsg(struct kiocb *iocb, struct socket *sock,
				  struct msghdr *msg, size_t len, int flags)
{
	int err = 0;
	long timeout;
	size_t target, chunk, copied = 0;
	struct sock *sk = sock->sk;
	struct sk_buff *skb = NULL;

	msg->msg_namelen = 0;
	lock_sock(sk);
	timeout = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);
	do {
		skb = skb_dequeue(&sk->sk_receive_queue);
		if (!skb) {
			if (copied >= target)
				break;
			err = sock_error(sk);
			if (err)
				break;
			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;
			err = -EAGAIN;
			if (!timeout)
				break;
			timeout = sk_wait_data(sk, &timeout);
			if (signal_pending(current)) {
				err = sock_intr_errno(timeout);
				goto out;
			}
			continue;
		}
		chunk = min_t(size_t, skb->len, len);
		if (memcpy_toiovec(msg->msg_iov, skb->data, chunk)) {
			skb_queue_head(&sk->sk_receive_queue, skb);
			if (!copied)
				copied = -EFAULT;
			break;
		}
		copied += chunk;
		len -= chunk;
		sock_recv_ts_and_drops(msg, sk, skb);
		if (!(flags & MSG_PEEK)) {
			skb_pull(skb, chunk);
			if (skb->len) {
				skb_queue_head(&sk->sk_receive_queue, skb);
				break;
			}
			kfree_skb(skb);
		} else {
			/* put message back and return */
			skb_queue_head(&sk->sk_receive_queue, skb);
			break;
		}
	} while (len > 0);
out:
	release_sock(sk);
	return copied ? : err;
}

static int lana_ui_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (unlikely(sk == NULL))
		return 0;
	sock_hold(sk);
	lock_sock(sk);
	release_sock(sk);
	sock_put(sk);
	lana_sk_free(sk);
	return 0;
}

static const struct net_proto_family lana_ui_family_ops = {
	.family = PF_LANA,
	.create = lana_ui_create,
	.owner	= THIS_MODULE,
};

static const struct proto_ops lana_ui_ops = {
	.family	     = PF_LANA,
	.owner       = THIS_MODULE,
	.release     = lana_ui_release,
	.recvmsg     = lana_ui_recvmsg,
	.bind	     = sock_no_bind,
	.connect     = sock_no_connect,
	.socketpair  = sock_no_socketpair,
	.accept      = sock_no_accept,
	.getname     = sock_no_getname,
	.poll	     = sock_no_poll,
	.ioctl       = sock_no_ioctl,
	.listen      = sock_no_listen,
	.shutdown    = sock_no_shutdown,
	.setsockopt  = sock_no_setsockopt,
	.getsockopt  = sock_no_getsockopt,
	.sendmsg     = sock_no_sendmsg,
	.mmap	     = sock_no_mmap,
	.sendpage    = sock_no_sendpage,
};

static struct proto lana_proto = {
	.name	  = "LANA",
	.owner	  = THIS_MODULE,
	.obj_size = sizeof(struct lana_sock),
	.slab_flags = SLAB_DESTROY_BY_RCU,
};

static int init_fb_pflana(void)
{
	int ret;
	ret = proto_register(&lana_proto, 0);
	if (ret)
		return ret;
	ret = sock_register(&lana_ui_family_ops);
	if (ret) {
		proto_unregister(&lana_proto);
		return ret;
	}
	return 0;
}

static void cleanup_fb_pflana(void)
{
	sock_unregister(PF_LANA);
	proto_unregister(&lana_proto);
}

static struct fblock *fb_pflana_ctor(char *name)
{
	int i, ret = 0;
	unsigned int cpu;
	struct fblock *fb;
	struct fb_pflana_priv __percpu *fb_priv;

	fb = alloc_fblock(GFP_ATOMIC);
	if (!fb)
		return NULL;
	fb_priv = alloc_percpu(struct fb_pflana_priv);
	if (!fb_priv)
		goto err;
	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct fb_pflana_priv *fb_priv_cpu;
		fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
		seqlock_init(&fb_priv_cpu->lock);
		for (i = 0; i < NUM_TYPES; ++i)
			fb_priv_cpu->port[i] = IDP_UNKNOWN;
	}
	put_online_cpus();

	ret = init_fblock(fb, name, fb_priv);
	if (ret)
		goto err2;
	fb->netfb_rx = fb_pflana_netrx;
	fb->event_rx = fb_pflana_event;
	fb->factory = &fb_pflana_factory;
	ret = register_fblock_namespace(fb);
	if (ret)
		goto err3;
	__module_get(THIS_MODULE);
	return fb;
err3:
	cleanup_fblock_ctor(fb);
err2:
	free_percpu(fb_priv);
err:
	kfree_fblock(fb);
	fb = NULL;
	return NULL;
}

static void fb_pflana_dtor(struct fblock *fb)
{
	free_percpu(rcu_dereference_raw(fb->private_data));
	module_put(THIS_MODULE);
}

static struct fblock_factory fb_pflana_factory = {
	.type = "pflana",
	.mode = MODE_SINK,
	.ctor = fb_pflana_ctor,
	.dtor = fb_pflana_dtor,
	.owner = THIS_MODULE,
};

static int __init init_fb_pflana_module(void)
{
	int ret;
	ret = init_fb_pflana();
	if (ret)
		return ret;
	ret = register_fblock_type(&fb_pflana_factory);
	if (ret)
		cleanup_fb_pflana();
	return ret;
}

static void __exit cleanup_fb_pflana_module(void)
{
	cleanup_fb_pflana();
	unregister_fblock_type(&fb_pflana_factory);
}

module_init(init_fb_pflana_module);
module_exit(cleanup_fb_pflana_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkma@tik.ee.ethz.ch>");
MODULE_DESCRIPTION("LANA PF_LANA module");
