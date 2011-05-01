/*
 * Lightweight Autonomic Network Architecture
 *
 * Global LANA IDP translation tables, core backend.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/atomic.h>
#include <linux/types.h>
#include <linux/cpu.h>
#include <linux/spinlock.h>
#include <linux/rwlock.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>

#include "xt_fblock.h"
#include "xt_idp.h"
#include "xt_hash.h"
#include "xt_critbit.h"

struct idp_elem {
	char name[FBNAMSIZ];
	idp_t idp;
	struct rcu_head rcu;
} ____cacheline_aligned;

static struct critbit_tree idpmap;
static struct fblock **fblmap_head = NULL;
static spinlock_t fblmap_head_lock;

static atomic64_t idp_counter;

static struct kmem_cache *fblock_cache = NULL;

extern struct proc_dir_entry *lana_proc_dir;
static struct proc_dir_entry *fblocks_proc;

static inline idp_t provide_new_fblock_idp(void)
{
	return (idp_t) atomic64_inc_return(&idp_counter);
}

static int register_to_fblock_namespace(char *name, idp_t val)
{
	struct idp_elem *elem;

	if (critbit_contains(&idpmap, name))
		return -EEXIST;
	elem = kzalloc(sizeof(*elem), GFP_ATOMIC);
	if (!elem)
		return -ENOMEM;
	strlcpy(elem->name, name, sizeof(elem->name));
	elem->idp = val;

	return critbit_insert(&idpmap, elem->name);
}

static void fblock_namespace_do_free_rcu(struct rcu_head *rp)
{
	struct idp_elem *p = container_of(rp, struct idp_elem, rcu);
	kfree(p);
}

static int unregister_from_fblock_namespace(char *name)
{
	int ret;
	struct idp_elem *elem;

	elem = struct_of(critbit_get(&idpmap, name), struct idp_elem);
	if (!elem)
		return -ENOENT;
	ret = critbit_delete(&idpmap, elem->name);
	if (ret)
		return ret;
	call_rcu(&elem->rcu, fblock_namespace_do_free_rcu);

	return 0;
}

/* Called within RCU read lock! */
idp_t __get_fblock_namespace_mapping(char *name)
{
	struct idp_elem *elem = struct_of(__critbit_get(&idpmap, name),
					  struct idp_elem);
	if (unlikely(!elem))
		return IDP_UNKNOWN;
	smp_rmb();
	return elem->idp;
}
EXPORT_SYMBOL_GPL(__get_fblock_namespace_mapping);

idp_t get_fblock_namespace_mapping(char *name)
{
	idp_t ret;
	rcu_read_lock();
	ret = __get_fblock_namespace_mapping(name);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(get_fblock_namespace_mapping);

/* Called within RCU read lock! */
int __change_fblock_namespace_mapping(char *name, idp_t new)
{
	struct idp_elem *elem = struct_of(__critbit_get(&idpmap, name),
					  struct idp_elem);
	if (unlikely(!elem))
		return -ENOENT;
	elem->idp = new;
	smp_wmb();
	return 0;
}
EXPORT_SYMBOL_GPL(__change_fblock_namespace_mapping);

int change_fblock_namespace_mapping(char *name, idp_t new)
{
	int ret;
	rcu_read_lock();
	ret = __change_fblock_namespace_mapping(name, new);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(change_fblock_namespace_mapping);

/* Caller needs to do a put_fblock() after his work is done! */
/* Called within RCU read lock! */
struct fblock *__search_fblock(idp_t idp)
{
	struct fblock *p0;

	p0 = rcu_dereference_raw(fblmap_head[hash_idp(idp)]);
	if (!p0)
		return NULL;
	while (p0) {
		if (p0->idp == idp) {
			get_fblock(p0);
			return p0;
		}
		p0 = rcu_dereference_raw(p0->next);
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(__search_fblock);

struct fblock *search_fblock(idp_t idp)
{
	struct fblock *ret;
	if (unlikely(idp == IDP_UNKNOWN))
		return NULL;
	rcu_read_lock();
	ret = __search_fblock(idp);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(search_fblock);

/* Note: user needs to do a put_fblock */
struct fblock *__search_fblock_n(char *name)
{
	idp_t id;
	struct fblock *fb;
	id = get_fblock_namespace_mapping(name);
	if (unlikely(id == IDP_UNKNOWN))
		return NULL;
	fb = search_fblock(id);
	if (!fb)
		return NULL;
	return fb;
}
EXPORT_SYMBOL_GPL(__search_fblock_n);

struct fblock *search_fblock_n(char *name)
{
	struct fblock *ret;
	if (unlikely(!name))
		return NULL;
	rcu_read_lock();
	ret = __search_fblock_n(name);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(search_fblock_n);

/* opt_string must be of type "key=val" and 0-terminated */
int __fblock_set_option(struct fblock *fb, char *opt_string)
{
	int ret = 0;
	char *val = opt_string;
	struct fblock_opt_msg msg;
	/* Hack: we let the fb think that this belongs to his own chain to
	 * get the reference back to itself. */
	struct fblock_notifier fbn;

	memset(&fbn, 0, sizeof(fbn));
	memset(&msg, 0, sizeof(msg));

	msg.key = opt_string;
	while (*val != '=' && *val != '\0')
		val++;
	if (*val == '\0')
		return -EINVAL;
	val++;
	*(val - 1) = '\0';
	msg.val = val;
	fbn.self = fb;

	get_fblock(fb);
	ret = fb->ops->event_rx(&fbn.nb, FBLOCK_SET_OPT, &msg);
	put_fblock(fb);

	return ret;
}
EXPORT_SYMBOL_GPL(__fblock_set_option);

int fblock_set_option(struct fblock *fb, char *opt_string)
{
	int ret;
	if (unlikely(!opt_string || !fb))
		return -EINVAL;
	rcu_read_lock();
	ret = __fblock_set_option(fb, opt_string);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(fblock_set_option);

/* Must already hold write_lock */
static void fblock_update_selfref(struct fblock_notifier *head,
				  struct fblock *self)
{
	while (rcu_dereference_raw(head) != NULL) {
		rcu_assign_pointer(head->self, self);
		rcu_assign_pointer(head, head->next);
	}
}

/*
 * Migrate src to dst, both are of same type, working data is
 * transferred to dst and droped from src. src gets dsts old data,
 * so that on free, we do not need to explicitly ignore srcs
 * private data and dsts remaining data.
 */
void fblock_migrate_p(struct fblock *dst, struct fblock *src)
{
	void *priv_old;

	get_fblock(dst);
	get_fblock(src);

	rcu_assign_pointer(priv_old, dst->private_data);
	rcu_assign_pointer(dst->private_data, src->private_data);
	rcu_assign_pointer(src->private_data, priv_old);

	put_fblock(dst);
	put_fblock(src);
}
EXPORT_SYMBOL_GPL(fblock_migrate_p);

void fblock_migrate_r(struct fblock *dst, struct fblock *src)
{
	int ref_old;
	struct fblock_notifier *not_old;
	struct fblock_subscrib *sub_old;

	get_fblock(dst);
	get_fblock(src);

	write_lock(&dst->lock);
	write_lock(&src->lock);

	dst->idp = src->idp;
	strlcpy(dst->name, src->name, sizeof(dst->name));

	rcu_assign_pointer(not_old, dst->notifiers);
	rcu_assign_pointer(dst->notifiers, src->notifiers);
	rcu_assign_pointer(src->notifiers, not_old);

	fblock_update_selfref(dst->notifiers, dst);
	fblock_update_selfref(src->notifiers, src);

	rcu_assign_pointer(sub_old, dst->others);
	rcu_assign_pointer(dst->others, src->others);
	rcu_assign_pointer(src->others, sub_old);

	ref_old = atomic_read(&dst->refcnt);
	atomic_set(&dst->refcnt, atomic_read(&src->refcnt));
	atomic_set(&src->refcnt, ref_old);

	write_unlock(&src->lock);
	write_unlock(&dst->lock);

	put_fblock(dst);
	put_fblock(src);
}
EXPORT_SYMBOL_GPL(fblock_migrate_r);

/*
 * fb1 on top of fb2 in the stack
 */
int __fblock_bind(struct fblock *fb1, struct fblock *fb2)
{
	int ret;
	struct fblock_bind_msg msg;
	/* Hack: we let the fb think that this belongs to his own chain to
	 * get the reference back to itself. */
	struct fblock_notifier fbn;

	memset(&fbn, 0, sizeof(fbn));
	memset(&msg, 0, sizeof(msg));

	get_fblock(fb1);
	get_fblock(fb2);

	msg.dir = TYPE_EGRESS;
	msg.idp = fb2->idp;
	fbn.self = fb1;
	ret = fb1->ops->event_rx(&fbn.nb, FBLOCK_BIND_IDP, &msg);
	if (ret != NOTIFY_OK) {
		put_fblock(fb1);
		put_fblock(fb2);
		return -EBUSY;
	}

	msg.dir = TYPE_INGRESS;
	msg.idp = fb1->idp;
	fbn.self = fb2;
	ret = fb2->ops->event_rx(&fbn.nb, FBLOCK_BIND_IDP, &msg);
	if (ret != NOTIFY_OK) {
		/* Release previous binding */
		msg.dir = TYPE_EGRESS;
		msg.idp = fb2->idp;
		fbn.self = fb1;
		ret = fb1->ops->event_rx(&fbn.nb, FBLOCK_UNBIND_IDP, &msg);
		if (ret != NOTIFY_OK)
			panic("Cannot release previously bound fblock!\n");
		put_fblock(fb1);
		put_fblock(fb2);
		return -EBUSY;
	}

	ret = subscribe_to_remote_fblock(fb1, fb2);
	if (ret) {
		__fblock_unbind(fb1, fb2);
		return -ENOMEM;
	}

	ret = subscribe_to_remote_fblock(fb2, fb1);
	if (ret) {
		__fblock_unbind(fb1, fb2);
		return -ENOMEM;
	}

	/* We don't give refcount back! */
	return 0;
}
EXPORT_SYMBOL_GPL(__fblock_bind);

int fblock_bind(struct fblock *fb1, struct fblock *fb2)
{
	int ret;
	rcu_read_lock();
	ret = __fblock_bind(fb1, fb2);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(fblock_bind);

/*
 * fb1 on top of fb2 in the stack
 */
int __fblock_unbind(struct fblock *fb1, struct fblock *fb2)
{
	int ret;
	struct fblock_bind_msg msg;
	/* Hack: we let the fb think that this belongs to his own chain to
	 * get the reference back to itself. */
	struct fblock_notifier fbn;

	/* We still have refcnt, we drop it on exit! */

	memset(&fbn, 0, sizeof(fbn));
	memset(&msg, 0, sizeof(msg));

	msg.dir = TYPE_EGRESS;
	msg.idp = fb2->idp;
	fbn.self = fb1;
	ret = fb1->ops->event_rx(&fbn.nb, FBLOCK_UNBIND_IDP, &msg);
	if (ret != NOTIFY_OK) {
		/* We are not bound to fb2 */
		return -EBUSY;
	}

	msg.dir = TYPE_INGRESS;
	msg.idp = fb1->idp;
	fbn.self = fb2;
	ret = fb2->ops->event_rx(&fbn.nb, FBLOCK_UNBIND_IDP, &msg);
	if (ret != NOTIFY_OK) {
		/* We are not bound to fb1, but fb1 was bound to us, so only
		 * release fb1 */
		put_fblock(fb1);
		return -EBUSY;
	}

	unsubscribe_from_remote_fblock(fb1, fb2);
	unsubscribe_from_remote_fblock(fb2, fb1);

	put_fblock(fb2);
	put_fblock(fb1);

	return 0;
}
EXPORT_SYMBOL_GPL(__fblock_unbind);

int fblock_unbind(struct fblock *fb1, struct fblock *fb2)
{
	int ret;
	rcu_read_lock();
	ret = __fblock_unbind(fb1, fb2);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(fblock_unbind);

/*
 * register_fblock is called when the idp is preknown to the
 * caller and has already been registered previously. The previous
 * registration has then called unregister_fblock to remove the 
 * fblock but to keep the namespace and idp number.
 */
int register_fblock(struct fblock *p, idp_t idp)
{
	struct fblock *p0;
	unsigned long flags;

	spin_lock_irqsave(&fblmap_head_lock, flags);
	p->idp = idp;
	p0 = rcu_dereference_raw(fblmap_head[hash_idp(p->idp)]);
	if (!p0)
		rcu_assign_pointer(fblmap_head[hash_idp(p->idp)], p);
	else {
		p->next = p0->next;
		rcu_assign_pointer(p0->next, p);
	}
	spin_unlock_irqrestore(&fblmap_head_lock, flags);
	return 0;
}
EXPORT_SYMBOL_GPL(register_fblock);

/*
 * register_fblock_namespace is called when a new functional block
 * instance is registered to the system. Then, its name will be 
 * registered into the namespace and it receives a new idp number.
 */
int register_fblock_namespace(struct fblock *p)
{
	struct fblock *p0;
	unsigned long flags;

	spin_lock_irqsave(&fblmap_head_lock, flags);
	p->idp = provide_new_fblock_idp();
	p0 = rcu_dereference_raw(fblmap_head[hash_idp(p->idp)]);
	if (!p0)
		rcu_assign_pointer(fblmap_head[hash_idp(p->idp)], p);
	else {
		p->next = p0->next;
		rcu_assign_pointer(p0->next, p);
	}
	spin_unlock_irqrestore(&fblmap_head_lock, flags);
	return register_to_fblock_namespace(p->name, p->idp);
}
EXPORT_SYMBOL_GPL(register_fblock_namespace);

static void free_fblock_rcu(struct rcu_head *rp)
{
	struct fblock *p = container_of(rp, struct fblock, rcu);
	put_fblock(p);
}

/*
 * unregister_fblock releases the functional block _only_ from the idp to
 * fblock translation table, but not from the namespace. The idp can then
 * later be reused, e.g. by another fblock.
 */
void unregister_fblock(struct fblock *p)
{
	struct fblock *p0;
	unsigned long flags;

	spin_lock_irqsave(&fblmap_head_lock, flags);
	p0 = rcu_dereference_raw(fblmap_head[hash_idp(p->idp)]);
	if (p0 == p)
		rcu_assign_pointer(fblmap_head[hash_idp(p->idp)], p->next);
	else if (p0) {
		struct fblock *p1;
		while ((p1 = rcu_dereference_raw(p0->next))) {
			if (p1 == p) {
				rcu_assign_pointer(p0->next, p1->next);
				break;
			}
			p0 = p1;
		}
	}
	spin_unlock_irqrestore(&fblmap_head_lock, flags);
	call_rcu(&p->rcu, free_fblock_rcu);
}
EXPORT_SYMBOL_GPL(unregister_fblock);

/*
 * Removes the functional block from the system along with its namespace
 * mapping.
 */
static void __unregister_fblock_namespace(struct fblock *p, int rcu)
{
	struct fblock *p0;
	unsigned long flags;

	spin_lock_irqsave(&fblmap_head_lock, flags);
	p0 = rcu_dereference_raw(fblmap_head[hash_idp(p->idp)]);
	if (p0 == p)
		rcu_assign_pointer(fblmap_head[hash_idp(p->idp)], p->next);
	else if (p0) {
		struct fblock *p1;
		while ((p1 = rcu_dereference_raw(p0->next))) {
			if (p1 == p) {
				rcu_assign_pointer(p0->next, p->next);
				break;
			}
			p0 = p1;
		}
	}
	spin_unlock_irqrestore(&fblmap_head_lock, flags);
	unregister_from_fblock_namespace(p->name);
	if (rcu)
		call_rcu(&p->rcu, free_fblock_rcu);
}

void unregister_fblock_namespace(struct fblock *p)
{
	__unregister_fblock_namespace(p, 1);
}
EXPORT_SYMBOL_GPL(unregister_fblock_namespace);

void unregister_fblock_namespace_no_rcu(struct fblock *p)
{
	__unregister_fblock_namespace(p, 0);
}
EXPORT_SYMBOL_GPL(unregister_fblock_namespace_no_rcu);

/* If state changes on 'remote' fb, we ('us') want to be notified. */
int subscribe_to_remote_fblock(struct fblock *us, struct fblock *remote)
{
	struct fblock_notifier *fn = kmalloc(sizeof(*fn), GFP_ATOMIC);
	if (!fn)
		return -ENOMEM;
	/* hold ref */
	get_fblock(us);
	get_fblock(remote);
	write_lock(&us->lock);
	fn->self = us;
	fn->remote = remote;
	init_fblock_subscriber(us, &fn->nb);
	fn->next = rcu_dereference_raw(us->notifiers);
	rcu_assign_pointer(us->notifiers, fn);
	write_unlock(&us->lock);
	return fblock_register_foreign_subscriber(remote,
			&rcu_dereference_raw(us->notifiers)->nb);
}
EXPORT_SYMBOL_GPL(subscribe_to_remote_fblock);

void unsubscribe_from_remote_fblock(struct fblock *us, struct fblock *remote)
{
	int found = 0;
	struct fblock_notifier *fn;

	if (unlikely(!rcu_dereference_raw(us->notifiers)))
		return;
	write_lock(&us->lock);
	fn = rcu_dereference_raw(us->notifiers);
	if (fn->remote == remote)
		rcu_assign_pointer(us->notifiers, us->notifiers->next);
	else {
		struct fblock_notifier *f1;
		while ((f1 = fn->next)) {
			if (f1->remote == remote) {
				found = 1;
				fn->next = f1->next;
				fn = f1; /* free f1 */
				break;
			} else
				fn = f1;
		}
	}
	write_unlock(&us->lock);
	if (found) {
		fblock_unregister_foreign_subscriber(remote, &fn->nb);
		kfree(fn);
	}
	/* drop ref */
	put_fblock(us);
	put_fblock(remote);
}
EXPORT_SYMBOL_GPL(unsubscribe_from_remote_fblock);

static void ctor_fblock(void *obj)
{
	struct fblock *p = obj;
	atomic_set(&p->refcnt, 1);
	rwlock_init(&p->lock);
	p->idp = IDP_UNKNOWN;
	p->next = NULL;
	p->private_data = NULL;
	p->ops = NULL;
	p->notifiers = NULL;
	p->others = NULL;
}

struct fblock *alloc_fblock(gfp_t flags)
{
	__module_get(THIS_MODULE);
	return kmem_cache_alloc(fblock_cache, flags);
}
EXPORT_SYMBOL_GPL(alloc_fblock);

int init_fblock(struct fblock *fb, char *name, void *priv,
		struct fblock_ops *ops)
{
	write_lock(&fb->lock);
	strlcpy(fb->name, name, sizeof(fb->name));
	rcu_assign_pointer(fb->private_data, priv);
	fb->ops = ops;
	fb->others = kmalloc(sizeof(*(fb->others)), GFP_ATOMIC);
	if (!fb->others)
		return -ENOMEM;
	ATOMIC_INIT_NOTIFIER_HEAD(&fb->others->subscribers);
	write_unlock(&fb->lock);
	return 0;
}
EXPORT_SYMBOL_GPL(init_fblock);

void kfree_fblock(struct fblock *p)
{
	kmem_cache_free(fblock_cache, p);
	module_put(THIS_MODULE);
}
EXPORT_SYMBOL_GPL(kfree_fblock);

void cleanup_fblock(struct fblock *fb)
{
	notify_fblock_subscribers(fb, FBLOCK_DOWN, &fb->idp);
	fb->factory->dtor(fb);
	kfree(rcu_dereference_raw(fb->others));
}
EXPORT_SYMBOL_GPL(cleanup_fblock);

void cleanup_fblock_ctor(struct fblock *fb)
{
	kfree(rcu_dereference_raw(fb->others));
}
EXPORT_SYMBOL_GPL(cleanup_fblock_ctor);

static int procfs_fblocks(char *page, char **start, off_t offset,
			  int count, int *eof, void *data)
{
	int i;
	off_t len = 0;
	struct fblock *fb;

	len += sprintf(page + len, "name type addr idp refcnt\n");
	rcu_read_lock();
	for (i = 0; i < HASHTSIZ; ++i) {
		fb = rcu_dereference_raw(fblmap_head[i]);
		while (fb) {
			len += sprintf(page + len, "%s %s %p %u %d\n",
				       fb->name, fb->factory->type,
				       fb, fb->idp, atomic_read(&fb->refcnt));
			fb = rcu_dereference_raw(fb->next);
		}
	}
	rcu_read_unlock();

	/* FIXME: fits in page? */
	*eof = 1;
	return len;
}

int init_fblock_tables(void)
{
	int ret = 0;

	get_critbit_cache();
	critbit_init_tree(&idpmap);

	fblmap_head_lock = __SPIN_LOCK_UNLOCKED(fblmap_head_lock);
	fblmap_head = kzalloc(sizeof(*fblmap_head) * HASHTSIZ, GFP_KERNEL);
	if (!fblmap_head)
		goto err;
	fblock_cache = kmem_cache_create("fblock", sizeof(struct fblock),
					 0, SLAB_HWCACHE_ALIGN, ctor_fblock);
	if (!fblock_cache)
		goto err2;
	atomic64_set(&idp_counter, 0);
	fblocks_proc = create_proc_read_entry("fblocks", 0400, lana_proc_dir,
					      procfs_fblocks, NULL);
	if (!fblocks_proc)
		goto err3;
	return 0;
err3:
	kmem_cache_destroy(fblock_cache);
err2:
	kfree(fblmap_head);
err:
	put_critbit_cache();
	return ret;
}
EXPORT_SYMBOL_GPL(init_fblock_tables);

void cleanup_fblock_tables(void)
{
	remove_proc_entry("fblocks", lana_proc_dir);
	put_critbit_cache();
	kfree(fblmap_head);
	synchronize_rcu();
	kmem_cache_destroy(fblock_cache);
}
EXPORT_SYMBOL_GPL(cleanup_fblock_tables);

