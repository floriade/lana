/*
 * Lightweight Autonomic Network Architecture
 *
 * Global LANA IDP translation tables, core backend.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/atomic.h>
#include <linux/types.h>
#include <linux/cpu.h>
#include <linux/spinlock.h>
#include <linux/slab.h>

#include "xt_fblock.h"
#include "xt_idp.h"
#include "xt_hash.h"
#include "xt_critbit.h"

struct idp_elem {
	char name[FBNAMSIZ];
	idp_t idp;
	struct rcu_head rcu;
} ____cacheline_aligned;

static struct critbit_tree idpmap; /* string -> idp translation map */
static struct fblock **fblmap_head = NULL; /* idp -> fblock translation map */
static spinlock_t fblmap_head_lock;
static atomic64_t idp_counter;
static struct kmem_cache *fblock_cache = NULL;

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
	struct fblock *p;
	struct fblock *p0;

	p0 = fblmap_head[hash_idp(idp)];
	if (!p0)
		return NULL;
	p = rcu_dereference_raw(p0->next);
	while (p != p0) {
		if (p->idp == idp) {
			get_fblock(p);
			return p;
		}
		p = rcu_dereference_raw(p->next);
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(__search_fblock);

struct fblock *search_fblock(idp_t idp)
{
	struct fblock * ret;
	rcu_read_lock();
	ret = __search_fblock(idp);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(search_fblock);

/*
 * register_fblock_idp is called when the idp is preknown to the
 * caller and has already been registered previously. The previous
 * registration has then called unregister_fblock to remove the 
 * fblock but to keep the namespace and idp number.
 */
int register_fblock_idp(struct fblock *p, idp_t idp)
{
	struct fblock *p0;
	unsigned long flags;

	spin_lock_irqsave(&fblmap_head_lock, flags);
	p->idp = idp;
	p0 = fblmap_head[hash_idp(p->idp)];
	if (!p0)
		rcu_assign_pointer(fblmap_head[hash_idp(p->idp)], p);
	else {
		p->next = p0->next;
		rcu_assign_pointer(p0->next, p);
	}
	spin_unlock_irqrestore(&fblmap_head_lock, flags);

	printk("[lana] (%u,%s) loaded!\n", p->idp, p->name);
	return 0;
}
EXPORT_SYMBOL_GPL(register_fblock_idp);

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
	p0 = fblmap_head[hash_idp(p->idp)];
	if (!p0)
		rcu_assign_pointer(fblmap_head[hash_idp(p->idp)], p);
	else {
		p->next = p0->next;
		rcu_assign_pointer(p0->next, p);
	}
	spin_unlock_irqrestore(&fblmap_head_lock, flags);

	printk("[lana] (%u,%s) loaded!\n", p->idp, p->name);
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
int unregister_fblock(struct fblock *p)
{
	int ret = -ENOENT;
	struct fblock *p0;
	unsigned long flags;

	spin_lock_irqsave(&fblmap_head_lock, flags);
	p0 = fblmap_head[hash_idp(p->idp)];
	if (p0 == p)
		rcu_assign_pointer(fblmap_head[hash_idp(p->idp)], p->next);
	else if (p0) {
		struct fblock *p1;
		while ((p1 = rcu_dereference_raw(p0->next))) {
			if (p1 == p) {
				rcu_assign_pointer(p0->next, p->next);
				ret = 0;
				break;
			}
			p0 = p1;
		}
	}
	spin_unlock_irqrestore(&fblmap_head_lock, flags);

	printk("[lana] (%s) unloaded!\n", p->name);
	call_rcu(&p->rcu, free_fblock_rcu);
	return ret;
}
EXPORT_SYMBOL_GPL(unregister_fblock);

/*
 * Removes the functional block from the system along with its namespace
 * mapping.
 */
void unregister_fblock_namespace(struct fblock *p)
{
	struct fblock *p0;
	unsigned long flags;

	spin_lock_irqsave(&fblmap_head_lock, flags);
	p0 = fblmap_head[hash_idp(p->idp)];
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

	printk("[lana] (%u,%s) unloaded!\n", p->idp, p->name);
	unregister_from_fblock_namespace(p->name);
	call_rcu(&p->rcu, free_fblock_rcu);
}
EXPORT_SYMBOL_GPL(unregister_fblock_namespace);

int xchg_fblock_idp(idp_t idp, struct fblock *new)
{
	return 0;
}
EXPORT_SYMBOL_GPL(xchg_fblock_idp);

int xchg_fblock(struct fblock *old, struct fblock *new)
{
	return 0;
}
EXPORT_SYMBOL_GPL(xchg_fblock);

static void ctor_fblock(void *obj)
{
	struct fblock *p = obj;

	atomic_set(&p->refcnt, 1);
	p->idp = IDP_UNKNOWN;
	p->next = NULL;
	p->private_data = NULL;
	p->ops = NULL;
	p->notifiers = NULL;
	p->others = NULL;
}

struct fblock *alloc_fblock(gfp_t flags)
{
	return kmem_cache_alloc(fblock_cache, flags);
}
EXPORT_SYMBOL_GPL(alloc_fblock);

int init_fblock(struct fblock *fb, char *name, void *priv,
		struct fblock_ops *ops)
{
	strlcpy(fb->name, name, sizeof(fb->name));
	fb->private_data = priv;
	fb->ops = ops;
	fb->others = kmalloc(sizeof(*(fb->others)), GFP_KERNEL);
	if (!fb->others)
		return -ENOMEM;
	ATOMIC_INIT_NOTIFIER_HEAD(&fb->others->subscribers);
	return 0;
}
EXPORT_SYMBOL_GPL(init_fblock);

void kfree_fblock(struct fblock *p)
{
	kmem_cache_free(fblock_cache, p);
}
EXPORT_SYMBOL_GPL(kfree_fblock);

void cleanup_fblock(struct fblock *fb)
{
	kfree(fb->others);
}
EXPORT_SYMBOL_GPL(cleanup_fblock);

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

	printk(KERN_INFO "[lana] %s cache created!\n",
	       fblock_cache->name);
	printk(KERN_INFO "[lana] IDP tables with size %u initialized!\n",
	       HASHTSIZ);
	return 0;
err2:
	kfree(fblmap_head);
err:
	put_critbit_cache();
	return ret;
}
EXPORT_SYMBOL_GPL(init_fblock_tables);

void cleanup_fblock_tables(void)
{
	put_critbit_cache();
	kfree(fblmap_head);
	printk(KERN_INFO "[lana] %s cache destroyed!\n",
	       fblock_cache->name);
	kmem_cache_destroy(fblock_cache);
	printk(KERN_INFO "[lana] IDP tables removed!\n");
}
EXPORT_SYMBOL_GPL(cleanup_fblock_tables);

