/*
 * Lightweight Autonomic Network Architecture
 *
 * Global LANA IDP translation tables, core backend. Implemented as RCU
 * protected hash tables with bucket lists.
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

struct str_idp_elem {
	idp_t idp;
	char name[FBNAMSIZ];
	struct idp_fb_elem *next;
	struct rcu_head rcu;
	atomic_t refcnt;
} ____cacheline_aligned_in_smp;

static struct str_idp_elem **str_idp_head = NULL;

static struct fblock **idp_fbl_head = NULL;
static spinlock_t idp_fbl_head_lock = __SPIN_LOCK_UNLOCKED(idp_fbl_head_lock);

static atomic_t idp_counter;
static struct kmem_cache *fblock_cache = NULL;

static inline idp_t provide_new_idp(void)
{
	int ret, c = atomic_read(&idp_counter);
	ret = atomic_inc_return(&idp_counter);
	if (unlikely(c > ret))
		panic("Too many functional blocks loaded!\n");
	return (idp_t) ret;
}

/* Caller needs to do a put_fblock() after his work is done! */
struct fblock *search_fblock(idp_t idp)
{
	struct fblock *p;
	struct fblock *p0;

	p0 = idp_fbl_head[hash_idp(idp)];
	rmb();
	p = p0->next;
	while (p != p0) {
		rmb();
		if (p->idp == idp) {
			get_fblock(p);
			return p;
		}
		p = p->next;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(search_fblock);

void register_fblock(struct fblock *p)
{
	struct fblock *p0;

	p->idp = provide_new_idp();
	p0 = idp_fbl_head[hash_idp(p->idp)];
	p->next = p0->next;
	wmb();
	p0->next = p;

	printk("[lana] %s loaded!\n", p->name);
}
EXPORT_SYMBOL_GPL(register_fblock);

static void free_fblock_rcu(struct rcu_head *rp)
{
	struct fblock *p = container_of(rp, struct fblock, rcu);
	put_fblock(p);
}

void unregister_fblock(struct fblock *p)
{
	unsigned long flags;

	spin_lock_irqsave(&idp_fbl_head_lock, flags);
	p->next->prev = p->prev;
	p->prev->next = p->next;
	spin_unlock_irqrestore(&idp_fbl_head_lock, flags);
	printk("[lana] %s unloaded!\n", p->name);

	call_rcu(&p->rcu, free_fblock_rcu);
	return;
}
EXPORT_SYMBOL_GPL(unregister_fblock);

void xchg_fblock(idp_t idp, struct fblock *newp)
{
}
EXPORT_SYMBOL_GPL(xchg_fblock);

static void ctor_fblock(void *obj)
{
	struct fblock *p = obj;
	p->idp = IDP_UNKNOWN;
	atomic_set(&p->refcnt, 1);
	p->next = p->prev = NULL;
	p->private_data = NULL;
}

struct fblock *alloc_fblock(gfp_t flags)
{
	return kmem_cache_alloc(fblock_cache, flags);
}
EXPORT_SYMBOL_GPL(alloc_fblock);

void kfree_fblock(struct fblock *p)
{
	kmem_cache_free(fblock_cache, p);
}
EXPORT_SYMBOL_GPL(kfree_fblock);

int init_fblock_tables(void)
{
	int ret = 0;

	str_idp_head = kzalloc(sizeof(*str_idp_head) * HASHTSIZ, GFP_KERNEL);
	if (!str_idp_head)
		return -ENOMEM;
	idp_fbl_head = kzalloc(sizeof(*idp_fbl_head) * HASHTSIZ, GFP_KERNEL);
	if (!idp_fbl_head)
		goto err;
	fblock_cache = kmem_cache_create("fblock", sizeof(struct fblock),
					 0, SLAB_HWCACHE_ALIGN, ctor_fblock);
	if (!fblock_cache)
		goto err2;
	atomic_set(&idp_counter, 0);

	printk(KERN_INFO "[lana] %s cache created!\n",
	       fblock_cache->name);
	printk(KERN_INFO "[lana] IDP tables with size %u initialized!\n",
	       HASHTSIZ);
	return 0;
err2:
	kfree(idp_fbl_head);
err:
	kfree(str_idp_head);
	return ret;
}
EXPORT_SYMBOL_GPL(init_fblock_tables);

void cleanup_fblock_tables(void)
{
	kfree(str_idp_head);
	kfree(idp_fbl_head);
	printk(KERN_INFO "[lana] %s cache destroyed!\n",
	       fblock_cache->name);
	kmem_cache_destroy(fblock_cache);
	printk(KERN_INFO "[lana] IDP tables removed!\n");
}
EXPORT_SYMBOL_GPL(cleanup_fblock_tables);

