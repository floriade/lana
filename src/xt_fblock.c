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
#include <linux/seqlock.h>
#include <linux/slab.h>

#include "xt_fblock.h"
#include "xt_idp.h"
#include "xt_hash.h"
#include "xt_critbit.h"

struct idp_elem {
	char name[FBNAMSIZ];
	idp_t idp;
	seqlock_t idp_lock;
} ____cacheline_aligned;

/* string -> idp translation map */
static struct critbit_tree idpmap;
/* idp -> fblock translation map */
static struct fblock **fblmap_head = NULL;
static spinlock_t fblmap_head_lock = __SPIN_LOCK_UNLOCKED(fblmap_head_lock);

static atomic_t idp_counter;
static struct kmem_cache *fblock_cache = NULL;

static inline idp_t provide_new_fblock_idp(void)
{
	int ret, c = atomic_read(&idp_counter);
	ret = atomic_inc_return(&idp_counter);
	if (unlikely(c > ret))
		panic("Too many functional blocks loaded!\n");
	return (idp_t) ret;
}

static int register_to_fblock_namespace(char *name, idp_t val)
{
	return 0;
}

static int unregister_from_fblock_namespace(char *name)
{
	return 0;
}

idp_t get_fblock_namespace_mapping(char *name)
{
	return IDP_UNKNOWN;
}
EXPORT_SYMBOL_GPL(get_fblock_namespace_mapping);

/* Caller needs to do a put_fblock() after his work is done! */
struct fblock *search_fblock(idp_t idp)
{
	struct fblock *p;
	struct fblock *p0;

	p0 = fblmap_head[hash_idp(idp)];
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

/*
 * register_fblock_idp is called when the idp is preknown to the
 * caller and has already been registered previously. The previous
 * registration has then called unregister_fblock to remove the 
 * fblock but to keep the namespace and idp number.
 */
int register_fblock_idp(struct fblock *p, idp_t idp)
{
	struct fblock *p0;
	p->idp = idp;
	p0 = fblmap_head[hash_idp(p->idp)];
	p->next = p0->next;
	wmb();
	p0->next = p;
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
	p->idp = provide_new_fblock_idp();
	p0 = fblmap_head[hash_idp(p->idp)];
	p->next = p0->next;
	wmb();
	p0->next = p;
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
idp_t unregister_fblock(struct fblock *p)
{
	idp_t ret = p->idp;
	unsigned long flags;

	spin_lock_irqsave(&fblmap_head_lock, flags);
	p->next->prev = p->prev;
	p->prev->next = p->next;
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
	unsigned long flags;

	spin_lock_irqsave(&fblmap_head_lock, flags);
	p->next->prev = p->prev;
	p->prev->next = p->next;
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

	critbit_init_tree(&idpmap);
	ret = critbit_node_cache_init();
	if (ret == -ENOMEM)
		return ret;
	fblmap_head = kzalloc(sizeof(*fblmap_head) * HASHTSIZ, GFP_KERNEL);
	if (!fblmap_head)
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
	kfree(fblmap_head);
err:
	critbit_node_cache_destroy();
	return ret;
}
EXPORT_SYMBOL_GPL(init_fblock_tables);

void cleanup_fblock_tables(void)
{
	critbit_node_cache_destroy();
	kfree(fblmap_head);
	printk(KERN_INFO "[lana] %s cache destroyed!\n",
	       fblock_cache->name);
	kmem_cache_destroy(fblock_cache);
	printk(KERN_INFO "[lana] IDP tables removed!\n");
}
EXPORT_SYMBOL_GPL(cleanup_fblock_tables);

