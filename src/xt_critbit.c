/*
 * Lightweight Autonomic Network Architecture
 *
 * Original userspace code from D. J. Bernstein. (http://cr.yp.to/critbit.html)
 * Added critbit_get method hack by instead of copying strings into the nodes
 * (original version), we now hold the reference to it and fetch the container
 * structure on lookups. By doing this, we only need to guarantee, that the
 * string is power of two boundary aligned. Added RCU and kmem_cache aligned
 * node allocation support.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

/*
 * Compared to a hash table, a crit-bit tree has comparable speed and two big
 * advantages. The first advantage is that a crit-bit tree supports more fast
 * operations: finding the smallest string, for example. The second advantage
 * is that a crit-bit tree guarantees good performance: it doesn't have any
 * tricky slowdowns for unusual (or malicious) data.
 *
 * Crit-bit trees are faster than comparison-based structures such as AVL trees
 * and B-trees. They're also simpler, especially for variable-length strings.
 *
 * Crit-bit trees have the disadvantage of not (yet!) being widely appreciated.
 * Very few textbooks explain them, and very few libraries implement them.
 *                              (D. J. Bernstein, http://cr.yp.to/critbit.html)
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/cache.h>
#include <linux/rcupdate.h>

#include "xt_critbit.h"

typedef long intptr_t;

struct critbit_node {
	void *child[2];
	struct rcu_head rcu;
	u32 byte;
	u8 otherbits;
} ____cacheline_aligned;

static struct kmem_cache *critbit_node_cache = NULL;

static inline struct critbit_node *critbit_alloc_node_aligned(gfp_t flags)
{
	return kmem_cache_alloc(critbit_node_cache, flags);
}

static inline void critbit_free_node(struct critbit_node *p)
{
	kmem_cache_free(critbit_node_cache, p);
}

int __critbit_contains(struct critbit_tree *tree, const char *elem)
{
	const u8 *ubytes = (void *) elem;
	const size_t ulen = strlen(elem);
	u8 c, *p;
	struct critbit_node *q;
	int direction;

	if (unlikely(!rcu_read_lock_held()))
		return -EINVAL;
	p = rcu_dereference_raw(tree->root);
	if (!p)
		return 0;
	while (1 & (intptr_t) p) {
		c = 0;
		q = (void *) (p - 1);
		if (q->byte < ulen)
			c = ubytes[q->byte];
		direction = (1 + (q->otherbits | c)) >> 8;
		p = rcu_dereference_raw(q->child[direction]);
	}

	return (0 == strcmp(elem, (char *) p));
}
EXPORT_SYMBOL(__critbit_contains);

int critbit_contains(struct critbit_tree *tree, const char *elem)
{
	int ret;
	rcu_read_lock();
	ret = __critbit_contains(tree, elem);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(critbit_contains);

char *__critbit_get(struct critbit_tree *tree, const char *elem)
{
	const u8 *ubytes = (void *) elem;
	const size_t ulen = strlen(elem);
	u8 c, *p;
	struct critbit_node *q;
	int direction;

	if (unlikely(!rcu_read_lock_held())) {
		printk(KERN_ERR "WARNING: No rcu_read_lock held!\n");
		return NULL;
	}
	p = rcu_dereference_raw(tree->root);
	if (!p)
		return NULL;
	while (1 & (intptr_t) p) {
		c = 0;
		q = (void *) (p - 1);
		if (q->byte < ulen)
			c = ubytes[q->byte];
		direction = (1 + (q->otherbits | c)) >> 8;
		p = rcu_dereference_raw(q->child[direction]);
	}

	return (0 == strcmp(elem, (char *) p)) ? (char *) p : NULL;
}
EXPORT_SYMBOL(__critbit_get);

char *critbit_get(struct critbit_tree *tree, const char *elem)
{
	char *ret;
	rcu_read_lock();
	ret = __critbit_get(tree, elem);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(critbit_get);

int __critbit_insert(struct critbit_tree *tree, char *elem)
{
	const u8 *const ubytes = (void *) elem;
	const size_t ulen = strlen(elem);
	u8 c, *p = rcu_dereference_raw(tree->root);
	u32 newbyte, newotherbits;
	struct critbit_node *q, *newnode;
	int direction, newdirection;
	void **wherep;

	if (unlikely(!IS_ALIGNED((unsigned long) elem, SMP_CACHE_BYTES)))
		return -EINVAL;
	if (!p) {
		rcu_assign_pointer(tree->root, elem);
		return 0;
	}

	while (1 & (intptr_t) p) {
		c = 0;
		q = (void *) (p - 1);
		if (q->byte < ulen)
			c = ubytes[q->byte];
		direction = (1 + (q->otherbits | c)) >> 8;
		p = rcu_dereference_raw(q->child[direction]);
	}

	for (newbyte = 0; newbyte < ulen; ++newbyte) {
		if (p[newbyte] != ubytes[newbyte]) {
			newotherbits = p[newbyte] ^ ubytes[newbyte];
			goto different_byte_found;
		}
	}

	if (p[newbyte] != 0) {
		newotherbits = p[newbyte];
		goto different_byte_found;
	}

	return -EEXIST;

different_byte_found:
	while (newotherbits & (newotherbits - 1))
		newotherbits &= newotherbits - 1;
	newotherbits ^= 255;
	c = p[newbyte];
	newdirection = (1 + (newotherbits | c)) >> 8;
	newnode = critbit_alloc_node_aligned(GFP_ATOMIC);
	if (!newnode)
		return -ENOMEM;
	newnode->byte = newbyte;
	newnode->otherbits = newotherbits;
	newnode->child[1 - newdirection] = elem;

	for (wherep = &tree->root;;) {
		u8 *p = *wherep;
		if (!(1 & (intptr_t) p))
			break;
		q = (void *) (p - 1);
		if (q->byte > newbyte)
			break;
		if (q->byte == newbyte && q->otherbits > newotherbits)
			break;
		c = 0;
		if (q->byte < ulen)
			c = ubytes[q->byte];
		direction = (1 + (q->otherbits | c)) >> 8;
		wherep = q->child + direction;
	}

	newnode->child[newdirection] = *wherep;
	rcu_assign_pointer(*wherep, (void *) (1 + (char *) newnode));
	return 0;
}
EXPORT_SYMBOL(__critbit_insert);

int critbit_insert(struct critbit_tree *tree, char *elem)
{
	int ret;
	unsigned long flags;
	spin_lock_irqsave(&tree->wr_lock, flags);
	ret = __critbit_insert(tree, elem);
	spin_unlock_irqrestore(&tree->wr_lock, flags);
	return ret;
}
EXPORT_SYMBOL(critbit_insert);

static void critbit_do_free_rcu(struct rcu_head *rp)
{
	struct critbit_node *p = container_of(rp, struct critbit_node, rcu);
	critbit_free_node(p);
}

int __critbit_delete(struct critbit_tree *tree, const char *elem)
{
	const u8 *ubytes = (void *) elem;
	const size_t ulen = strlen(elem);
	u8 c, *p = rcu_dereference_raw(tree->root);
	void **wherep = &tree->root;
	void **whereq = NULL;
	struct critbit_node *q = NULL;
	int direction = 0;

	if (!p)
		return 0;
	while (1 & (intptr_t) p) {
		whereq = wherep;
		q = (void *) (p - 1);
		c = 0;
		if (q->byte < ulen)
			c = ubytes[q->byte];
		direction = (1 + (q->otherbits | c)) >> 8;
		wherep = q->child + direction;
		p = *wherep;
	}

	if (0 != strcmp(elem, (char *) p))
		return -ENOENT;
	/* Here, we could decrement a refcount to the elem. */
	if (!whereq) {
		tree->root = NULL;
		return 0;
	}

	rcu_assign_pointer(*whereq, q->child[1 - direction]);
	call_rcu(&q->rcu, critbit_do_free_rcu);
	return 0;
}
EXPORT_SYMBOL(__critbit_delete);

int critbit_delete(struct critbit_tree *tree, const char *elem)
{
	int ret;
	unsigned long flags;
	spin_lock_irqsave(&tree->wr_lock, flags);
	ret = __critbit_delete(tree, elem);
	spin_unlock_irqrestore(&tree->wr_lock, flags);
	return ret;
}
EXPORT_SYMBOL(critbit_delete);

int critbit_node_cache_init(void)
{
	if (critbit_node_cache)
		return -EBUSY;
	critbit_node_cache = kmem_cache_create("critbit", sizeof(struct critbit_node),
					       0, SLAB_HWCACHE_ALIGN, NULL);
	if (!critbit_node_cache)
		return -ENOMEM;
	printk(KERN_INFO "[lana] %s cache created!\n",
	       critbit_node_cache->name);
	return 0;
}
EXPORT_SYMBOL(critbit_node_cache_init);

void critbit_node_cache_destroy(void)
{
	printk(KERN_INFO "[lana] %s cache destroyed!\n",
	       critbit_node_cache->name);
	kmem_cache_destroy(critbit_node_cache);
}
EXPORT_SYMBOL(critbit_node_cache_destroy);

