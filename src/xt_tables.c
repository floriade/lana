/*
 * Lightweight Autonomic Network Architecture
 *
 * Global LANA IDP translation tables, core backend. Hashing functions
 * derived from Bob Jenkins. Implemented as RCU protected hash tables
 * with bucket lists.
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

#include "xt_tables.h"
#include "xt_fblock.h"
#include "xt_idp.h"

#define HASHTPO2SIZ 9 /* Default: 512 slots */
#define HASHSIZE(n) ((__u32) 1 << (n))
#define HASHTSIZ    HASHSIZE(HASHTPO2SIZ)
#define HASHMASK(n) (HASHSIZE(n) - 1)
#define HASHSLOT(n) ((n) & HASHMASK(HASHTPO2SIZ))
#define HASHINITVAL 0xACDC

#define ROT(x,k) (((x) << (k)) | ((x) >> (32 - (k))))
#define MIX(a, b, c) {                     \
	a -= c;  a ^= ROT(c,  4);  c += b; \
	b -= a;  b ^= ROT(a,  6);  a += c; \
	c -= b;  c ^= ROT(b,  8);  b += a; \
	a -= c;  a ^= ROT(c, 16);  c += b; \
	b -= a;  b ^= ROT(a, 19);  a += c; \
	c -= b;  c ^= ROT(b,  4);  b += a; }
#define FINAL(a, b, c) {                  \
	c ^= b; c -= ROT(b, 14);          \
	a ^= c; a -= ROT(c, 11);          \
	b ^= a; b -= ROT(a, 25);          \
	c ^= b; c -= ROT(b, 16);          \
	a ^= c; a -= ROT(c,  4);          \
	b ^= a; b -= ROT(a, 14);          \
	c ^= b; c -= ROT(b, 24); }

struct str_idp_elem {
	idp_t idp;
	char name[FBNAMSIZ];
	struct idp_fb_elem *next;
	struct rcu_head rcu;
	atomic_t refcnt;
} ____cacheline_aligned_in_smp;

static atomic_t idp_counter;
static struct str_idp_elem **str_idp_head = NULL;
static struct fblock **idp_fbl_head = NULL;
static spinlock_t idp_fbl_head_lock = __SPIN_LOCK_UNLOCKED(idp_fbl_head_lock);

static inline __u32 hash_idp(const idp_t k)
{
	__u32 a,b,c;
	a = b = c = 0xdeadbeef + (((uint32_t) 1) << 2) + HASHINITVAL;
	a =+ k;
	FINAL(a, b, c);
	return HASHSLOT(c);
}

#ifdef __LITTLE_ENDIAN
static __u32 hash_string(const char *key, size_t len)
{
	__u32 a,b,c;
	union {
		const void *ptr;
		size_t i;
	} u; /* Needed for Mac Powerbook G4 */
	a = b = c = 0xdeadbeef + ((uint32_t) len) + HASHINITVAL;
	u.ptr = key;

	if ((u.i & 0x3) == 0) {
		/* 32 Bit chunks */
		const __u32 *k = (const __u32 *) key;

		/*
		 * All but last block: aligned reads and affect 32 bits
		 * of (a,b,c).
		 */
		while (len > 12) {
			a += k[0];
			b += k[1];
			c += k[2];
			MIX(a, b, c);
			len -= 12;
			k += 3;
		}

		/*
		 * Handle the last (probably partial) block:
		 * "k[2]&0xffffff" actually reads beyond the end of the
		 * string, but then masks off the part it's not allowed
		 * to read.  Because the string is aligned, the masked-off
		 * tail is in the same word as the rest of the string.
		 * Every machine with memory protection I've seen does it
		 * on word boundaries, so is OK with this. But VALGRIND
		 * will still catch it and complain.  The masking trick does
		 * make the hash noticably faster for short strings (like
		 * English words).
		 */
		switch (len) {
		case 12:
			c += k[2];
			b += k[1];
			a += k[0];
			break;
		case 11:
			c += k[2] & 0xffffff;
			b += k[1];
			a += k[0];
			break;
		case 10:
			c += k[2] & 0xffff;
			b += k[1];
			a += k[0];
			break;
		case  9:
			c += k[2] & 0xff;
			b += k[1];
			a += k[0];
			break;
		case  8:
			b += k[1];
			a += k[0];
			break;
		case  7:
			b += k[1] & 0xffffff;
			a += k[0];
			break;
		case  6:
			b += k[1] & 0xffff;
			a += k[0];
			break;
		case  5:
			b += k[1] & 0xff;
			a += k[0];
			break;
		case  4:
			a += k[0];
			break;
		case  3:
			a += k[0] & 0xffffff;
			break;
		case  2:
			a += k[0] & 0xffff;
			break;
		case  1:
			a += k[0] & 0xff;
			break;
		case  0:
			return c;
		}
	} else if ((u.i & 0x1) == 0) {
		/* 16 Bit chunks */
		const __u16 *k = (const __u16 *) key;
		const __u8  *k8;

		/* All but last block: aligned reads and different mixing */
		while (len > 12) {
			a += k[0] + (((__u32) k[1]) << 16);
			b += k[2] + (((__u32) k[3]) << 16);
			c += k[4] + (((__u32) k[5]) << 16);
			MIX(a, b, c);
			len -= 12;
			k += 6;
		}

		/* Handle the last (probably partial) block */
		k8 = (const __u8 *) k;
		switch (len) {
		case 12:
			c += k[4] + (((__u32) k[5]) << 16);
			b += k[2] + (((__u32) k[3]) << 16);
			a += k[0] + (((__u32) k[1]) << 16);
			break;
		case 11:
			c += ((__u32) k8[10]) << 16;
		case 10:
			c += k[4];
			b += k[2] + (((__u32) k[3]) << 16);
			a += k[0] + (((__u32) k[1]) << 16);
			break;
		case  9:
			c += k8[8];
		case  8:
			b += k[2] + (((__u32) k[3]) << 16);
			a += k[0] + (((__u32) k[1]) << 16);
			break;
		case  7:
			b += ((__u32) k8[6]) << 16;
		case  6:
			b += k[2];
			a += k[0] + (((__u32) k[1]) << 16);
			break;
		case  5:
			b += k8[4];
		case  4:
			a += k[0] + (((__u32) k[1]) << 16);
			break;
		case  3:
			a += ((__u32) k8[2]) << 16;
		case  2:
			a += k[0];
			break;
		case  1:
			a += k8[0];
			break;
		case  0:
			return c;
		}
	} else {
		/* Need to read the key one byte at a time */
		const __u8 *k = (const __u8 *) key;

		/* All but the last block: affect some 32 bits of (a,b,c) */
		while (len > 12) {
			a += k[0];
			a += ((__u32) k[1]) << 8;
			a += ((__u32) k[2]) << 16;
			a += ((__u32) k[3]) << 24;
			b += k[4];
			b += ((__u32) k[5]) << 8;
			b += ((__u32) k[6]) << 16;
			b += ((__u32) k[7]) << 24;
			c += k[8];
			c += ((__u32) k[9]) << 8;
			c += ((__u32) k[10]) << 16;
			c += ((__u32) k[11]) << 24;
			MIX(a, b, c);
			len -= 12;
			k += 12;
		}

		/* Last block: affect all 32 bits of (c) */
		switch (len) {
		case 12:
			c += ((__u32) k[11]) << 24;
		case 11:
			c += ((__u32) k[10]) << 16;
		case 10:
			c += ((__u32) k[9]) << 8;
		case  9:
			c += k[8];
		case  8:
			b += ((__u32) k[7]) << 24;
		case  7:
			b += ((__u32) k[6]) << 16;
		case  6:
			b += ((__u32) k[5]) << 8;
		case  5:
			b += k[4];
		case  4:
			a += ((__u32) k[3]) << 24;
		case  3:
			a += ((__u32) k[2]) << 16;
		case  2:
			a += ((__u32) k[1]) << 8;
		case  1:
			a += k[0];
			break;
		case  0:
			return c;
		}
	}

	FINAL(a, b, c);
	return HASHSLOT(c);
}
#else
# ifndef __BIG_ENDIAN
# error "Fix your endianess!"
# endif
static __u32 hash_string(const char *key, size_t len)
{
	__u32 a,b,c;
	union {
		const void *ptr;
		size_t i;
	} u; /* To cast key to (size_t) happily */
	a = b = c = 0xdeadbeef + ((__u32) len) + HASHINITVAL;
	u.ptr = key;

	if ((u.i & 0x3) == 0) {
		/* 32 Bit chunks */
		const __u32 *k = (const __u32 *) key;

		/*
		 * All but last block: aligned reads and affect 32 bits
		 * of (a,b,c).
		 */
		while (len > 12) {
			a += k[0];
			b += k[1];
			c += k[2];
			MIX(a, b, c);
			len -= 12;
			k += 3;
		}

		/*
		 * Handle the last (probably partial) block:
		 * "k[2]<<8" actually reads beyond the end of the string,
		 * but then shifts out the part it's not allowed to read.
		 * Because the string is aligned, the illegal read is in the
		 * same word as the rest of the string.  Every machine with
		 * memory protection I've seen does it on word boundaries,
		 * so is OK with this. But VALGRIND will still catch it and
		 * complain.  The masking trick does make the hash noticably
		 * faster for short strings (like English words).
		 */
		switch (len) {
		case 12:
			c += k[2];
			b += k[1];
			a += k[0];
			break;
		case 11:
			c += k[2] & 0xffffff00;
			b += k[1];
			a += k[0];
			break;
		case 10:
			c += k[2] & 0xffff0000;
			b += k[1];
			a += k[0];
			break;
		case  9:
			c += k[2] & 0xff000000;
			b += k[1];
			a += k[0];
			break;
		case  8:
			b += k[1];
			a += k[0];
			break;
		case  7:
			b += k[1] & 0xffffff00;
			a += k[0];
			break;
		case  6:
			b += k[1] & 0xffff0000;
			a += k[0];
			break;
		case  5:
			b += k[1] & 0xff000000;
			a += k[0];
			break;
		case  4:
			a += k[0];
			break;
		case  3:
			a += k[0] & 0xffffff00;
			break;
		case  2:
			a += k[0] & 0xffff0000;
			break;
		case  1:
			a += k[0] & 0xff000000;
			break;
		case  0:
			return c;
		}
	} else {
		/* Need to read the key one byte at a time */
		const __u8 *k = (const __u8 *) key;

		/* All but the last block: affect some 32 bits of (a,b,c) */
		while (len > 12) {
			a += ((__u32) k[0]) << 24;
			a += ((__u32) k[1]) << 16;
			a += ((__u32) k[2]) << 8;
			a += ((__u32) k[3]);
			b += ((__u32) k[4]) << 24;
			b += ((__u32) k[5]) << 16;
			b += ((__u32) k[6]) << 8;
			b += ((__u32) k[7]);
			c += ((__u32) k[8]) << 24;
			c += ((__u32) k[9]) << 16;
			c += ((__u32) k[10]) << 8;
			c += ((__u32) k[11]);
			MIX(a, b, c);
			len -= 12;
			k += 12;
		}

		/* Last block: affect all 32 bits of (c) */
		switch (len) {
		case 12:
			c += k[11];
		case 11:
			c += ((__u32) k[10]) << 8;
		case 10:
			c += ((__u32) k[9]) << 16;
		case  9:
			c += ((__u32) k[8]) << 24;
		case  8:
			b += k[7];
		case  7:
			b += ((__u32) k[6]) << 8;
		case  6:
			b += ((__u32) k[5]) << 16;
		case  5:
			b += ((__u32) k[4]) << 24;
		case  4:
			a += k[3];
		case  3:
			a += ((__u32) k[2]) << 8;
		case  2:
			a += ((__u32) k[1]) << 16;
		case  1:
			a += ((__u32) k[0]) << 24;
			break;
		case  0:
			return c;
		}
	}

	FINAL(a, b, c);
	return c;
}
#endif

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
	int c = atomic_read(&idp_counter);

	p->idp = atomic_inc_return(&idp_counter);
	if (unlikely(c > p->idp))
		panic("Too many functional blocks loaded!\n");
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

int init_tables(void)
{
	int ret = 0;

	str_idp_head = kzalloc(sizeof(*str_idp_head) * HASHTSIZ, GFP_KERNEL);
	if (!str_idp_head)
		return -ENOMEM;

	idp_fbl_head = kzalloc(sizeof(*idp_fbl_head) * HASHTSIZ, GFP_KERNEL);
	if (!idp_fbl_head)
		goto err;

	atomic_set(&idp_counter, 0);

	printk(KERN_INFO "[lana] IDP tables with size %u initialized!\n",
	       HASHTSIZ);
	return 0;
err:
	kfree(str_idp_head);
	return ret;
}
EXPORT_SYMBOL_GPL(init_tables);

void cleanup_tables(void)
{
	kfree(str_idp_head);
	kfree(idp_fbl_head);
	printk(KERN_INFO "[lana] IDP tables removed!\n");
}
EXPORT_SYMBOL_GPL(cleanup_tables);

