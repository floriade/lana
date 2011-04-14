/*
 * Lightweight Autonomic Network Architecture
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#ifndef XT_HASH_H
#define XT_HASH_H

#include <linux/types.h>

/* Default: 512 slots */
#define HASHTPO2SIZ 9
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

static inline __u32 hash_idp(const idp_t k)
{
        __u32 a,b,c;
	if (k < HASHTSIZ)
		return k;
        a = b = c = 0xdeadbeef + (((uint32_t) 1) << 2) + HASHINITVAL;
        a =+ k;
        FINAL(a, b, c);
        return HASHSLOT(c);
}

extern __u32 hash_string(const char *key, size_t len);

#endif /* XT_HASH_H */
