/*
 * Lightweight Autonomic Network Architecture
 *
 * Hashing functions derived from Bob Jenkins.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/types.h>
#include <linux/module.h>
#include <asm/byteorder.h>

#include "xt_idp.h"
#include "xt_hash.h"

#ifdef __LITTLE_ENDIAN
__u32 hash_string(const char *key, size_t len)
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
__u32 hash_string(const char *key, size_t len)
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
EXPORT_SYMBOL(hash_string);

