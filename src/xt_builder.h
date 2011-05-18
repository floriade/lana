/*
 * Lightweight Autonomic Network Architecture
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#ifndef XT_BUILDER_H
#define XT_BUILDER_H

#include "xt_conf.h"
#include "xt_fblock.h"

extern int register_fblock_type(struct fblock_factory *fops);
extern void unregister_fblock_type(struct fblock_factory *fops);
extern struct fblock *build_fblock_object(char *type, char *name);
extern int init_fblock_builder(void);
extern void cleanup_fblock_builder(void);

#endif /* XT_BUILDER_H */

