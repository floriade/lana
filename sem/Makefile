#
# Lightweight Autonomic Network Architecture
#
# Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
# Swiss federal institute of technology (ETH Zurich)
# Subject to the GPL.
#

cocc-objs  = api/alloc/drop_kmalloc_cast.cocc        \
	     api/alloc/kzalloc-simple.cocc           \
	     api/err_cast.cocc                       \
	     api/memdup.cocc                         \
	     api/resource_size.cocc                  \
	     api/kstrdup.cocc                        \
	     api/memdup_user.cocc                    \
	     locks/mini_lock.cocc                    \
	     locks/flags.cocc                        \
	     locks/call_kern.cocc                    \
	     locks/double_lock.cocc                  \
	     null/deref_null.cocc                    \
	     null/kmerr.cocc                         \
	     null/eno.cocc                           \
	     misc/ifcol.cocc                         \
	     misc/doubleinit.cocc                    \
	     tests/doubletest.cocc                   \
	     tests/doublebitand.cocc                 \
	     iterators/itnull.cocc                   \
	     iterators/list_entry_update.cocc        \
	     iterators/fen.cocc                      \
	     free/kfree.cocc 
chk-objs   = $(shell find ../src -name "*.[ch]")

.PHONY: $(cocc-objs)

all: $(cocc-objs)

$(cocc-objs): %.cocc: %.cocci
	@for f in $(chk-objs) ; do        \
		spatch -sp_file $< $$f ;  \
	done

