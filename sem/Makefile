#
# Lightweight Autonomic Network Architecture
#
# Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
# Swiss federal institute of technology (ETH Zurich)
# Subject to the GPL.
#

# TODO
#locks/double_lock.cocc                  \
#locks/flags.cocc                        \
#null/deref_null.cocc                    \
#null/kmerr.cocc                         \
#misc/doubleinit.cocc                    \
#iterators/list_entry_update.cocc        \
#free/kfree.cocc

cocc-objs  =                                         \
	     api/alloc/kzalloc-simple.cocc           \
	     api/alloc/drop_kmalloc_cast.cocc        \
	     api/err_cast.cocc                       \
	     api/memdup.cocc                         \
	     api/resource_size.cocc                  \
	     api/kstrdup.cocc                        \
	     api/memdup_user.cocc                    \
	     locks/mini_lock.cocc                    \
	     locks/call_kern.cocc                    \
	     null/eno.cocc                           \
	     misc/ifcol.cocc                         \
	     tests/doubletest.cocc                   \
	     tests/doublebitand.cocc                 \
	     tests/notnull.cocc                      \
	     iterators/itnull.cocc                   \
	     iterators/fen.cocc

chk-objs   = $(shell find ../src -name "*.[ch]")

.PHONY: $(cocc-objs)

all: $(cocc-objs)

spatch:
	wget http://coccinelle.lip6.fr/distrib/coccinelle-1.0.0-rc7.tgz
	tar xvf coccinelle-1.0.0-rc7.tgz
	cd coccinelle-1.0.0-rc7/ && ./configure --prefix=/usr/ && make && make install

$(cocc-objs): %.cocc: %.cocci
	@echo "\n++++++ Applying $< ++++++\n"
	for f in $(chk-objs) ; do                          \
		spatch -local_includes -out_place -sp_file $< $$f || exit; \
	done

clean:
	@rm *.cocci_res

