#
# Lightweight Autonomic Network Architecture
#
# Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
# Swiss federal institute of technology (ETH Zurich)
# Subject to the GPL.
#

cocc-objs-p  =                                       \
	     api/alloc/kzalloc-simple.cocc           \
	     api/alloc/drop_kmalloc_cast.cocc        \
	     api/err_cast.cocc                       \
	     api/memdup.cocc                         \
	     api/resource_size.cocc                  \
	     api/kstrdup.cocc                        \
	     api/memdup_user.cocc                    \
	     locks/call_kern.cocc                    \
	     null/eno.cocc                           \
	     iterators/itnull.cocc                   \
	     iterators/fen.cocc

cocc-objs-n  =                                       \
	     tests/notnull.cocc

cocc-objs-r  =                                       \
	     locks/double_lock.cocc                  \
	     locks/flags.cocc                        \
	     locks/mini_lock.cocc                    \
	     null/kmerr.cocc                         \
	     null/deref_null.cocc                    \
	     free/kfree.cocc                         \
	     iterators/list_entry_update.cocc        \
	     tests/doubletest.cocc                   \
	     tests/doublebitand.cocc                 \
	     misc/doubleinit.cocc                    \
	     misc/ifcol.cocc

chk-objs   = $(shell find ../src -name "*.[ch]")

.PHONY: $(cocc-objs)

all: $(cocc-objs-p) $(cocc-objs-r) $(cocc-objs-n)

spatch:
	wget http://coccinelle.lip6.fr/distrib/coccinelle-1.0.0-rc7.tgz
	tar xvf coccinelle-1.0.0-rc7.tgz
	cd coccinelle-1.0.0-rc7/ && ./configure --prefix=/usr/ && make depend && make all && make install

$(cocc-objs-p): %.cocc: %.cocci
	@echo "\n++++++ Applying $< ++++++\n"
	for f in $(chk-objs) ; do                          \
		spatch -D patch -local_includes -out_place -sp_file $< $$f || exit; \
	done

$(cocc-objs-n): %.cocc: %.cocci
	@echo "\n++++++ Applying $< ++++++\n"
	for f in $(chk-objs) ; do                          \
		spatch -local_includes -out_place -sp_file $< $$f || exit; \
	done

$(cocc-objs-r): %.cocc: %.cocci
	@echo "\n++++++ Applying $< ++++++\n"
	for f in $(chk-objs) ; do                          \
		spatch -D report -local_includes -out_place -sp_file $< $$f || exit; \
	done

clean:
	@rm *.cocci_res

