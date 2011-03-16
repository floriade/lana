#
# Lightweight Autonomic Network Architecture
#
# Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
# Swiss federal institute of technology (ETH Zurich)
# Subject to the GPL.
#

LD_NORM      = echo "LD        $<"; \
               gcc -pie -z relo
CC_NORM      = echo "CC        $<"; \
               gcc

LD           = $(LD_NORM) -o
CC           = $(CC_NORM) -c

MAKEFLAGS   += --no-print-directory

BINDIR       = usr/sbin
ETCDIR       = etc

CFLAGS      += -O2 -fno-delete-null-pointer-checks -std=gnu99 -pedantic
CFLAGS      += -fstack-protector -D_FORTIFY_SOURCE=2 -fPIE -D_REENTRANT
CFLAGS      += -Wall -Werror -Wundef -Wstrict-prototypes -Wuninitialized

INCLUDE      = -I../src/

fbcfg-libs   =
fbcfg-objs   = fbcfg.o
fbcfg-targ   = fbcfg

vlink-libs   =
vlink-objs   = vlink.o
vlink-targ   = vlink

all: build

build: build_vlink build_fbcfg

build_vlink: $(vlink-objs)
	@$(LD) $(vlink-targ) $(vlink-objs) $(vlink-libs)

build_fbcfg: $(fbcfg-objs)
	@$(LD) $(fbcfg-targ) $(fbcfg-objs) $(fbcfg-libs)

%.o: %.c
	@$(CC) $(CFLAGS) $(INCLUDE) $<

install:
	@install -D $(vlink-targ) $(DESTDIR)/$(BINDIR)/$(vlink-targ)
	@install -D $(fbcfg-targ) $(DESTDIR)/$(BINDIR)/$(fbcfg-targ)

uninstall:
	@rm $(DESTDIR)/$(BINDIR)/$(vlink-targ)
	@rm $(DESTDIR)/$(BINDIR)/$(fbcfg-targ)

clean:
	@rm *.o *~ $(vlink-targ) $(fbcfg-targ)

help:
	@echo "make <targets>"
	@echo "available targets:"
	@echo "  build         - Builds source"
	@echo "  clean         - Removes generated files"
	@echo "  install       - Installs userspace tools into system"
	@echo "  uninstall     - Removes userspace tools from system"
	@echo "  help          - Shows this help"

