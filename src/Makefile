#
# Lightweight Autonomic Network Architecture
#
# Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
# Swiss federal institute of technology (ETH Zurich)
# Subject to the GPL.
#

# LANA core files
obj-m += nl_vlink.o

# LANA optional modules
obj-m += fb_eth_vlink.o

MDIR := /lib/modules/$(shell uname -r)
KDIR := $(MDIR)/build
DEST := $(MDIR)/kernel/drivers/net/lana/

CORE_LD_DEP := 
CORE_ULD_DEP := 

all: build

build:
	make -C $(KDIR) M=$(PWD) modules

install:
	@install -d $(DEST)
	@cp -r *.ko $(DEST)
	@echo "modules installed"
	@depmod
	@echo "modules.dep regenerated"

uninstall:
	@rm -rf $(DEST)
	@echo "modules uninstalled"
	@depmod
	@echo "modules.dep regenerated"

load_core:
	# modprobes here
	@echo "not now"

unload_core:
	# rmmods here
	@echo "not now"

clean:
	make -C $(KDIR) M=$(PWD) clean

help:
	@echo "make <targets>"
	@echo "available targets:"
	@echo "  build         - Builds source"
	@echo "  clean         - Removes generated files"
	@echo "  install       - Installs .ko files into system"
	@echo "  uninstall     - Removes .ko files from system"
	@echo "  load_core     - Loads core modules into the kernel"
	@echo "  unload_core   - Unloads core modules from the kernel"
	@echo "  help          - Shows this help"

