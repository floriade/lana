# LANA core files
obj-m += nlvlink.o
# LANA optional modules
obj-m += fb_eth_vlink.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
