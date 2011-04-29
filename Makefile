# ksocket project
# BSD-style socket APIs for kernel 2.6 developers
# 
# @2007-2008, China
# @song.xian-guang@hotmail.com (MSN Accounts)
# 
# This code is licenced under the GPL
# Feel free to contact me if any questions
# 

#### tell make that these targets are not actual files
.PHONY: default clean

#### some variable definitions
obj-m := kcache.o
ksocket_tcp_srv-objs := ../ksocket-0.0.2/ksocket.o
KDIR  := /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)

#EXTRA_LDFLAGS := -I../../src
EXTRA_LDFLAGS := -I../ksocket-0.0.2/src

ifeq ($(ADDRSAFE),true)
    EXTRA_CFLAGS += -DKSOCKET_ADDR_SAFE
endif

#### -C means chdir to KDIR, M means set variable M to working dir
#### so ineffect, this will parse run make w/ the Makefil in /lib/modules/.../build
#### with target "modules" and variable M set to PWD. M must be module!
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	rm -rf *.ko *.o *.mod.* .H* .tm* .*cmd Module.symvers Module.markers
