obj-m := spec.o

spec-y := devspec.o

ifndef KVERSION
KVERSION := $(shell uname -r)
endif

KERNEL_DIR := /lib/modules/$(KVERSION)/build
#KERNEL_DIR := $(OMNIPLAY_DIR)/linux-lts-quantal-3.5.0
#KERNEL_DIR := /home/theia/src/theia-es/linux-lts-quantal-3.5.0
#KERNEL_DIR := /usr/src/linux-headers-3.5.0-99

all:
	$(MAKE) -C $(KERNEL_DIR) CROSS_COMPILE=$(CROSS_COMPILE) SUBDIRS=$(shell pwd) modules

clean:
	$(RM) *.o *.a .depend *.d *.ko *.mod.c

install:
	install spec.ko /lib/modules/$(shell uname -r)/kernel/fs/
	/sbin/depmod
