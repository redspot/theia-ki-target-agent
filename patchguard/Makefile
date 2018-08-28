obj-m += patchguard.o
CFLAGS_patchguard.o += -g3

ifndef KVERSION
KVERSION := $(shell uname -r)
endif

ifndef KERNEL_DIR
KERNEL_DIR := /lib/modules/$(KVERSION)/build
endif

clean:
	$(MAKE) -C $(KERNEL_DIR) CROSS_COMPILE=$(CROSS_COMPILE) SUBDIRS=`pwd` clean

all:
	$(MAKE) -C $(KERNEL_DIR) CROSS_COMPILE=$(CROSS_COMPILE) SUBDIRS=`pwd` modules
