obj-m := spec.o

spec-y := devspec.o

ifndef KVERSION
KVERSION := $(shell uname -r)
endif

ifndef KERNEL_DIR
#KERNEL_DIR := /var/lib/go-agent/pipelines/target-agent/linux-lts-quantal-3.5.0/debian/build/build-generic
KERNEL_DIR := /lib/modules/$(KVERSION)/build
#KERNEL_DIR := $(OMNIPLAY_DIR)/linux-lts-quantal-3.5.0
#KERNEL_DIR := /home/theia/src/theia-es/linux-lts-quantal-3.5.0
#KERNEL_DIR := /usr/src/linux-headers-3.5.0-99
endif

all:
	$(MAKE) -C $(KERNEL_DIR) CROSS_COMPILE=$(CROSS_COMPILE) M=$(shell pwd) modules

clean:
	$(RM) *.o *.a .depend *.d *.ko *.mod.c

install:
	$(MAKE) -C $(KERNEL_DIR) CROSS_COMPILE=$(CROSS_COMPILE) M=$(shell pwd) INSTALL_MOD_DIR=updates/dkms modules_install
	[ -d /etc/modules-load.d ] && cp ${PWD}/theia.conf /etc/modules-load.d \
	|| { grep -q '^spec$$' /etc/modules || echo spec >> /etc/modules ; }
	[ -f /etc/udev/rules.d/99-theia-spec.rules ] || cp ${PWD}/99-theia-spec.rules /etc/udev/rules.d
	[ ! -e /debug ] && ln -s /sys/kernel/debug /debug
	[ ! -e /data ] && mkdir /data 2>/dev/null || true
