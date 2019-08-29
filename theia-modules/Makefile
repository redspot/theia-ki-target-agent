#KDIR ?= /lib/modules/$(shell uname -r)/build
KDIR ?= ../linux-lts-quantal-3.5.0/theia_build/
KBUILD_EXTRA_SYMBOLS = ../linux-lts-quantal-3.5.0/theia_build/Module.symvers
PWD := $(shell pwd)

CFLAGS_theia_core.o = -DDEBUG
CFLAGS_theia_hook.o = -DDEBUG
CFLAGS_theia_syscalls.o = -DDEBUG
CFLAGS_theia_trace.o = -DDEBUG

#core
obj-m += theia_core.o
#ftrace hooks
obj-m += theia_hook_mod.o
theia_hook_mod-objs := theia_hook.o theia_syscalls.o
#tracepoint hooks
obj-m += theia_trace.o

clean-files := theia_syscalls.h

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules CC=$(CC) 2>&1

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

$(obj)/theia_syscalls.o: $(src)/theia_syscalls.h

syscalls_header: src=$(PWD)
syscalls_header: $(src)/theia_syscalls.h

$(src)/theia_syscalls.h: $(src)/theia_syscalls.h.pre
	$(CC) -Wall -E -xc $< \
		| sed -e 's/__NL__/\n/g' \
		| sed -e 's/DEFINE/#define/g' \
		| grep -v '^# ' \
		> $@

all: default

wilson: CC := gcc-4.9
wilson:
	$(MAKE) -C $(KDIR) M=$(PWD) modules CC=$(CC) 2>&1
