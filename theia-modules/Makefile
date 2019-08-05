KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

CFLAGS_theia_core.o = -DDEBUG
CFLAGS_theia_hook.o = -DDEBUG
CFLAGS_theia_syscalls.o = -DDEBUG
CFLAGS_theia_trace.o = -DDEBUG

#core
obj-m += theia_core.o
#ftrace hooks
obj-m += theia_hook.o
theia_hook-objs := theia_syscalls.o
#tracepoint hooks
obj-m += theia_trace.o

clean-files := theia_syscalls.h

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules CC=$(CC)

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

$(obj)/theia_syscalls.o: $(src)/theia_syscalls.h

$(src)/theia_syscalls.h: $(src)/theia_syscalls.h.pre
	$(CC) -Wall -E -xc $< \
		| sed -e $$'s/__NL__/\\\n/g' \
		| sed -e 's/DEFINE/#define/g' \
		| grep -v '^# ' \
		> $@

all: default

wilson: KDIR := ../linux-lts-quantal-3.5.0/theia_build/
wilson: CC := /home/linuxbrew/.linuxbrew/bin/gcc-4.9
wilson:
	$(MAKE) -C $(KDIR) M=$(PWD) modules CC=$(CC) 2>&1
