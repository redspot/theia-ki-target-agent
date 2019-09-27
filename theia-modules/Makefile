KDIR ?= /lib/modules/$(shell uname -r)/build
#KDIR ?= ../linux-lts-quantal-3.5.0/theia_build/
PWD := $(shell pwd)

CC ?= gcc
MY_CPP := $(CC) -E
GCCVERSION := $(shell $(CC) -dumpversion)
ifeq "$(shell expr $(GCCVERSION) \< 4.9)" "1"
	MY_CPP = gcc-4.9 -E
endif

ccflags-y += -DDEBUG -I$(src) -I$(src)/include -Werror

#core
obj-m += theia_core_mod.o
theia_core_mod-objs := core_maps.o theia_core.o
#ftrace hooks
obj-m += theia_hook_mod.o
theia_hook_mod-objs := theia_hook.o theia_syscalls.o util.o serialize.o
#tracepoint hooks
obj-m += theia_trace.o

clean-files := theia_syscalls.h

default: syscalls_header
	$(MAKE) -C $(KDIR) M=$(PWD) modules CC="$(CC)" 2>&1

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

$(obj)/theia_syscalls.o: $(src)/theia_syscalls.h

src ?= $(PWD)
syscalls_header: $(src)/theia_syscalls.h

$(src)/theia_syscalls.h: $(src)/theia_syscalls.h.pre
	$(MY_CPP) -Wall -xc $< \
		| sed -e 's/__NL__/\n/g' \
		| sed -e 's/^DEFINE/#define/g' \
		| sed -e 's/^PRAGMA/#pragma/g' \
		| sed -e 's/^IFNDEF/#ifndef/g' \
		| sed -e 's/^IFDEF/#ifdef/g' \
		| sed -e 's/^ENDIF/#endif/g' \
		| grep -v '^# ' \
		| grep -v '^$$' \
		> $@

all: default

wilson: CC := gcc-4.9
wilson: default
