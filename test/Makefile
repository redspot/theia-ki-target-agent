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

CC := gcc

CFLAGS := -Wall -Werror -g
CFLAGS += -fPIC
LDFLAGS := -Wall -Werror -g -Wl,-dynamic-linker=/lib64/ld-linux-x86-64.so.2

#LDLIBS := libutil.a

KERNEL_CONFIG := replay_headers/include/linux/replay_configs.h

DEPS_DIR := .deps

TARGETS=theia_toggle parseklog parseulog parsemlog launcher resume theia_replay parseckpt \
	getstats filemap replay_pause reset_ndx

# For automatic .h dependency tracking... may not work perfectly for launcher as
#    the include path changes for it
CFILES=$(wildcard *.c)
DEPS=$(patsubst %.c, .deps/%.d, $(CFILES))

.PHONY: all
all: $(TARGETS)

$(KERNEL_CONFIG):
	$(MAKE) -C $(KERNEL_DIR) headers_install INSTALL_HDR_PATH=`pwd`/replay_headers

# Build dependencies + any extra flags
launcher: libutil.a
launcher: CFLAGS += --static -fPIC -I../../eglibc-2.15/prefix/include -L../../eglibc-2.15/prefix/lib 

resume: libutil.a
resume: CFLAGS += --static

theia_replay: libutil.a
theia_replay: CFLAGS += --static

getstats: libutil.a

filemap: libutil.a 

parseklog: parseklib.o

rewriteklog: parseklib.o

libutil.a: util.o parseklib.o
	ar rv $@ $^
	ranlib $@

util.o parseklib.o: $(KERNEL_CONFIG)

reset_ndx: libutil.a

theia_toggle: libutil.a

.PHONY: clean
clean:
	rm -f *.a *.o $(TARGETS)
	rm -rf replay_headers/*

.deps/%.d: %.c .dep_dirs_made
	@$(CC) $(CFLAGS) -M -o $@ $<

.dep_dirs_made:
	@touch .dep_dirs_made
	@mkdir .deps

-include $(DEPS)

.PHONY: nuke
nuke: clean
	rm -rf .deps .dep_dirs_made

install: $(TARGETS)
	echo $^ | xargs -n1 | xargs -I% install -Dv % /usr/local/bin/%
