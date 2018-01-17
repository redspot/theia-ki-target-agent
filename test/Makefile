CC := gcc

CFLAGS := -Wall -Werror -g 
CFLAGS += -fPIC 
LDFLAGS := -Wall -Werror -g -Wl,-dynamic-linker=/lib64/ld-linux-x86-64.so.2

#LDLIBS := libutil.a

KERN_CONFIG := replay_headers/include/linux/replay_configs.h

DEPS_DIR := .deps

TARGETS=theia_toggle parseklog parseulog parsemlog launcher resume theia_replay parseckpt \
	getstats filemap replay_pause reset_ndx

# For automatic .h dependency tracking... may not work perfectly for launcher as
#    the include path changes for it
CFILES=$(wildcard *.c)
DEPS=$(patsubst %.c, .deps/%.d, $(CFILES))

.PHONY: all
all: $(TARGETS)

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

parseklib.o: $(KENREL_CONFIG)

reset_ndx: libutil.a

theia_toggle: libutil.a

.PHONY: clean
clean:
	rm -f *.a *.o $(TARGETS)

.deps/%.d: %.c .dep_dirs_made
	@$(CC) $(CFLAGS) -M -o $@ $<

.dep_dirs_made:
	@touch .dep_dirs_made
	@mkdir .deps

-include $(DEPS)

.PHONY: nuke
nuke: clean
	rm -rf .deps .dep_dirs_made

