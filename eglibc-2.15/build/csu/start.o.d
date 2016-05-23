$(common-objpfx)csu/start.o: \
 ../sysdeps/i386/elf/start.S ../include/libc-symbols.h \
 $(common-objpfx)config.h \
 ../sysdeps/wordsize-32/symbol-hacks.h ../sysdeps/generic/bp-sym.h

../include/libc-symbols.h:

$(common-objpfx)config.h:

../sysdeps/wordsize-32/symbol-hacks.h:

../sysdeps/generic/bp-sym.h:
