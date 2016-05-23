$(common-objpfx)string/strncmp-sse4.o: \
 ../sysdeps/i386/i686/multiarch/strncmp-sse4.S ../include/libc-symbols.h \
 $(common-objpfx)config.h \
 ../sysdeps/wordsize-32/symbol-hacks.h

../include/libc-symbols.h:

$(common-objpfx)config.h:

../sysdeps/wordsize-32/symbol-hacks.h:
