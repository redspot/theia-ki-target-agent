$(common-objpfx)string/rtld-memset-sse2.os: \
 ../sysdeps/i386/i686/multiarch/memset-sse2.S ../include/libc-symbols.h \
 $(common-objpfx)config.h \
 ../sysdeps/wordsize-32/symbol-hacks.h

../include/libc-symbols.h:

$(common-objpfx)config.h:

../sysdeps/wordsize-32/symbol-hacks.h:
