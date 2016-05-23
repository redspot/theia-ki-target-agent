$(common-objpfx)string/rtld-memcmp-sse4.os: \
 ../sysdeps/i386/i686/multiarch/memcmp-sse4.S ../include/libc-symbols.h \
 $(common-objpfx)config.h \
 ../sysdeps/wordsize-32/symbol-hacks.h

../include/libc-symbols.h:

$(common-objpfx)config.h:

../sysdeps/wordsize-32/symbol-hacks.h:
