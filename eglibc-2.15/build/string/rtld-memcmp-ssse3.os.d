$(common-objpfx)string/rtld-memcmp-ssse3.os: \
 ../sysdeps/i386/i686/multiarch/memcmp-ssse3.S ../include/libc-symbols.h \
 $(common-objpfx)config.h \
 ../sysdeps/wordsize-32/symbol-hacks.h

../include/libc-symbols.h:

$(common-objpfx)config.h:

../sysdeps/wordsize-32/symbol-hacks.h:
