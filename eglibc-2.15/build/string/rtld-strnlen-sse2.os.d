$(common-objpfx)string/rtld-strnlen-sse2.os: \
 ../sysdeps/i386/i686/multiarch/strnlen-sse2.S ../include/libc-symbols.h \
 $(common-objpfx)config.h \
 ../sysdeps/wordsize-32/symbol-hacks.h \
 ../sysdeps/i386/i686/multiarch/strlen-sse2.S

../include/libc-symbols.h:

$(common-objpfx)config.h:

../sysdeps/wordsize-32/symbol-hacks.h:

../sysdeps/i386/i686/multiarch/strlen-sse2.S:
