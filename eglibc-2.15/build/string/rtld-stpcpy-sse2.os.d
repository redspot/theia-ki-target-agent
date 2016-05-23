$(common-objpfx)string/rtld-stpcpy-sse2.os: \
 ../sysdeps/i386/i686/multiarch/stpcpy-sse2.S ../include/libc-symbols.h \
 $(common-objpfx)config.h \
 ../sysdeps/wordsize-32/symbol-hacks.h \
 ../sysdeps/i386/i686/multiarch/strcpy-sse2.S

../include/libc-symbols.h:

$(common-objpfx)config.h:

../sysdeps/wordsize-32/symbol-hacks.h:

../sysdeps/i386/i686/multiarch/strcpy-sse2.S:
