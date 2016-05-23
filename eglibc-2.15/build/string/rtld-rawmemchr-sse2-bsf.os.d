$(common-objpfx)string/rtld-rawmemchr-sse2-bsf.os: \
 ../sysdeps/i386/i686/multiarch/rawmemchr-sse2-bsf.S \
 ../include/libc-symbols.h $(common-objpfx)config.h \
 ../sysdeps/wordsize-32/symbol-hacks.h \
 ../sysdeps/i386/i686/multiarch/memchr-sse2-bsf.S

../include/libc-symbols.h:

$(common-objpfx)config.h:

../sysdeps/wordsize-32/symbol-hacks.h:

../sysdeps/i386/i686/multiarch/memchr-sse2-bsf.S:
