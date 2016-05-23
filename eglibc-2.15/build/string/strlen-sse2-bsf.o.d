$(common-objpfx)string/strlen-sse2-bsf.o: \
 ../sysdeps/i386/i686/multiarch/strlen-sse2-bsf.S \
 ../include/libc-symbols.h $(common-objpfx)config.h \
 ../sysdeps/wordsize-32/symbol-hacks.h

../include/libc-symbols.h:

$(common-objpfx)config.h:

../sysdeps/wordsize-32/symbol-hacks.h:
