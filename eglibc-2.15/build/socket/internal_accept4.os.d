$(common-objpfx)socket/internal_accept4.os: \
 ../sysdeps/unix/sysv/linux/i386/internal_accept4.S \
 ../include/libc-symbols.h $(common-objpfx)config.h \
 ../sysdeps/wordsize-32/symbol-hacks.h

../include/libc-symbols.h:

$(common-objpfx)config.h:

../sysdeps/wordsize-32/symbol-hacks.h:
