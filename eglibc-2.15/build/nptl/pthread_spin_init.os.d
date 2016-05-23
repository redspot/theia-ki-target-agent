$(common-objpfx)nptl/pthread_spin_init.os: \
 ../nptl/sysdeps/unix/sysv/linux/i386/pthread_spin_init.c \
 ../include/libc-symbols.h $(common-objpfx)config.h \
 ../sysdeps/wordsize-32/symbol-hacks.h \
 ../nptl/sysdeps/i386/pthread_spin_init.c

../include/libc-symbols.h:

$(common-objpfx)config.h:

../sysdeps/wordsize-32/symbol-hacks.h:

../nptl/sysdeps/i386/pthread_spin_init.c:
