$(common-objpfx)nptl/pthread_spin_trylock.os: \
 ../nptl/sysdeps/i386/i686/pthread_spin_trylock.S \
 ../include/libc-symbols.h $(common-objpfx)config.h \
 ../sysdeps/wordsize-32/symbol-hacks.h \
 ../nptl/sysdeps/i386/i686/../i486/pthread_spin_trylock.S \
 $(common-objpfx)pthread-errnos.h

../include/libc-symbols.h:

$(common-objpfx)config.h:

../sysdeps/wordsize-32/symbol-hacks.h:

../nptl/sysdeps/i386/i686/../i486/pthread_spin_trylock.S:

$(common-objpfx)pthread-errnos.h:
