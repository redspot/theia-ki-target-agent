$(common-objpfx)csu/elf-init.oS: elf-init.c \
 ../include/libc-symbols.h $(common-objpfx)config.h \
 ../sysdeps/wordsize-32/symbol-hacks.h \
 /usr/lib/gcc/i686-linux-gnu/4.6/include/stddef.h

../include/libc-symbols.h:

$(common-objpfx)config.h:

../sysdeps/wordsize-32/symbol-hacks.h:

/usr/lib/gcc/i686-linux-gnu/4.6/include/stddef.h:
