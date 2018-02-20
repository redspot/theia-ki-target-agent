CFLAGS := $(CFLAGS) -g3 -Wl,-dynamic-linker=/lib64/ld-linux-x86-64.so.2

all:
	$(CC) -o relay-read-file relay-read-file.c -lpthread $(CFLAGS)

clean:
	/bin/rm -rf *.o relay-read-file

