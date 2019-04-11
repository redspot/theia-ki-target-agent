../configure \
--prefix=/usr/local/eglibc \
--disable-profile \
--enable-add-on \
--without-gd \
--without-selinux \
--without-cvs \
--enable-kernel=3.2.0 \
--target=x86_64-linux-gnu \
--host=x86_64-linux-gnu \
CC=gcc-4.7
