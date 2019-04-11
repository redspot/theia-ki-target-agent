#!/bin/bash
make install
if [ ! -L /usr/local/eglibc/locale ]; then
    pushd /usr/local/eglibc
    ln -s /usr/lib/locale locale
    popd
fi
cp ld.so.conf.theia /usr/local/eglibc/etc/ld.so.conf
rm -f /usr/local/eglibc/etc/ld.so.cache
