#!/bin/bash
make install
if [ ! -L /usr/local/eglibc/locale ]; then
    pushd /usr/local/eglibc
    ln -s /usr/lib/locale locale
    popd
fi
