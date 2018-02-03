#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cp ${DIR}/theia.conf /etc/modules-load.d
cp ${DIR}/99-theia-spec.rules /etc/udev/rules.d

if [ ! -e /debug ]; then
    ln -s /sys/kernel/debug /debug
fi

if [ ! -e /data ]; then
    mkdir /data 2>/dev/null || true
fi

true
