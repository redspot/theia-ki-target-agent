#!/bin/bash

#find the location of this script
#and assume that it is in the theia-ki-target-agent/linux-lts-quantal-3.5.0 dir
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

#exit on error from any command
set -e

#run this script like "BUILD_DIR=other_dir ./install-kernel.sh" to override
if [ -z "${BUILD_DIR}" ]; then
  BUILD_DIR=theia_build
fi

num_cores=`cat /proc/cpuinfo | grep processor | wc -l`
build_parallel=$(($num_cores+1))

CC=gcc
#use ccache if available
if which ccache >/dev/null; then
  CC="ccache gcc"
fi

#install kernel
make -j$build_parallel O="${DIR}/${BUILD_DIR}" CC="$CC" install

KVERSION=$(make -j$build_parallel O="${DIR}/${BUILD_DIR}" CC="$CC" kernelrelease)
DEBUG_KERNEL=/usr/lib/debug/boot/vmlinux-${KVERSION}
if [ -f ${DEBUG_KERNEL} ]; then
    rm ${DEBUG_KERNEL}
fi
cp "${DIR}/${BUILD_DIR}/vmlinux" ${DEBUG_KERNEL}
ls -lh ${DEBUG_KERNEL}
orig_user=$([ x"$SUDO_USER" != x ] && echo $SUDO_USER || id -un)
orig_group=$([ x"$SUDO_GID" != x ] && (getent group $SUDO_GID | cut -d: -f1) ||
    id -gn)
sudo chown ${orig_user}:${orig_group} -R ${DIR}
