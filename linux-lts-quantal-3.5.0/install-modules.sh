#!/bin/bash

#find the location of this script
#and assume that it is in the theia-ki-target-agent/linux-lts-quantal-3.5.0 dir
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

#exit on error from any command
set -e

#run this script like "BUILD_DIR=other_dir ./install-modules.sh" to override
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

#install kernel modules
make -j$build_parallel O="${DIR}/${BUILD_DIR}" CC="$CC" modules_install
