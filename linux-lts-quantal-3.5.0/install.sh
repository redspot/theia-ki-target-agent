#!/bin/bash

#find the location of this script
#and assume that it is in the theia-ki-target-agent/linux-lts-quantal-3.5.0 dir
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

#exit on error from any command
set -e

#run this script like "BUILD_DIR=other_dir ./install.sh" to override

BUILD_DIR="${BUILD_DIR}" ./install-modules.sh
BUILD_DIR="${BUILD_DIR}" ./install-kernel.sh
