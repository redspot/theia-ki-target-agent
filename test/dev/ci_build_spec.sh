#!/bin/bash
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [ x"${GO_PIPELINE_COUNTER}" == x ]; then
    echo GO_PIPELINE_COUNTER not set. maybe this isnt running from GoCD?
    exit 1
fi
#this script is located in test/dev
export CROSS_COMPILE=${DIR}/../../linux-lts-quantal-3.5.0/debian.master/bin/
export KERNEL_DIR=${DIR}/../../linux-lts-quantal-3.5.0
/usr/bin/sudo -E /usr/sbin/dkms build -m spec -v 1.0-$GO_PIPELINE_COUNTER -k 3.5.0-99-generic
/usr/bin/sudo -E /usr/sbin/dkms mkdeb -m spec -v 1.0-$GO_PIPELINE_COUNTER -k 3.5.0-99-generic
