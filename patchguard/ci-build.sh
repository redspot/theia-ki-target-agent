#!/bin/bash
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
patchguard_src="${DIR}/patchguard.c"
#the pre_setup.sh script updates the MODULE_VERSION
#with the pipeline counter
PVERSION=$(grep ^MODULE_VERSION ${patchguard_src} | cut -d\" -f2)
#get proper kernel build dir from spec module, with current Module.symvers
ARTIFACT=${DIR}/../ci-build-path.target-spec
if [ -f $ARTIFACT ]; then
    export KERNEL_DIR="$(cat ${ARTIFACT} | xargs)/spec_build"
else
    echo could not find \"$ARTIFACT\". module symbols will not match.
fi
export CROSS_COMPILE=${DIR}/../linux-lts-quantal-3.5.0/debian.master/bin/
/usr/bin/sudo -E /usr/sbin/dkms build -m patchguard -v $PVERSION -k 3.5.0-99-generic
/usr/bin/sudo -E /usr/sbin/dkms mkdeb -m patchguard -v $PVERSION -k 3.5.0-99-generic
/usr/bin/sudo ${DIR}/../fix-owner.sh
/bin/cp /var/lib/dkms/patchguard/$PVERSION/deb/*.deb .
