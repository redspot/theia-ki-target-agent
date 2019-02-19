#!/bin/bash
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
patchguard_src="${DIR}/patchguard.c"
PVERSION=$(grep ^MODULE_VERSION ${patchguard_src} | cut -d\" -f2)
ARTIFACT=${DIR}/../ci-build-path.target-spec
if [ -f $ARTIFACT ]; then
    export KERNEL_DIR="$(cat ${ARTIFACT} | xargs)/spec_build"
else
    echo could not find \"$ARTIFACT\". module symbols will not match.
fi
/usr/bin/sudo -E /usr/sbin/dkms build -m patchguard -v $PVERSION -k 3.5.0-99-generic
/usr/bin/sudo -E /usr/sbin/dkms mkdeb -m patchguard -v $PVERSION -k 3.5.0-99-generic
/bin/cp /var/lib/dkms/patchguard/$PVERSION/deb/*.deb .
