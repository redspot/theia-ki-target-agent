#!/bin/bash
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
patchguard_src="${DIR}/patchguard.c"
if [ "`whoami`" != 'root' ]; then
    sed -i -e "/^MODULE_VERSION/ s/0000/${GO_PIPELINE_COUNTER}/" $patchguard_src
    PVERSION=$(grep ^MODULE_VERSION ${patchguard_src} | cut -d\" -f2)
    [ x"$PVERSION" != x ]
    PATCHGUARD_PATH="/usr/src/patchguard-${PVERSION}"
    sed -i -e "/^PACKAGE_VERSION/ s/00000/${PVERSION}/" ${PATCHGUARD_PATH}/dkms.conf
	exec sudo -E "${DIR}/$(basename $0)"
else
	if [ -e ${PATCHGUARD_PATH} -a -L ${PATCHGUARD_PATH} ]; then
		rm ${PATCHGUARD_PATH}
	elif [ -e ${PATCHGUARD_PATH} -a ! -L ${PATCHGUARD_PATH} ]; then
		exit 1
	fi
	ln -s ${DIR} ${PATCHGUARD_PATH}
    if ! dkms status patchguard/${PVERSION} | grep -q ^patchguard; then
        dkms add -m patchguard -v ${PVERSION}
    fi
fi
