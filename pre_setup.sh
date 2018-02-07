#!/bin/bash
PVERSION="1.0-${GO_PIPELINE_COUNTER}"
SPEC_PATH="/usr/src/spec-${PVERSION}"
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ "`whoami`" == 'root' ]; then
	if [ -e ${SPEC_PATH} -a -L ${SPEC_PATH} ]; then
		rm ${SPEC_PATH}
	elif [ -e ${SPEC_PATH} -a ! -L ${SPEC_PATH} ]; then
		exit 1
	fi
	ln -s ${DIR}/test/dev ${SPEC_PATH}
else
	exec sudo -E "${DIR}/$(basename $0)"
fi

sed -i -e "/^PACKAGE_VERSION/ s/0000/${GO_PIPELINE_COUNTER}/" ${SPEC_PATH}/dkms.conf

if ! dkms status spec/${PVERSION} | grep -q ^spec; then
	dkms add -m spec -v ${PVERSION}
fi
