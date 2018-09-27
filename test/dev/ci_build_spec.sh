#!/bin/bash
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [ x"${GO_PIPELINE_COUNTER}" == x ]; then
    echo GO_PIPELINE_COUNTER not set. maybe this isnt running from GoCD?
    exit 1
fi

cd ${DIR}/../../linux-lts-quantal-3.5.0
cp ${DIR}/Makefile.kernel_ci Makefile
[ -d "${DIR}/../../spec_build" ] && rm -rf "${DIR}/../../spec_build"
mkdir "${DIR}/../../spec_build"
cp "${DIR}/spec.config" "${DIR}/../../spec_build/.config"
OUT="${DIR}/../../spec_build"
sed -i.bak -e "s/13+theia1/13+theia2+$(
git describe --always --long | tr - +)/" \
    "${OUT}/.config" >/dev/null

#this script is located in test/dev
export CROSS_COMPILE=${DIR}/../../linux-lts-quantal-3.5.0/debian.master/bin/
export KERNEL_DIR="${OUT}"
make oldconfig O="${OUT}" CROSS_COMPILE="${CROSS_COMPILE}" \
&& make prepare O="${OUT}" CROSS_COMPILE="${CROSS_COMPILE}" \
&& make scripts O="${OUT}" CROSS_COMPILE="${CROSS_COMPILE}"

/usr/bin/sudo -E /usr/sbin/dkms build -m spec -v 1.0-$GO_PIPELINE_COUNTER -k 3.5.0-99-generic
/usr/bin/sudo -E /usr/sbin/dkms mkdeb -m spec -v 1.0-$GO_PIPELINE_COUNTER -k 3.5.0-99-generic
