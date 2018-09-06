#!/bin/bash
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# check env for non-empty vars
# ${!v} is bash-specific indirect var reference
# v=VAR; VAR=1; echo ${v} = ${!v}  # should output 'VAR = 1'
for v in GO_PIPELINE_NAME GO_PIPELINE_COUNTER
do
    if [ x"${!v}" == x ]; then
        # pre_setup.sh does different things for different pipelines
        # so, provide correct vars
        echo ${v} not set. maybe this isnt running from GoCD?
        exit 1
    fi
done

if [ "${GO_PIPELINE_NAME}" == "target-spec" ]; then
    pipeline_prefix="spec"
elif [ "${GO_PIPELINE_NAME}" == "target-patchguard" ]; then
    pipeline_prefix="pg"
else
    # pre_setup.sh gets run by a few pipelines that dont need it
    exit 0
fi

spec_unpriv() {
    # SPEC_VER is independent from the code base
    export SPEC_VER="1.0-${GO_PIPELINE_COUNTER}"
    export SPEC_PATH="/usr/src/spec-${SPEC_VER}"
    sed -i -e "/^PACKAGE_VERSION/ s/0000/${GO_PIPELINE_COUNTER}/" ${DIR}/test/dev/dkms.conf
}
spec_priv() {
    # if symlink, then delete and replace. we have 2 gocd agents, so paths can change
    if [ -e ${SPEC_PATH} -a -L ${SPEC_PATH} ]; then
        rm ${SPEC_PATH}
    # if exists and not a symlink, dont nuke it
    elif [ -e ${SPEC_PATH} -a ! -L ${SPEC_PATH} ]; then
        exit 1
    fi
    ln -s ${DIR}/test/dev ${SPEC_PATH}
    # dkms will not rebuild even if code changes. so, rotate in by version num to force
    if ! dkms status spec/${SPEC_VER} | grep -q ^spec; then
        dkms add -m spec -v ${SPEC_VER}
    fi
}
pg_unpriv() {
    patchguard_src="${DIR}/patchguard/patchguard.c"
    # PG_VER is not independent from code base
    # e.g. MODULE_VERSION("1.1-0000") gets pipeline counter
    # AND devs (us) can bump 1.1 up for compat reasons.
    # really, spec mod should be the same way
    sed -i -e "/^MODULE_VERSION/ s/0000/${GO_PIPELINE_COUNTER}/" $patchguard_src
    export PG_VER=$(grep ^MODULE_VERSION ${patchguard_src} | cut -d\" -f2)
    [ x"$PG_VER" != x ]
    export PATCHGUARD_PATH="/usr/src/patchguard-${PG_VER}"
    sed -i -e "/^PACKAGE_VERSION/ s/0000/${PG_VER}/" ${DIR}/patchguard/dkms.conf
}
pg_priv() {
    # if symlink, then delete and replace. we have 2 gocd agents, so paths can change
	if [ -e ${PATCHGUARD_PATH} -a -L ${PATCHGUARD_PATH} ]; then
		rm ${PATCHGUARD_PATH}
    # if exists and not a symlink, dont nuke it
	elif [ -e ${PATCHGUARD_PATH} -a ! -L ${PATCHGUARD_PATH} ]; then
		exit 1
	fi
	ln -s ${DIR}/patchguard ${PATCHGUARD_PATH}
    # dkms will not rebuild even if code changes. so, rotate in by version num to force
    if ! dkms status patchguard/${PG_VER} | grep -q ^patchguard; then
        dkms add -m patchguard -v ${PG_VER}
    fi
}

if [ "`whoami`" != 'root' ]; then
    [ x"${pipeline_prefix}" != x ]
    ${pipeline_prefix}_unpriv
    # sudoers allows 'go' to exec target-*/pre_setup.sh
    # but not target-*/subdir/pre_setup.sh
    exec sudo -E "${DIR}/$(basename $0)"
else
    ${pipeline_prefix}_priv
fi
