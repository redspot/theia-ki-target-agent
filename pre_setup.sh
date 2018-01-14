#!/bin/bash

if [ "`whoami`" == 'root' ]; then
	if [ ! -d /usr/src/spec-1.0 ]; then
		mkdir -p /usr/src/spec-1.0
	fi
	if [ "`stat -c '%U' /usr/src/spec-1.0`" != 'go' ]; then
		chown go /usr/src/spec-1.0
	fi
else
	DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
	exec sudo "${DIR}/$(basename $0)"
fi

cp /var/lib/go-agent/pipelines/target-agent/test/dev/* /usr/src/spec-1.0

if ! dkms status spec/1.0 | grep -q ^spec; then
	dkms add -m spec -v 1.0
fi
