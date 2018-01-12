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
