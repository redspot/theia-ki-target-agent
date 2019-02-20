#!/bin/bash
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
find ${DIR} -user root -print0 | xargs -0 --no-run-if-empty chown go:go
