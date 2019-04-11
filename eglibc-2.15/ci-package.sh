#!/bin/bash
fpm -f -s dir -t deb -n theia-eglibc -v 2.15-$GO_PIPELINE_COUNTER /usr/local/eglibc/
