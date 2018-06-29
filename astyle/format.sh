#!/bin/bash

if ! hash astyle 2> /dev/null; then
  echo "Please install astyle"
  exit 1
fi

# -- List files to format here! -- #

astyle --options=astyle/astyle.conf linux-lts-quantal-3.5.0/kernel/replay.c
