#!/bin/bash

#FIXME: Restart is required to turn logging back on.

DATA_MNT="theia:/data"
DATA_LOCAL='/data'
THEIA_HOME="$HOME/theia-ki-target-agent"

source archive.sh

# Archive prior ahg dump.
archive_ahg_dump


# Toggle logging off
if [ $1 = "0" ]; then
  sudo $THEIA_HOME/test/theia_toggle logging off
  exit
fi

# Toggle logging on.
if [ -z "$(findmnt ${DATA_MNT})" ] ; then
  mkdir $DATA_LOCAL &> /dev/null
  sudo mount $DATA_MNT $DATA_LOCAL
fi


# Insert spec module.
sudo modprobe spec

# Mount debugfs.

if [ -z "$(findmnt '/debug')" ] ; then
  sudo mkdir /debug &> /dev/null
  sudo mount -t debugfs debugfs /debug
fi

# Start relay-read-file
if [ -z "$(pgrep "relay-read-file")" ] ; then
  echo "Starting relay-read-file"
  read_file="$THEIA_HOME/relay-reader/relay-read-file"
  $(sudo $read_file) &
fi

# Start logging.sh
sudo $THEIA_HOME/test/theia_toggle logging on
