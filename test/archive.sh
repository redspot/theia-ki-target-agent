#!/bin/bash

ARCHIVE_HOME="/data/archives"

archive_ahg_dump(){
  ts=$(date +%Y%m%d-%H%M)
  sudo mv -v "/data/ahg.dump.1" "$ARCHIVE_HOME/ahg.dump.$ts"
}
