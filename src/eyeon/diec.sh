#!/bin/sh
CWD=$(dirname $0)
export LD_LIBRARY_PATH="$CWD/base:$LD_LIBRARY_PATH"
$CWD/base/diec $*
