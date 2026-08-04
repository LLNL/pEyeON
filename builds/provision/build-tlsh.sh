#!/usr/bin/env bash

set -euo pipefail

if [ ! -d /opt/tlsh/.git ]; then
  git clone https://github.com/trendmicro/tlsh.git /opt/tlsh
fi

cd /opt/tlsh
./make.sh
