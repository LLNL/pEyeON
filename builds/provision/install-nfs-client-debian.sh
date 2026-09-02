#!/usr/bin/env bash

set -euo pipefail

# Install the optional VM-side NFS client. The image does not run an NFS server
# and does not enable an automatic mount; users choose their own export at run
# time.
apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    nfs-common \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
