#!/usr/bin/env bash

set -euo pipefail

apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    libmagic1 ssdeep jq gosu curl \
    7zip zstd tar unzip sleuthkit cabextract lz4 lzop unar cpio device-tree-compiler \
    libfontconfig1 liblzma5 \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Useful for inspecting the analytics database in-container.
bash "$(dirname "$0")/install-duckdb-cli.sh"
