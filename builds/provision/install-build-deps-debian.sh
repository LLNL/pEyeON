#!/usr/bin/env bash

set -euo pipefail

apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    git make wget unzip curl \
    build-essential clang pkg-config \
    python3 python3-dev python3-venv \
    libfontconfig1-dev liblzma-dev libssl-dev \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
