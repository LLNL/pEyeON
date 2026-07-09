#!/usr/bin/env bash

set -euo pipefail

binwalk_tag="${BINWALK_TAG:-v3.1.0}"

export PATH="/root/.cargo/bin:$PATH"

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --profile minimal

cargo install --git https://github.com/ReFirmLabs/binwalk --tag "$binwalk_tag" binwalk
