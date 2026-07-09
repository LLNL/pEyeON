#!/usr/bin/env bash

set -euo pipefail

arch=$(dpkg --print-architecture)
url="https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-5/sasquatch_1.0_${arch}.deb"

tmp_deb=$(mktemp --suffix=.deb)
trap 'rm -f "$tmp_deb"' EXIT

curl -fsSL -o "$tmp_deb" "$url"
DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y "$tmp_deb"
apt-get clean
rm -rf /var/lib/apt/lists/*
