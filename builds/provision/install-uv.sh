#!/usr/bin/env bash

set -euo pipefail

if command -v uv >/dev/null 2>&1; then
  exit 0
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# Official installer. Installs to ~/.local/bin/uv by default.
curl -fsSL https://astral.sh/uv/install.sh -o "$tmpdir/uv-install.sh"
bash "$tmpdir/uv-install.sh"

installed_uv="${HOME}/.local/bin/uv"
if [ -x "$installed_uv" ]; then
  install -m 0755 "$installed_uv" /usr/local/bin/uv
fi

uv --version
