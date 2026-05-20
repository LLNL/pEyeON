#!/bin/bash

set -euo pipefail

if [ "$EUID" -eq 0 ]; then
    echo "Run this script as a normal user, not with sudo." >&2
    exit 1
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
eyeon_dir=$(cd -- "${script_dir}/.." && pwd)
surfactant_tmp_state=/tmp/.surfactant_extracted_dirs.json

if [ -e "$surfactant_tmp_state" ] && [ ! -w "$surfactant_tmp_state" ]; then
    echo "Surfactant temp state exists but is not writable: $surfactant_tmp_state" >&2
    echo "This is usually left behind by a previous sudo run." >&2
    echo "Remove it once with: sudo rm -f $surfactant_tmp_state" >&2
    exit 1
fi

wget -qO- https://astral.sh/uv/install.sh | sh
source $HOME/.local/bin/env

cd "$eyeon_dir"
uv venv
uv add install --upgrade pip setuptools wheel
uv add install .
uv run surfactant plugin update-db --all

uv run eyeon --help >/dev/null
echo "EyeON user environment installed successfully via uv"
