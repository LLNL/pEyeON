#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  install-eyeon-venv.sh --venv <path> (--src <path> | --wheel <path>)

Examples:
  install-eyeon-venv.sh --venv /eye --src /src
  install-eyeon-venv.sh --venv /opt/eyeon/venv --wheel /tmp/peyeon.whl
EOF
}

venv_dir=""
src_dir=""
wheel_path=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --venv)
      venv_dir="$2"; shift 2 ;;
    --src)
      src_dir="$2"; shift 2 ;;
    --wheel)
      wheel_path="$2"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$venv_dir" ]]; then
  echo "Missing required: --venv" >&2
  usage
  exit 2
fi

if [[ -n "$src_dir" && -n "$wheel_path" ]]; then
  echo "Choose exactly one of --src or --wheel" >&2
  usage
  exit 2
fi

if [[ -z "$src_dir" && -z "$wheel_path" ]]; then
  echo "Missing required: --src or --wheel" >&2
  usage
  exit 2
fi

python3 -m venv "$venv_dir"
"$venv_dir/bin/pip" install --upgrade pip setuptools wheel

if [[ -n "$src_dir" ]]; then
  "$venv_dir/bin/pip" install "$src_dir"
else
  "$venv_dir/bin/pip" install "$wheel_path"
fi
