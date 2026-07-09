#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

target_arch=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --amd64)
      target_arch="amd64"; shift ;;
    --arm64)
      target_arch="arm64"; shift ;;
    -h|--help)
      echo "Usage: builds/vm/build-qcow2.sh [--arm64|--amd64]" >&2
      exit 0
      ;;
    *)
      echo "Unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

if ! command -v packer >/dev/null 2>&1; then
  echo "Missing packer. On macOS: brew install hashicorp/tap/packer" >&2
  exit 1
fi

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
  echo "Missing QEMU. On macOS: brew install qemu" >&2
  exit 1
fi

if ! python3 -c 'import build' >/dev/null 2>&1; then
  echo "Missing Python build backend. Install with: python3 -m pip install --user build" >&2
  exit 1
fi

python3 -m build --wheel

wheel=$(ls -1 dist/*.whl | tail -1)
if [[ -z "$wheel" ]]; then
  echo "Failed to find wheel in dist/*.whl" >&2
  exit 1
fi

host_arch=$(uname -m)
if [[ -z "$target_arch" ]]; then
  if [[ "$host_arch" == "arm64" ]]; then
    target_arch="arm64"
  else
    target_arch="amd64"
  fi
fi

template="builds/vm/packer/debian12-${target_arch}.pkr.hcl"

sums_url="https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS"
image_url="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-${target_arch}.qcow2"

sha512=$(curl -fsSL "$sums_url" | awk "/debian-12-generic-${target_arch}\\.qcow2\$/ {print \$1; exit}")
if [[ -z "$sha512" ]]; then
  echo "Failed to resolve Debian cloud image checksum from $sums_url" >&2
  exit 1
fi

qemu_accel="hvf"
if [[ "$host_arch" == "arm64" && "$target_arch" == "amd64" ]]; then
  # x86_64 guest on Apple Silicon: run under TCG emulation.
  qemu_accel="tcg"
fi

packer init "$template"

outdir="builds/vm/output/debian12-${target_arch}"
rm -rf "$outdir"

packer build \
  -var "debian_cloud_image_url=$image_url" \
  -var "debian_cloud_image_checksum=sha512:$sha512" \
  -var "qemu_accelerator=$qemu_accel" \
  -var "eyeon_wheel=$wheel" \
  "$template"

raw_disk="${outdir}/packer-debian12"
named_disk="${outdir}/eyeon-debian12-${target_arch}.qcow2"
if [[ -f "$raw_disk" && ! -f "$named_disk" ]]; then
  mv "$raw_disk" "$named_disk"
fi

echo "Build complete. Output directory: ${outdir}" >&2
if [[ -f "$named_disk" ]]; then
  echo "Disk image: ${named_disk}" >&2
else
  echo "Disk image: ${raw_disk}" >&2
fi
