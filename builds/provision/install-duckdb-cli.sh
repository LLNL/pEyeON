#!/usr/bin/env bash

set -euo pipefail

# Install the DuckDB CLI binary.
#
# Debian doesn't always ship a recent DuckDB CLI in the default apt repos, and
# we want a consistent tool in both containers and VM images.

if command -v duckdb >/dev/null 2>&1; then
  exit 0
fi

arch="$(dpkg --print-architecture)"
case "$arch" in
  amd64|arm64) ;;
  *)
    echo "Unsupported architecture for DuckDB CLI: $arch" >&2
    exit 2
    ;;
esac

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

zip="${tmpdir}/duckdb_cli.zip"

# If DUCKDB_CLI_VERSION is unset, use GitHub's stable "latest" asset link.
version="${DUCKDB_CLI_VERSION:-}"
if [[ -n "$version" ]]; then
  url="https://github.com/duckdb/duckdb/releases/download/v${version}/duckdb_cli-linux-${arch}.zip"
else
  url="https://github.com/duckdb/duckdb/releases/latest/download/duckdb_cli-linux-${arch}.zip"
fi

curl -fsSL "$url" -o "$zip"
unzip -q "$zip" -d "$tmpdir"

if [[ -x "${tmpdir}/duckdb" ]]; then
  install -m 0755 "${tmpdir}/duckdb" /usr/local/bin/duckdb
elif [[ -x "${tmpdir}/duckdb_cli" ]]; then
  install -m 0755 "${tmpdir}/duckdb_cli" /usr/local/bin/duckdb
else
  echo "DuckDB CLI zip did not contain an expected binary (duckdb/duckdb_cli)." >&2
  echo "URL: $url" >&2
  echo "Contents:" >&2
  (cd "$tmpdir" && ls -la) >&2
  exit 2
fi

duckdb --version
