#!/usr/bin/env bash

set -euo pipefail

analytics_dir="${1:-}"
if [[ -z "$analytics_dir" ]]; then
  echo "Usage: install-peyeon-analytics-uv.sh /opt/pEyeON-Analytics" >&2
  exit 2
fi

if [[ ! -f "$analytics_dir/pyproject.toml" ]]; then
  echo "Expected pEyeON-Analytics checkout at: $analytics_dir" >&2
  exit 2
fi

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required (install-uv.sh)" >&2
  exit 2
fi

# pEyeON-Analytics currently targets Python 3.13.
uv python install 3.13

cd "$analytics_dir"

# If a host dev venv was copied into the image build context, it can have
# incompatible symlinks/permissions. Always recreate it in the guest.
rm -rf .venv

# Create/update the project venv from the lockfile.
uv sync --frozen

# Smoke import without launching Streamlit.
uv run --frozen --no-sync python -c "import duckdb; import dlt; import dbt" >/dev/null
