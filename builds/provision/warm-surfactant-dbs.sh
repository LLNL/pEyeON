#!/usr/bin/env bash

set -euo pipefail

export XDG_DATA_HOME="${XDG_DATA_HOME:-/opt/eyeon/share}"
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-/opt/eyeon/config}"

mkdir -p "$XDG_DATA_HOME" "$XDG_CONFIG_HOME"

python - <<'PY'
from pathlib import Path

from surfactant.database_manager import utils

docs_dir = Path(utils.__file__).parents[2] / "docs"
docs_dir.mkdir(parents=True, exist_ok=True)

content = utils.download_content(utils.RTD_URL, timeout=30)
if not content:
    raise SystemExit(f"failed to download {utils.RTD_URL}")

(docs_dir / "database_sources.toml").write_text(content, encoding="utf-8")
PY

surfactant plugin update-db --all

chmod -R a+rX "$XDG_DATA_HOME" "$XDG_CONFIG_HOME"

# Remove Surfactant's build-time root-owned temp state so non-root users can
# recreate it at runtime when needed.
rm -f /tmp/.surfactant_extracted_dirs.json
