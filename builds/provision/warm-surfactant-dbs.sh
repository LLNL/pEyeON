#!/usr/bin/env bash

set -euo pipefail

surfactant plugin update-db --all

# Remove Surfactant's build-time root-owned temp state so non-root users can
# recreate it at runtime when needed.
rm -f /tmp/.surfactant_extracted_dirs.json
