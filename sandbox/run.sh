#!/usr/bin/env bash
# Aegis sandbox launcher (macOS / Linux / WSL).
#   ./run.sh            # sandbox the current directory
#   ./run.sh /path/repo # sandbox a specific repo
# Only the repo is mounted; no network; no privileges. Aegis runs inside.
set -euo pipefail

REPO="${1:-$PWD}"
DIR="$(cd "$(dirname "$0")" && pwd)"

docker build -t aegis-sandbox "$DIR"

docker run --rm -it \
  -v "$REPO:/work" \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  aegis-sandbox
