#!/usr/bin/env bash
# Build a standalone openeyes-agent binary with PyInstaller.
#
# IMPORTANT: PyInstaller cannot cross-compile. Run this script ON each target
# OS to get native binaries:
#   - Ubuntu/Debian  -> produces dist/openeyes-agent        (Linux x86_64/arm64)
#   - macOS (Silicon)-> produces dist/openeyes-agent        (arm64 when run on M-series)
#   - Windows        -> use:  python -m PyInstaller --onefile --name openeyes-agent ^
#                             openeyes_agent\__main__.py     (produces dist\openeyes-agent.exe)
#
# The agent is pure-stdlib, so "python3 -m openeyes_agent" also works anywhere
# without building a binary at all.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m pip install --quiet --upgrade pyinstaller

python3 -m PyInstaller \
  --onefile \
  --name openeyes-agent \
  --paths . \
  --collect-submodules openeyes_agent \
  openeyes_agent/__main__.py

echo
echo "Built: $(pwd)/dist/openeyes-agent"
file "$(pwd)/dist/openeyes-agent" 2>/dev/null || true
