#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
PY="${PYTHON:-python3}"
if [[ ! -d .venv ]]; then
  "$PY" -m venv .venv
fi
.venv/bin/python -m pip install -q -r requirements.txt
exec .venv/bin/python server.py
