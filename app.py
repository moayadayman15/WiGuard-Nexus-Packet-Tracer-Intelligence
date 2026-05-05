#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
export WIGUARD_HOST=${WIGUARD_HOST:-127.0.0.1}
export WIGUARD_PORT=${WIGUARD_PORT:-5000}
python diagnose_backend.py
python app.py
