#!/usr/bin/env bash
# Author: Kevin Tigges
# Last modified: 2026-09-27
# Purpose: Start the local FastAPI dashboard with validated host, port, and reload settings.

set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PYTHON="$ROOT_DIR/.venv/bin/python"
PORT="${1:-8000}"
HOST="${HOST:-127.0.0.1}"
export DASHBOARD_RECOMMENDATION_TRACKING_ENABLED="${DASHBOARD_RECOMMENDATION_TRACKING_ENABLED:-true}"

if [[ ! -x "$PYTHON" ]]; then
    printf 'Virtual environment not found. Create .venv and install the project first.\n' >&2
    exit 1
fi

if [[ ! "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    printf 'Port must be a number from 1 through 65535.\n' >&2
    exit 1
fi

printf 'Dashboard: http://%s:%s\n' "$HOST" "$PORT"

UVICORN_ARGS=(vulnerability_view.dashboard_server:app --host "$HOST" --port "$PORT")
if [[ "${DASHBOARD_RELOAD:-true}" == "true" ]]; then
    UVICORN_ARGS+=(--reload --reload-dir "$ROOT_DIR/src" --reload-dir "$ROOT_DIR/dashboard")
fi

cd "$ROOT_DIR"
exec "$PYTHON" -m uvicorn "${UVICORN_ARGS[@]}"