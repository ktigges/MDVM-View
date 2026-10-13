#!/usr/bin/env bash
# Purpose: Summarize managed-identity publication telemetry without operator Storage access.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIMIT=10
LIMIT_SET=false
SHOW_PROGRESS=false

for argument in "$@"; do
  case "$argument" in
    --progress)
      SHOW_PROGRESS=true
      ;;
    *)
      if [[ "$argument" =~ ^[1-9][0-9]*$ ]] && [[ "$LIMIT_SET" == "false" ]]; then
        LIMIT="$argument"
        LIMIT_SET=true
      else
        echo "Usage: ./infra/check-runs.sh [positive-count] [--progress]" >&2
        exit 2
      fi
      ;;
  esac
done

if [[ -n "${PYTHON:-}" ]]; then
  PYTHON_BIN="$PYTHON"
elif [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python3)"
else
  echo "Python was not found. Create .venv or set PYTHON to the interpreter path." >&2
  exit 1
fi

arguments=(check-runs --limit "$LIMIT")
if [[ "$SHOW_PROGRESS" == "true" ]]; then
  arguments+=(--progress)
fi

cd "$ROOT_DIR"
exec "$PYTHON_BIN" -m vulnerability_view.operations_cli "${arguments[@]}"
