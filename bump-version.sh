#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TFVARS_FILE="$ROOT_DIR/infra/terraform/main.tfvars.json"
CONFIG_FILE="$ROOT_DIR/dashboard/config.js"
FUNCTION_CONFIG_FILE="$ROOT_DIR/function-version.json"
DRY_RUN=false
TARGET=""

usage() {
  echo "Usage: ./bump-version.sh <web|function> [--dry-run]" >&2
}

for argument in "$@"; do
  case "$argument" in
    web|function)
      if [[ -n "$TARGET" ]]; then
        usage
        exit 2
      fi
      TARGET="$argument"
      ;;
    --dry-run)
      DRY_RUN=true
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  usage
  exit 2
fi

python3 - "$TFVARS_FILE" "$CONFIG_FILE" "$TARGET" "$DRY_RUN" "$FUNCTION_CONFIG_FILE" <<'PY'
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys

tfvars_path = Path(sys.argv[1])
config_path = Path(sys.argv[2])
target = sys.argv[3]
dry_run = sys.argv[4].lower() == "true"
function_config_path = Path(sys.argv[5])

if target == "web" and not config_path.is_file():
    raise SystemExit(f"Missing dashboard configuration file: {config_path}")
if target == "function" and not function_config_path.is_file():
    raise SystemExit(f"Missing Function version file: {function_config_path}")

values = json.loads(tfvars_path.read_text(encoding="utf-8")) if tfvars_path.is_file() else {}
config_text = config_path.read_text(encoding="utf-8") if target == "web" else ""
dashboard_version_match = re.search(r'\bversion:\s*"([^"]+)"', config_text)
dashboard_version = dashboard_version_match.group(1) if dashboard_version_match else ""
function_config = {}
if target == "function":
    function_config = json.loads(function_config_path.read_text(encoding="utf-8"))
    if not isinstance(function_config, dict):
        raise SystemExit(f"Function version file must contain a JSON object: {function_config_path}")

now = datetime.now(timezone.utc)
today = now.strftime("%Y.%m.%d")
new_revision = now.strftime("%Y-%m-%dT%H:%M:%SZ")

def bump(version: str, label: str) -> str:
    match = re.fullmatch(r"(\d{4}\.\d{2}\.\d{2})\.(\d+)", version)
    if not match:
        raise SystemExit(
            f"{label} must use YYYY.MM.DD.N format, for example 2026.10.09.1: "
            f"{version!r}"
        )
    revision = int(match.group(2)) + 1 if match.group(1) == today else 1
    return f"{today}.{revision}"

version_key = "function_version" if target == "function" else "dashboard_version"
old_version = str(function_config.get("version") or "") if target == "function" else dashboard_version
new_version = bump(old_version, version_key)
updates = {}
if tfvars_path.is_file() and version_key in values:
    tfvars_text, count = re.subn(
        rf'("{version_key}"\s*:\s*")[^"]+(")',
        rf"\g<1>{new_version}\g<2>",
        tfvars_path.read_text(encoding="utf-8"),
        count=1,
    )
    if count != 1:
        raise SystemExit(f"Could not update {version_key} in {tfvars_path}")
    updates[tfvars_path] = tfvars_text

config_text = ""
if target == "web":
    config_text = config_path.read_text(encoding="utf-8")
    config_text, version_count = re.subn(
        r'(version:\s*")[^"]+(")',
        rf"\g<1>{new_version}\g<2>",
        config_text,
        count=1,
    )
    config_text, revision_count = re.subn(
        r'(revision:\s*")[^"]+(")',
        rf"\g<1>{new_revision}\g<2>",
        config_text,
        count=1,
    )
    if version_count != 1 or revision_count != 1:
        raise SystemExit(f"Could not update version and revision in {config_path}")
    updates[config_path] = config_text
else:
    function_config["version"] = new_version
    function_config["revision"] = new_revision
    updates[function_config_path] = json.dumps(function_config, indent=2) + "\n"
    example_path = tfvars_path.with_name("main.tfvars.example.json")
    if example_path.is_file():
        example_text, count = re.subn(
            r'("function_version"\s*:\s*")[^"]+(")',
            rf"\g<1>{new_version}\g<2>",
            example_path.read_text(encoding="utf-8"), count=1,
        )
        if count:
            updates[example_path] = example_text

label = "Function" if target == "function" else "Dashboard"
print(f"{label}: {old_version} -> {new_version}")
if target == "web":
    print(f"UI revision: {new_revision}")
if dry_run:
    print("Dry run only; no files changed.")
else:
    for path, content in updates.items():
        path.write_text(content, encoding="utf-8")
        print(f"Updated: {path}")
PY
