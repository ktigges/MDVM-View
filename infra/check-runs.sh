#!/usr/bin/env bash
# Author: Kevin Tigges
# Last modified: 2026-09-27
# Purpose: Summarize immutable collector runs and their actionable endpoint issues.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="$ROOT_DIR/infra/terraform"
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

for command in az jq terraform; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 1
  fi
done

utc_to_local() {
  local value="$1" normalized epoch
  if date -d "$value" "+%Y-%m-%d %H:%M:%S %Z" >/dev/null 2>&1; then
    date -d "$value" "+%Y-%m-%d %H:%M:%S %Z"
    return
  fi
  normalized="${value%%.*}"
  normalized="${normalized%Z}"
  epoch="$(date -j -u -f "%Y-%m-%dT%H:%M:%S" "$normalized" +%s)"
  date -r "$epoch" "+%Y-%m-%d %H:%M:%S %Z"
}

if [[ "$SHOW_PROGRESS" == "true" ]]; then
  "$ROOT_DIR/infra/check-function-logs.sh" 1 1 --status-only
  echo
fi

ACCOUNT_NAME="${STORAGE_ACCOUNT_NAME:-$(terraform -chdir="$TF_DIR" output -raw history_storage_account_name)}"
CONTAINER_NAME="${STORAGE_CONTAINER_NAME:-$(terraform -chdir="$TF_DIR" output -raw history_container_name)}"
TEMP_FILE="$(mktemp)"
trap 'rm -f -- "$TEMP_FILE"' EXIT

SHOW_EXPERIMENTAL="${ENABLE_EXPERIMENTAL_ENDPOINTS:-}"
if [[ -z "$SHOW_EXPERIMENTAL" && -f "$ROOT_DIR/.env" ]]; then
  while IFS='=' read -r key value; do
    if [[ "$key" == "ENABLE_EXPERIMENTAL_ENDPOINTS" ]]; then
      SHOW_EXPERIMENTAL="$value"
      break
    fi
  done < "$ROOT_DIR/.env"
fi
case "$SHOW_EXPERIMENTAL" in
  [Tt][Rr][Uu][Ee])
    INCLUDE_EXPERIMENTAL=true
    ;;
  *)
    INCLUDE_EXPERIMENTAL=false
    ;;
esac

manifests=()
while IFS= read -r manifest; do
  if [[ -n "$manifest" ]]; then
    manifests+=("$manifest")
  fi
done < <(
  az storage blob list \
    --account-name "$ACCOUNT_NAME" \
    --container-name "$CONTAINER_NAME" \
    --auth-mode login \
    --prefix runs/ \
    --output json |
    jq -r --argjson limit "$LIMIT" '
      [.[] | select(.name | endswith("/manifest.json"))]
      | sort_by(.properties.lastModified)
      | reverse
      | .[0:$limit][].name
    '
)

if ((${#manifests[@]} == 0)); then
  echo "No run manifests found in $ACCOUNT_NAME/$CONTAINER_NAME." >&2
  exit 1
fi

if [[ "$INCLUDE_EXPERIMENTAL" == "true" ]]; then
  echo "Experimental endpoint results: included"
else
  echo "Experimental endpoint results: hidden (ENABLE_EXPERIMENTAL_ENDPOINTS is false)"
fi
echo "Published durable runs only; failed Function invocations may not appear."
echo

for manifest in "${manifests[@]}"; do
  az storage blob download \
    --account-name "$ACCOUNT_NAME" \
    --container-name "$CONTAINER_NAME" \
    --auth-mode login \
    --name "$manifest" \
    --file "$TEMP_FILE" \
    --overwrite \
    --no-progress \
    --only-show-errors \
    --output none

  SNAPSHOT_UTC="$(jq -r '.snapshotTimeUtc // empty' "$TEMP_FILE")"
  SNAPSHOT_LOCAL="$(utc_to_local "$SNAPSHOT_UTC")"
  jq -r --argjson includeExperimental "$INCLUDE_EXPERIMENTAL" --arg snapshotLocal "$SNAPSHOT_LOCAL" '
    def is_experimental:
      (.Endpoint // "") == "remediation_tasks"
      or (.Endpoint // "") == "vulnerability_changes";
    ([
      .endpointStatuses[]?
      | select(.Status != "Success")
      | select($includeExperimental or (is_experimental | not))
    ]) as $failures
    | (if (.runId | startswith("synthetic-")) then "Synthetic"
       elif (.runId | startswith("live-")) then "Live"
       else "Unknown"
       end) as $type
    | (if .complete != true then "Failed/Incomplete"
       elif ($failures | length) > 0 then "PartialSuccess"
       else "Success"
       end) as $status
    | "Run ID:           \(.runId)",
      "Type:             \($type)",
      "Snapshot (UTC):   \(.snapshotTimeUtc)",
    "Snapshot (Local): \($snapshotLocal)",
    "Status:           \($status)",
      "Findings:         \([.files[]? | select(.dataset == "findings") | .rowCount][0] // 0)",
      "Reported issues:  \($failures | length)",
      (if ($failures | length) == 0 then
         "Issues:           None"
       else
         "Issues:",
         ($failures[] |
           "  Endpoint: \(.Endpoint // "Unknown")",
           "  Status:   \(.Status // "Unknown")",
           (if (.Error // "") == "" then empty
            else "  Error:\n    \(.Error | gsub("[\r\n\t]+"; " "))"
            end),
           "")
       end),
      "------------------------------------------------------------"
  ' "$TEMP_FILE"
done
