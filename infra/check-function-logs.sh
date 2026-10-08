#!/usr/bin/env bash
# Author: Kevin Tigges
# Last modified: 2026-10-08
# Purpose: Inspect collector Function invocations, failures, exceptions, progress, and memory portably without modifying Azure.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TFVARS="$ROOT_DIR/infra/terraform/main.tfvars.json"
HOURS="${1:-24}"
LIMIT="${2:-10}"
MODE="${3:-}"

if ! [[ "$HOURS" =~ ^[1-9][0-9]*$ ]] \
  || ! [[ "$LIMIT" =~ ^[1-9][0-9]*$ ]] \
  || { [[ -n "$MODE" ]] && [[ "$MODE" != "--status-only" ]]; }; then
  echo "Usage: ./infra/check-function-logs.sh [positive-hours] [positive-count] [--status-only]" >&2
  exit 2
fi

for command in az jq; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 1
  fi
done

utc_to_epoch() {
  # Converts Azure UTC timestamps with GNU date on Linux or BSD date on macOS.
  local value="$1" normalized
  if date -u -d "$value" +%s >/dev/null 2>&1; then
    date -u -d "$value" +%s
    return
  fi
  normalized="${value%%.*}"
  normalized="${normalized%Z}"
  date -j -u -f "%Y-%m-%dT%H:%M:%S" "$normalized" +%s
}

if [[ ! -f "$TFVARS" ]]; then
  echo "Terraform variables file not found: $TFVARS" >&2
  exit 1
fi

SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID:-$(jq -r '.subscription_id // empty' "$TFVARS")}"
RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:-$(jq -r '.resource_group_name // empty' "$TFVARS")}"
FUNCTION_APP="${FUNCTION_APP_NAME:-$(jq -r '.function_app_name // empty' "$TFVARS")}"
PROJECT_NAME="$(jq -r '.project_name // empty' "$TFVARS")"
ENVIRONMENT="$(jq -r '.environment // empty' "$TFVARS")"
WORKSPACE_NAME="${LOG_ANALYTICS_WORKSPACE_NAME:-log-${PROJECT_NAME}-${ENVIRONMENT}}"
WORKSPACE_GUID_FIELD="cus""tomerId"

if [[ -z "$SUBSCRIPTION_ID" || -z "$RESOURCE_GROUP" || -z "$FUNCTION_APP" ]]; then
  echo "subscription_id, resource_group_name, and function_app_name are required in $TFVARS." >&2
  exit 1
fi

az account show --subscription "$SUBSCRIPTION_ID" --output none

WORKSPACE_ID="$(
  az monitor log-analytics workspace show \
    --subscription "$SUBSCRIPTION_ID" \
    --resource-group "$RESOURCE_GROUP" \
    --workspace-name "$WORKSPACE_NAME" \
    --query "$WORKSPACE_GUID_FIELD" \
    --output tsv
)"
FUNCTION_RESOURCE_ID="$(
  az functionapp show \
    --subscription "$SUBSCRIPTION_ID" \
    --resource-group "$RESOURCE_GROUP" \
    --name "$FUNCTION_APP" \
    --query id \
    --output tsv
)"

if [[ -z "$WORKSPACE_ID" || -z "$FUNCTION_RESOURCE_ID" ]]; then
  echo "Could not resolve the Function App or Log Analytics workspace." >&2
  exit 1
fi

echo "Function App:  $FUNCTION_APP"
echo "Workspace:     $WORKSPACE_NAME"
echo "Window:        Last $HOURS hour(s)"
echo

RUN_STATE_JSON="$(
  az monitor log-analytics query \
    --subscription "$SUBSCRIPTION_ID" \
    --workspace "$WORKSPACE_ID" \
    --analytics-query "let starts = AppTraces
        | where TimeGenerated > ago(${HOURS}h)
        | where Message startswith \"Executing 'Functions.dataprep_snapshot'\"
        | extend InvocationId = extract(@'Id=([0-9a-fA-F-]{36})', 1, Message)
        | project InvocationId, StartedUtc=TimeGenerated;
      let completions = AppTraces
        | where TimeGenerated > ago(${HOURS}h)
        | where Message startswith \"Executed 'Functions.dataprep_snapshot'\"
        | extend InvocationId = extract(@'Id=([0-9a-fA-F-]{36})', 1, Message)
        | project InvocationId, CompletedUtc=TimeGenerated;
      starts
        | join kind=leftouter completions on InvocationId
        | top 1 by StartedUtc desc
        | project InvocationId, StartedUtc, CompletedUtc" \
    --output json
)"

LATEST_INVOCATION_ID="$(jq -r '.[0].InvocationId // empty' <<<"$RUN_STATE_JSON")"
LATEST_STARTED_UTC="$(jq -r '.[0].StartedUtc // empty' <<<"$RUN_STATE_JSON")"
LATEST_COMPLETED_UTC="$(jq -r '.[0].CompletedUtc // empty | select(. != "None")' <<<"$RUN_STATE_JSON")"

echo "Active-run safety check:"
if [[ -z "$LATEST_INVOCATION_ID" ]]; then
  echo "  No invocation start was found in this time window."
elif [[ -n "$LATEST_COMPLETED_UTC" ]]; then
  echo "  Latest invocation $LATEST_INVOCATION_ID completed at $LATEST_COMPLETED_UTC."
else
  PROGRESS_JSON="$(
    az monitor log-analytics query \
      --subscription "$SUBSCRIPTION_ID" \
      --workspace "$WORKSPACE_ID" \
      --analytics-query "AppTraces
        | where TimeGenerated >= datetime(${LATEST_STARTED_UTC})
        | where Message startswith '['
        | top 1 by TimeGenerated desc
        | project TimeGenerated, Message" \
      --output json
  )"
  LATEST_PROGRESS_UTC="$(jq -r '.[0].TimeGenerated // empty' <<<"$PROGRESS_JSON")"
  LATEST_PROGRESS_MESSAGE="$(jq -r '.[0].Message // empty' <<<"$PROGRESS_JSON")"
  LATEST_PROGRESS_EPOCH=""
  if [[ -n "$LATEST_PROGRESS_UTC" ]]; then
    LATEST_PROGRESS_EPOCH="$(utc_to_epoch "$LATEST_PROGRESS_UTC")"
  fi
  if [[ -n "$LATEST_PROGRESS_UTC" ]] \
    && [[ "$LATEST_PROGRESS_EPOCH" =~ ^[0-9]+$ ]] \
    && (( $(date -u +%s) - LATEST_PROGRESS_EPOCH <= 600 )); then
    echo "  ACTIVE - DO NOT INVOKE ANOTHER RUN."
    echo "  Invocation:      $LATEST_INVOCATION_ID"
    echo "  Started UTC:     $LATEST_STARTED_UTC"
    echo "  Latest progress: $LATEST_PROGRESS_UTC"
    echo "  $LATEST_PROGRESS_MESSAGE"
  else
    echo "  INDETERMINATE - invocation $LATEST_INVOCATION_ID has no completion and no progress in the last 10 minutes."
    echo "  Do not invoke another run until Azure reports completion/failure or fresh progress is confirmed."
  fi
fi

echo
if [[ "$MODE" == "--status-only" ]]; then
  echo "Read-only status check complete. No Function or storage resources were modified."
  exit 0
fi

echo "Recent dataprep_snapshot invocations:"

az monitor log-analytics query \
  --subscription "$SUBSCRIPTION_ID" \
  --workspace "$WORKSPACE_ID" \
  --analytics-query "AppRequests
    | where TimeGenerated > ago(${HOURS}h)
    | where Name == 'dataprep_snapshot'
    | top ${LIMIT} by TimeGenerated desc
    | extend DurationSeconds = round(DurationMs / 1000.0, 1)
    | project TimeGenerated, Success, DurationSeconds, OperationId" \
  --output table

FAILED_JSON="$(
  az monitor log-analytics query \
    --subscription "$SUBSCRIPTION_ID" \
    --workspace "$WORKSPACE_ID" \
    --analytics-query "AppRequests
      | where TimeGenerated > ago(${HOURS}h)
      | where Name == 'dataprep_snapshot' and Success == false
      | top 1 by TimeGenerated desc
      | project TimeGenerated, DurationMs, OperationId" \
    --output json
)"

FAILED_OPERATION_ID="$(jq -r '.[0].OperationId // empty' <<<"$FAILED_JSON")"
if [[ -z "$FAILED_OPERATION_ID" ]]; then
  echo
  echo "No failed dataprep_snapshot invocation was found in this time window."
  exit 0
fi

FAILED_START="$(jq -r '.[0].TimeGenerated' <<<"$FAILED_JSON")"
FAILED_DURATION_MS="$(jq -r '.[0].DurationMs | tonumber | floor' <<<"$FAILED_JSON")"
FAILED_DURATION_SECONDS=$((FAILED_DURATION_MS / 1000))
WINDOW_START="$(date -u -d "$FAILED_START -1 minute" +"%Y-%m-%dT%H:%M:%SZ")"
WINDOW_END="$(date -u -d "$FAILED_START +$((FAILED_DURATION_SECONDS + 120)) seconds" +"%Y-%m-%dT%H:%M:%SZ")"

echo
echo "Latest failed invocation:"
echo "  Started UTC:  $FAILED_START"
echo "  Duration:     ${FAILED_DURATION_SECONDS}s"
echo "  Operation ID: $FAILED_OPERATION_ID"

echo
echo "Failure-window warnings and errors:"
az monitor log-analytics query \
  --subscription "$SUBSCRIPTION_ID" \
  --workspace "$WORKSPACE_ID" \
  --analytics-query "AppTraces
    | where TimeGenerated between (datetime(${WINDOW_START}) .. datetime(${WINDOW_END}))
    | where SeverityLevel >= 2
      or Message has_any ('Failed', 'failed', 'exited', 'Exception', 'timeout', 'Timeout')
    | project TimeGenerated, SeverityLevel, OperationId, Message
    | order by TimeGenerated asc" \
  --output table

echo
echo "Correlated exceptions:"
az monitor log-analytics query \
  --subscription "$SUBSCRIPTION_ID" \
  --workspace "$WORKSPACE_ID" \
  --analytics-query "AppExceptions
    | where OperationId == '${FAILED_OPERATION_ID}'
    | project TimeGenerated, ExceptionType, OuterMessage, InnermostMessage
    | order by TimeGenerated asc" \
  --output table

MEMORY_JSON="$(
  az monitor metrics list \
    --resource "$FUNCTION_RESOURCE_ID" \
    --metric MemoryWorkingSet \
    --start-time "$WINDOW_START" \
    --end-time "$WINDOW_END" \
    --interval PT1M \
    --aggregation Maximum \
    --query "value[0].timeseries[0].data" \
    --output json
)"
PEAK_MEMORY_BYTES="$(jq '[.[].maximum // 0] | max // 0 | floor' <<<"$MEMORY_JSON")"
PEAK_MEMORY_MIB="$(awk -v bytes="$PEAK_MEMORY_BYTES" 'BEGIN { printf "%.1f", bytes / 1048576 }')"

echo
echo "MemoryWorkingSet during failure window:"
jq -r '.[] | select((.maximum // 0) > 0) | "\(.timeStamp)  \((.maximum / 1048576 * 10 | round) / 10) MiB"' <<<"$MEMORY_JSON"
echo "Peak memory: ${PEAK_MEMORY_MIB} MiB"
echo
echo "Read-only check complete. No Function or storage resources were modified."
