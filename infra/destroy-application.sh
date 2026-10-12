#!/usr/bin/env bash
# Purpose: Remove replaceable application resources while preserving protected history.

set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

if [[ -n "${PYTHON:-}" ]]; then
  PYTHON_BIN=$PYTHON
elif [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
elif [[ -x "$ROOT_DIR/.venv-win/Scripts/python.exe" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv-win/Scripts/python.exe"
else
  printf 'The deployment Python environment was not found. Create .venv and install the project first.\n' >&2
  exit 1
fi

run_cli() {
  (
    cd "$ROOT_DIR"
    "$PYTHON_BIN" -m vulnerability_view.operations_cli "$@"
  )
}

read_output() {
  run_cli output "$1"
}

confirm_exact() {
  local expected=$1
  local prompt=$2
  local response
  printf '%s\nType %s to continue: ' "$prompt" "$expected"
  read -r response
  [[ "$response" == "$expected" ]]
}

printf 'Checking Azure identity, scope, and teardown permissions.\n'
run_cli deployment-preflight

resource_group=$(read_output resource_group_name)
function_app=$(read_output function_app_name)
web_app=$(read_output web_app_name)
history_account=$(read_output history_storage_account_name)
history_container=$(read_output history_container_name)
current_container=$(read_output current_container_name)
workflow_container=$(read_output dashboard_recommendation_tracking_container)

cat <<EOF

SAFE APPLICATION TEARDOWN

Replaceable resources selected for removal include:
  - Function App: $function_app
  - Web App: $web_app
  - Function runtime Storage
  - Application identities, monitoring resources, and related assignments
  - Dashboard Microsoft Entra application and Enterprise Application

Resources that must remain:
  - Resource group: $resource_group
  - Protected history account: $history_account
  - History container: $history_container
  - Current-pointer container: $current_container
  - Protected workflow container: $workflow_container
  - Network perimeter foundation and local Terraform state
EOF

printf 'Creating and validating the application teardown plan.\n'
run_cli teardown-plan
run_cli teardown-show

confirm_exact "REVIEWED PLAN" \
  "Confirmation 1 of 4: Confirm that the displayed plan removes only replaceable application resources." \
  || { printf 'Application teardown canceled at confirmation 1.\n' >&2; exit 1; }
confirm_exact "$resource_group" \
  "Confirmation 2 of 4: Confirm the resource group whose protected foundation will remain." \
  || { printf 'Application teardown canceled at confirmation 2.\n' >&2; exit 1; }
confirm_exact "$web_app" \
  "Confirmation 3 of 4: Confirm the Web App selected for removal." \
  || { printf 'Application teardown canceled at confirmation 3.\n' >&2; exit 1; }
confirm_exact "REMOVE REPLACEABLE APPLICATION" \
  "Confirmation 4 of 4: This removes the Function, Web App, identities, directory application, and related assignments." \
  || { printf 'Application teardown canceled at confirmation 4.\n' >&2; exit 1; }

run_cli teardown-apply
printf 'Application teardown completed. Protected history and foundation resources remain.\n'
