#!/usr/bin/env bash
# Purpose: Permanently delete one explicitly confirmed disposable test environment.

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

read_config_value() {
  run_cli config-value "$1"
}

confirm_exact() {
  local expected=$1
  local prompt=$2
  local response
  printf '%s\nType %s to continue: ' "$prompt" "$expected"
  read -r response
  [[ "$response" == "$expected" ]]
}

run_cli deployment-preflight

subscription_id=$(read_config_value subscription_id)
resource_group=$(read_config_value resource_group_name)
history_account=$(read_config_value history_storage_account_name)
active_subscription_id=$(az account show --query id --output tsv)
if [[ "$active_subscription_id" != "$subscription_id" ]]; then
  printf 'Azure CLI is using subscription %s, but this deployment uses %s.\n' \
    "$active_subscription_id" "$subscription_id" >&2
  printf 'Run az account set --subscription %s and retry.\n' "$subscription_id" >&2
  exit 1
fi

cat <<EOF

PERMANENT TEST-ENVIRONMENT DELETION

This operation permanently deletes:
  - Subscription target: $subscription_id
  - Resource group: $resource_group
  - Protected history account: $history_account
  - All immutable and current history
  - Every container and resource remaining in the resource group
  - Terraform-managed application identities, directory objects, and assignments

This operation is only for a disposable test environment. It cannot be undone.
EOF

run_cli teardown-plan --allow-empty
run_cli teardown-show --allow-empty
az resource list --subscription "$subscription_id" --resource-group "$resource_group" --output table

confirm_exact "DELETE TEST ENVIRONMENT" \
  "Confirmation 1 of 4: Confirm this is a disposable test environment with no history that must be retained." \
  || { printf 'Full test-environment deletion canceled at confirmation 1.\n' >&2; exit 1; }
confirm_exact "$subscription_id" \
  "Confirmation 2 of 4: Confirm the exact Azure subscription." \
  || { printf 'Full test-environment deletion canceled at confirmation 2.\n' >&2; exit 1; }
confirm_exact "$resource_group" \
  "Confirmation 3 of 4: Confirm the exact resource group and every resource inside it." \
  || { printf 'Full test-environment deletion canceled at confirmation 3.\n' >&2; exit 1; }
confirm_exact "PERMANENTLY DELETE $resource_group" \
  "Confirmation 4 of 4: Permanently delete all application resources and retained history." \
  || { printf 'Full test-environment deletion canceled at confirmation 4.\n' >&2; exit 1; }

run_cli teardown-apply --allow-empty
az group delete --subscription "$subscription_id" --name "$resource_group" --yes
if [[ $(az group exists --subscription "$subscription_id" --name "$resource_group" --output tsv) != "false" ]]; then
  printf 'Deletion did not complete: resource group %s still exists.\n' "$resource_group" >&2
  exit 1
fi

printf 'Confirmed deleted: resource group %s and all resources and history inside it.\n' "$resource_group"
