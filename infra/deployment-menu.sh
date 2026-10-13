#!/usr/bin/env bash
# Purpose: Run reviewed deployment and verification workflows from an interactive menu.

set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

resolve_python() {
  if [[ -n "${PYTHON:-}" ]]; then
    printf '%s\n' "$PYTHON"
  elif [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
    printf '%s\n' "$ROOT_DIR/.venv/bin/python"
  elif command -v python3 >/dev/null 2>&1; then
    command -v python3
  else
    printf 'Python was not found. Create .venv or set PYTHON to the interpreter path.\n' >&2
    return 1
  fi
}

PYTHON_BIN=$(resolve_python)

run_cli() {
  (
    cd "$ROOT_DIR"
    "$PYTHON_BIN" -m vulnerability_view.operations_cli "$@"
  )
}

pause_menu() {
  printf '\nPress Enter to return to the menu.'
  read -r
}

confirm_value() {
  local expected=$1
  local prompt=$2
  local response
  printf '%s\nType %s to continue: ' "$prompt" "$expected"
  read -r response
  [[ "$response" == "$expected" ]]
}

plan_apply_webapp() {
  printf 'Checking Azure identity, scope, and deployment permissions.\n'
  run_cli deployment-preflight
  printf 'Checking regional App Service plan quota.\n'
  run_cli configure-webapp-sku
  printf 'Planning the cumulative Web App stage: foundation, Function, and Web App infrastructure.\n'
  run_cli plan webapp
  run_cli show webapp
  if ! confirm_value "APPLY" "Apply only if the reviewed plan has no protected-storage deletion or replacement."; then
    printf 'Web App apply canceled.\n'
    return 1
  fi
  run_cli apply webapp
}

deploy_verify() {
  local stage=$1
  run_cli deploy "$stage"
  run_cli verify "$stage"
}

invoke_collection() {
  local mode=${1:-scheduled}
  run_cli check-function-logs --hours 1 --limit 3 --status-only
  local confirmation="COLLECT"
  local prompt="This starts a live collection and publishes a new immutable run if successful."
  local args=(invoke function --confirm)
  if [[ "$mode" == "full" ]]; then
    confirmation="FULL"
    prompt="This forces a full vulnerability baseline and complete recommendation-machine reconciliation."
    args+=(--full)
  fi
  if ! confirm_value "$confirmation" "$prompt"; then
    printf 'Live collection canceled.\n'
    return 1
  fi
  run_cli "${args[@]}"
  run_cli verify function
}

complete_update() {
  if ! plan_apply_webapp; then
    return
  fi
  deploy_verify function
  deploy_verify webapp
  printf '\nComplete infrastructure and code deployment finished.\n'
  printf 'Run an initial/live collection now? [y/N]: '
  local response
  read -r response
  if [[ "$response" =~ ^[Yy]$ ]]; then
    invoke_collection
  fi
}

verify_all() {
  run_cli verify function
  run_cli verify webapp
}

operations_menu() {
  while true; do
    cat <<'EOF'

Operations and diagnostics
  1) Show current collector activity
  2) Show active progress and latest 5 published runs
  3) Show latest 10 published runs
  4) Show detailed Function diagnostics for the last 24 hours
  5) Show extended Function diagnostics for the last 72 hours
  6) Verify Function and Web App
  7) Force full vulnerability and relationship reconciliation
  8) Return to deployment menu
EOF
    printf 'Select an option: '
    read -r operations_choice
    case "$operations_choice" in
      1) run_cli check-function-logs --hours 1 --limit 3 --status-only; pause_menu ;;
      2) run_cli check-runs --limit 5 --progress; pause_menu ;;
      3) run_cli check-runs --limit 10; pause_menu ;;
      4) run_cli check-function-logs --hours 24 --limit 10; pause_menu ;;
      5) run_cli check-function-logs --hours 72 --limit 25; pause_menu ;;
      6) verify_all; pause_menu ;;
      7) invoke_collection full; pause_menu ;;
      8) return ;;
      *) printf 'Select a number from 1 through 8.\n' ;;
    esac
  done
}

if [[ -t 1 ]] && command -v clear >/dev/null 2>&1; then
  clear
fi

cat <<'EOF'

Deployment identity notice
  - Deployment, update, and verification commands run as the identity currently signed in to Azure CLI.
  - That identity must have the customer tenant, subscription, resource, RBAC, and Entra permissions required by the operation.
  - The scripts and deployed application do not store the signed-in user's credentials.
  - Runtime authentication and resource access use the deployed Entra application/service principal and managed identities.
  - Run "az account show --output table" to confirm the active Azure context before continuing.
EOF

while true; do
  cat <<'EOF'

Vulnerability View deployment menu
  1) Complete initial deployment or update: infrastructure, Function, and Web App
  2) Plan, review, and apply Web App infrastructure
  3) Deploy and verify Function code
  4) Deploy and verify Web App code
  5) Invoke a live collection and verify Function
  6) Verify Function and Web App
  7) Operations and diagnostics
  8) Show saved Web App plan
  9) Exit
EOF
  printf 'Select an option: '
  read -r choice
  case "$choice" in
    1) complete_update; pause_menu ;;
    2) plan_apply_webapp || true; pause_menu ;;
    3) deploy_verify function; pause_menu ;;
    4) deploy_verify webapp; pause_menu ;;
    5) invoke_collection; pause_menu ;;
    6) verify_all; pause_menu ;;
    7) operations_menu ;;
    8) run_cli show webapp; pause_menu ;;
    9) exit 0 ;;
    *) printf 'Select a number from 1 through 9.\n' ;;
  esac
done
