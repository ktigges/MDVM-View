#!/usr/bin/env bash
# Purpose: Run reviewed deployment and verification workflows from an interactive menu.

set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
DEPLOYMENT_MENU_VERSION="2026.10.19.9"

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
    PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}" \
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
  local confirmation="COLLECT"
  local prompt="This starts a live collection and publishes a new immutable run if successful."
  local args=(invoke function --confirm)
  local page_size page_default=1000 choice debug_endpoint=machine_vulnerabilities
  if [[ "$mode" == "scheduled" ]]; then
    while true; do
      printf 'D) Debug one page (no publication)\nC) Complete collection\nRun mode [D]: '
      read -r choice
      case "${choice:-D}" in
        D|d)
          confirmation="DEBUG"
          prompt="Machine debug discovers one device, then requests one filtered findings page; catalog debug requests one page. No retries or publication."
          args+=(--debug)
          page_default=1
          break
          ;;
        C|c) break ;;
        *) printf 'Select D for debugging or C for complete collection.\n' ;;
      esac
    done
  fi
  if [[ "$confirmation" == "DEBUG" ]]; then
    while true; do
      printf 'M) Machine vulnerability findings\nV) Vulnerability catalog\nDebug endpoint [M]: '
      read -r choice
      case "${choice:-M}" in
        M|m) break ;;
        V|v) debug_endpoint=vulnerabilities; page_default=1000; break ;;
        *) printf 'Select M for machine findings or V for the vulnerability catalog.\n' ;;
      esac
    done
    args+=(--endpoint "$debug_endpoint")
  fi
  printf 'Page size controls each request, not the total records collected.\n'
  while true; do
    printf 'Records per page (1-1000) [%s]: ' "$page_default"
    read -r page_size
    page_size=${page_size:-$page_default}
    if [[ "$page_size" =~ ^([1-9][0-9]{0,2}|1000)$ ]]; then
      break
    fi
    printf 'Enter a whole number from 1 to 1000.\n'
  done
  args+=(--page-size "$page_size")
  if [[ "$mode" == "full" ]]; then
    confirmation="FULL"
    prompt="This forces a full vulnerability baseline and complete recommendation-machine reconciliation."
    args+=(--full)
  fi
  if [[ "$confirmation" != "DEBUG" ]]; then
    run_cli check-function-logs --hours 1 --limit 3 --status-only
  fi
  if ! confirm_value "$confirmation" "$prompt"; then
    printf 'Live collection canceled.\n'
    return 1
  fi
  run_cli "${args[@]}"
  if [[ "$confirmation" != "DEBUG" ]]; then
    run_cli verify function
  fi
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
    invoke_collection complete
  fi
}

verify_all() {
  run_cli verify function
  run_cli verify webapp
}

function_logs_for_days() {
  local action=$1 days
  while true; do
    printf 'Lookback in whole days [2]: '
    read -r days
    days=${days:-2}
    if [[ "$days" =~ ^[1-9][0-9]*$ ]]; then
      break
    fi
    printf 'Enter a positive whole number of days.\n'
  done
  if [[ "$action" == "export" ]]; then
    run_cli export-function-logs --days "$days"
  else
    run_cli check-function-logs --days "$days" --limit 25
  fi
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
  6) Pull sanitized collector logs for the last 24 hours
  7) Verify Function and Web App
  8) Force full vulnerability and relationship reconciliation
  9) Show Function execution, host, and deployment logs (choose days)
  10) Pull sanitized Function logs (choose days)
  11) Return to deployment menu
EOF
    printf 'Select an option: '
    read -r operations_choice
    case "$operations_choice" in
      1) run_cli check-function-logs --hours 1 --limit 3 --status-only; pause_menu ;;
      2) run_cli check-runs --limit 5 --progress; pause_menu ;;
      3) run_cli check-runs --limit 10; pause_menu ;;
      4) run_cli check-function-logs --hours 24 --limit 10; pause_menu ;;
      5) run_cli check-function-logs --hours 72 --limit 25; pause_menu ;;
      6) run_cli export-function-logs --hours 24; pause_menu ;;
      7) verify_all; pause_menu ;;
      8) invoke_collection full; pause_menu ;;
      9) function_logs_for_days show; pause_menu ;;
      10) function_logs_for_days export; pause_menu ;;
      11) return ;;
      *) printf 'Select a number from 1 through 11.\n' ;;
    esac
  done
}

if [[ -t 1 ]] && command -v clear >/dev/null 2>&1; then
  clear
fi

GIT_REVISION=$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || printf 'unavailable')

cat <<'EOF'

Deployment identity notice
  - Deployment, update, and verification commands run as the identity currently signed in to Azure CLI.
  - That identity must have the customer tenant, subscription, resource, RBAC, and Entra permissions required by the operation.
  - The scripts and deployed application do not store the signed-in user's credentials.
  - Runtime authentication and resource access use the deployed Entra application/service principal and managed identities.
  - Run "az account show --output table" to confirm the active Azure context before continuing.
EOF

while true; do
  printf '\nVulnerability View deployment menu %s (revision %s)\n' "$DEPLOYMENT_MENU_VERSION" "$GIT_REVISION"
  cat <<'EOF'
  1) Complete initial deployment or update: infrastructure, Function, and Web App
  2) Plan, review, and apply Web App infrastructure
  3) Deploy and verify Function code
  4) Deploy and verify Web App code
  5) Debug a Defender page or run a live collection
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
