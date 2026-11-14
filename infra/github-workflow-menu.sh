#!/usr/bin/env bash
# Purpose: Publish tested development work and promote customer-ready releases.

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

run_workflow() {
  (
    cd "$ROOT_DIR"
    "$PYTHON_BIN" -m vulnerability_view.github_workflow_cli "$@"
  )
}

pause_menu() {
  printf '\nPress Enter to return to the menu.'
  read -r
}

while true; do
  clear
  cat <<'EOF'
GitHub development and customer release workflow

  main      = active development and testing
  latest    = customer-ready stable release
  archive/* = read-only snapshots (never pushed or merged from here)
  other     = work branches (for example refactor/sla-simplification)

  Options 1-4 run on main; options 5-6 run on a work branch.

  1) Test, commit, and publish current work to main
  2) Test and promote origin/main to latest for customers
  3) Test once, publish main, and promote latest
  4) Validate customer release readiness
  5) Test, commit, and push the current work branch
  6) Merge the pushed work branch into main (fast-forward; no push)
  7) Exit
EOF
  printf '\nSelect an option: '
  read -r choice
  case "$choice" in
    1)
      run_workflow status
      printf '\nCommit message (required only when changes are uncommitted): '
      read -r commit_message
      printf 'This stages all current worktree changes, runs tests, commits if needed, and pushes main.\nType PUBLISH to continue: '
      read -r confirmation
      run_workflow publish-main --message "$commit_message" --confirm "$confirmation"
      pause_menu
      ;;
    2)
      run_workflow status
      printf '\nThis promotes the exact tested origin/main commit to the customer-facing latest branch.\nType PROMOTE to continue: '
      read -r confirmation
      run_workflow promote-latest --confirm "$confirmation"
      pause_menu
      ;;
    3)
      run_workflow status
      printf '\nCommit message (required only when changes are uncommitted): '
      read -r commit_message
      printf 'This runs tests once, publishes main, and promotes the same tested commit to latest.\n'
      run_workflow publish-and-promote --message "$commit_message"
      pause_menu
      ;;
    4)
      run_workflow validate-release
      pause_menu
      ;;
    5)
      run_workflow status
      printf '\nCommit message (required only when changes are uncommitted): '
      read -r commit_message
      printf 'Work branches normally require passing tests. Type ALLOW-FAILING to push even if tests fail, or press Enter: '
      read -r allow_failing
      printf 'This stages all current worktree changes, runs tests, commits if needed, and pushes this work branch only.\nType PUSH to continue: '
      read -r confirmation
      branch_args=(publish-branch --message "$commit_message" --confirm "$confirmation")
      if [[ "$allow_failing" == "ALLOW-FAILING" ]]; then
        branch_args+=(--allow-failing-tests)
      fi
      run_workflow "${branch_args[@]}" || true
      pause_menu
      ;;
    6)
      run_workflow status
      printf '\nThis fast-forwards local main to the pushed work branch and switches to main. Nothing is pushed.\nType MERGE to continue: '
      read -r confirmation
      run_workflow merge-into-main --confirm "$confirmation" || true
      pause_menu
      ;;
    7)
      exit 0
      ;;
    *)
      printf 'Invalid selection.\n'
      pause_menu
      ;;
  esac
done
