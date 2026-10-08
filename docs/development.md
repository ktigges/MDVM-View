# Development, demonstration, and source control

> **Last modified:** 2026-09-28
> **Purpose:** Run the dashboard during development, demonstrate it consistently, validate changes, and publish source safely.

## Dashboard development

Replay a retained raw snapshot without calling Defender or Azure:

```bash
.venv/bin/vulnerability-view simulate-scheduled-run \
  --from-raw latest \
  --local-only
```

Start the local dashboard:

```bash
./start-app.sh
```

Use `./start-app.sh 8080` for another port. Set
`DASHBOARD_RELOAD=false` to disable the development reloader. Recommendation
tracking is off by default. When explicitly enabled locally, it is an in-memory
preview and resets when the process stops.

To read the verified Azure current bundle without copying it locally:

```bash
DASHBOARD_DATA_SOURCE=azure ./start-app.sh
curl http://127.0.0.1:8000/api/status
```

## Ten-minute walkthrough

1. Explain the goals: identify, prioritize, coordinate remediation, measure SLA,
   show trend, and separate operating ownership.
2. Confirm source-data health and the visible data-origin filter.
3. Show Critical/High findings and known-exploit evidence.
4. Open the highest-ranked recommendation and explain Defender severity,
   current impact, actionable workloads, device instances, and linked CVEs.
5. Explain that one scale-out workload can represent many retained instances;
   grouping changes presentation, not evidence.
6. Show dashboard-local recommendation work status and state that it does not
   update Defender.
7. Distinguish the finding SLA clock from Defender remediation-task due dates.
8. Show confirmed fixes, new/reopened findings, and current remaining work.
9. Show trend comparisons and clarify which history is synthetic or live.
10. Close with the operating path: scheduled collection, immutable history,
    authenticated dashboard access, and source-health monitoring.

## Validation

Run the smallest affected test selection first:

```bash
.venv/bin/python -m pytest -q tests/test_dashboard_exports.py
```

Run the complete suite before release:

```bash
.venv/bin/python -m pytest -q
terraform -chdir=infra/terraform validate
bash -n infra/deploy.sh
bash -n infra/check-runs.sh
bash -n infra/check-function-logs.sh
git diff --check
```

## Publish the source repository

Review the staged file list before the first commit. Ignore rules exclude
credentials, environment values, Terraform state and plans, generated data,
deployment ZIP files, local notes, editor state, and local environments.

```bash
git init -b main
git add .
git status --short
git diff --cached --check
git diff --cached --name-only
git commit -m "Initial"
gh auth login
gh repo create <repository-name> --private --source=. --remote=origin --push
```

Create the repository as private first unless public release has completed its
legal, licensing, security, and organizational reviews. Do not use `git add -f`
to force environment-specific values or generated data into source control.

## Cleanup boundary

Stop local foreground processes with `Ctrl+C`. Local generated files may be
removed under the defined sensitive-data handling process.

Local cleanup does not authorize deletion of Azure Storage history. Never
delete the protected storage account, containers, or retained `raw/`,
`curated/`, or `runs/` paths as part of cleanup, reset, redeployment, or
"start over" work.

Only `current/manifest.json` is replaced during normal operation. Retention
deletion requires a separate, explicit human decision naming the exact eligible
targets.
