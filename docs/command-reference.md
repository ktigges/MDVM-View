# Command reference

> **Last modified:** 2026-09-28  
> **Purpose:** Explain supported project commands, what they change, and when operators should use them.

Run commands from the repository root unless a section says otherwise.

## 1. Quick operator decisions

| Need | Command |
|---|---|
| See whether the collector is active | `./infra/check-function-logs.sh 1 3 --status-only` |
| Continuously watch collector status | `watch -n 20 './infra/check-function-logs.sh 1 1 --status-only'` |
| Show active progress plus published runs | `./infra/check-runs.sh 5 --progress` |
| Inspect detailed failures and memory | `./infra/check-function-logs.sh 24 10` |
| List completed immutable runs | `./infra/check-runs.sh 10` |
| Deploy Function code only | `./infra/deploy.sh tfdeploy function` |
| Deploy Web App code only | `./infra/deploy.sh tfdeploy webapp` |
| Verify deployed Function | `./infra/deploy.sh tfverify function` |
| Verify deployed Web App | `./infra/deploy.sh tfverify webapp` |
| Manually start a collection | `CONFIRM_LIVE_COLLECTION=yes ./infra/deploy.sh tfinvoke function` |
| Start the local dashboard | `./start-app.sh` |
| Check effective non-secret application configuration | `vulnerability-view show-config` |
| Validate local generated datasets | `vulnerability-view validate` |

Never manually invoke while the status checker reports `ACTIVE` or
`INDETERMINATE`.

## 2. Initial workstation setup

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
```

| Command | Use |
|---|---|
| `python3.12 -m venv .venv` | Create the project virtual environment |
| `source .venv/bin/activate` | Activate it in the current shell |
| `python -m pip install -e '.[dev]'` | Install runtime dependencies, CLI, and tests |
| `cp .env.example .env` | Create ignored local runtime configuration; never commit secrets |

Azure CLI sign-in:

```bash
az login --tenant "$AZURE_TENANT_ID"
az account set --subscription "$AZURE_SUBSCRIPTION_ID"
az account show --output table
```

Use these before local live collection, Terraform, deployment, or Azure
diagnostics. `az account show` is read-only and confirms the active context.

## 3. Local dashboard

```bash
./start-app.sh
./start-app.sh 8080
HOST=0.0.0.0 DASHBOARD_RELOAD=false ./start-app.sh 8000
DASHBOARD_DATA_SOURCE=azure ./start-app.sh
```

| Command | Use |
|---|---|
| `./start-app.sh` | Start local dashboard on `127.0.0.1:8000` with reload and in-memory tracking |
| `./start-app.sh 8080` | Use a different validated port |
| `HOST=...` | Override bind address; expose beyond localhost only when intentionally secured |
| `DASHBOARD_RELOAD=false` | Disable development reload |
| `DASHBOARD_DATA_SOURCE=azure` | Read the verified Azure current bundle rather than local JSON |
| `Ctrl+C` | Stop the foreground local server |

Local recommendation tracking is in memory and resets when the server stops. It
does not write Defender or Azure workflow history.

## 4. Application CLI

General help:

```bash
vulnerability-view --help
vulnerability-view <command> --help
```

### Configuration and status

| Command | Changes data? | When to use |
|---|---|---|
| `vulnerability-view show-config` | No | Display effective non-secret configuration |
| `vulnerability-view status` | No | Show local run/output status |
| `vulnerability-view status --runs 30` | No | Increase local history rows shown |
| `vulnerability-view status --azure` | No | Include the Azure current manifest |

### Permissions and validation

| Command | Changes data? | When to use |
|---|---|---|
| `vulnerability-view preflight` | No durable writes | Verify credentials and one-row access to each configured API |
| `vulnerability-view validate` | No | Validate local dashboard datasets and reconciliation |
| `vulnerability-view verify-history latest` | No | Verify latest local immutable bundle checksums and raw archive |
| `vulnerability-view verify-history <run-id>` | No | Verify a specific local run |

### Live collection

| Command | Changes data? | When to use |
|---|---|---|
| `vulnerability-view collect-live --local-only` | Local files only | Collect Defender data without reading/writing Azure history |
| `vulnerability-view collect-live --local-only --enrichment targeted` | Local files only | Normal daily local collection |
| `vulnerability-view collect-live --local-only --enrichment full` | Local files only | Explicit full recommendation-machine reconciliation |
| `vulnerability-view collect-live --local-only --enrichment none` | Local files only | Skip API relationship enrichment for diagnosis |
| `vulnerability-view collect-live --from-raw latest --local-only` | Local files only | Replay latest retained raw pages without calling Defender |
| `vulnerability-view collect-live --from-raw <folder> --local-only` | Local files only | Replay a selected raw run |
| `vulnerability-view collect-live` | **Writes immutable Azure run and current pointer** | Workstation-driven live publication when Azure storage is configured |

Use the deployed Function for scheduled production collection. Do not start a
workstation collection and a Function collection concurrently.

### Synthetic and presentation builds

| Command | Changes data? | When to use |
|---|---|---|
| `vulnerability-view generate-synthetic` | Local files only | Generate the default synthetic presentation |
| `vulnerability-view build-sample --mode synthetic` | Local files only | Explicit synthetic-only build |
| `vulnerability-view build-sample --mode live` | Local files only | Build a local live presentation |
| `vulnerability-view build-sample --mode live --from-raw latest` | Local files only | Build local live output from retained raw pages |
| `vulnerability-view build-sample --mode combined` | Local files only | Combine labeled synthetic and live rows locally |
| `vulnerability-view build-sample --mode combined --from-raw latest` | Local files only | Combined local replay without another Defender download |

`build-sample` does not advance the Azure current pointer.

### History migration and restoration

| Command | Changes data? | When to use |
|---|---|---|
| `vulnerability-view backfill-history --local-only` | Local bundles only | Rebuild retained raw snapshots and validate migration locally |
| `vulnerability-view backfill-history` | **Uploads immutable runs** | Migrate all local retained raw history to Azure |
| `vulnerability-view seed-synthetic-history --local-only` | Local bundle/output only | Validate a labeled synthetic history bundle |
| `vulnerability-view seed-synthetic-history --confirm-azure-write` | **Uploads immutable synthetic run and advances current** | Explicit test-environment synthetic publication |
| `vulnerability-view restore-current` | Local files only | Download verified Azure current datasets to local dashboard files |

Backfill uploads runs in order and advances the current pointer only after the
newest run is durable. None of these commands delete Azure history.

### Scheduled-run simulation

```bash
vulnerability-view simulate-scheduled-run --from-raw latest --local-only
vulnerability-view simulate-scheduled-run --enrichment targeted --local-only
vulnerability-view simulate-scheduled-run --enrichment auto
```

This forwards to `collect-live` with schedule-equivalent options. Omit
`--local-only` only when an Azure publication is intended.

## 5. Terraform and deployment helper

The deployment helper uses cumulative stages:

1. `foundation`
2. `function`
3. `webapp`

When the Web App already exists, plan the `webapp` stage even for a Function
infrastructure setting change so Terraform preserves the cumulative deployment.

### Planning and applying infrastructure

```bash
./infra/deploy.sh tfplan foundation
terraform -chdir=infra/terraform show foundation.tfplan
./infra/deploy.sh tfapply foundation

./infra/deploy.sh tfplan function
terraform -chdir=infra/terraform show function.tfplan
./infra/deploy.sh tfapply function

./infra/deploy.sh tfplan webapp
terraform -chdir=infra/terraform show webapp.tfplan
./infra/deploy.sh tfapply webapp
```

| Command | Effect |
|---|---|
| `tfplan <stage>` | Runs `terraform init`, validates configuration, refreshes state, and saves a plan; does not apply |
| `terraform ... show <stage>.tfplan` | Read-only review of the exact saved plan |
| `tfapply <stage>` | Applies only the existing saved plan; does not regenerate it |

Never apply a plan that proposes deleting or replacing protected retained
history storage. A no-change plan may omit settings that already match Azure.

### Publishing code

```bash
./infra/deploy.sh tfdeploy function
./infra/deploy.sh tfverify function

./infra/deploy.sh tfdeploy webapp
./infra/deploy.sh tfverify webapp
```

| Command | Effect |
|---|---|
| `tfdeploy function` | Packages and publishes Function code; does not run Terraform or intentionally invoke collection |
| `tfverify function` | Checks Function host, trigger discovery, and storage visibility |
| `tfdeploy webapp` | Packages and publishes dashboard/server code |
| `tfverify webapp` | Checks Web App and Easy Auth redirect |

Code-only deployments do not need `tfplan` or `tfapply`.

### API preflight and manual invocation

```bash
./infra/deploy.sh tfpreflight
CONFIRM_LIVE_COLLECTION=yes ./infra/deploy.sh tfinvoke function
```

| Command | Effect |
|---|---|
| `tfpreflight` | Read-only Defender API check using the signed-in workstation identity |
| `tfinvoke function` | Starts one live collector invocation and writes a new immutable run if successful |

Always run the active-status check before `tfinvoke`.

### Replaceable Function teardown

```bash
CONFIRM_TF_DESTROY_FUNCTION=yes ./infra/deploy.sh tfdestroy function
```

This operation is intentionally limited to replaceable Function-stage
infrastructure. It must not target protected history storage or the resource
group containing it. Review the generated destroy plan before approval.

## 6. Collection progress, runs, failures, and memory

### Active status only

```bash
./infra/check-function-logs.sh 1 3 --status-only
```

Possible results:

| State | Meaning / action |
|---|---|
| `ACTIVE - DO NOT INVOKE ANOTHER RUN` | Fresh collector progress exists; wait |
| Latest invocation completed | Safe to inspect the published run |
| `INDETERMINATE` | Start exists without completion or fresh progress; wait and investigate before invoking |
| No invocation start | No start was found in the selected time window |

Continuously monitor without modifying Azure:

```bash
watch -n 20 './infra/check-function-logs.sh 1 1 --status-only'
```

### Published runs with optional in-flight progress

```bash
./infra/check-runs.sh
./infra/check-runs.sh 20
./infra/check-runs.sh 5 --progress
```

`check-runs.sh` reads completed immutable manifests only. `--progress` first
prints the active-run safety check, then lists published runs. The active run
will not appear in the manifest list until publication completes.

### Detailed Function diagnostics

```bash
./infra/check-function-logs.sh
./infra/check-function-logs.sh 48 20
```

Arguments are lookback hours and invocation count. Without `--status-only`, the
script also shows completed requests, latest failure traces, exceptions, and
minute-level peak memory.

All three diagnostic forms are read-only.

## 7. Terraform inspection commands

```bash
terraform -chdir=infra/terraform validate
terraform -chdir=infra/terraform output
terraform -chdir=infra/terraform output -raw function_app_name
terraform -chdir=infra/terraform output -raw web_app_name
terraform -chdir=infra/terraform output -raw history_storage_account_name
terraform -chdir=infra/terraform show webapp.tfplan
```

Use `validate` after Terraform edits, `output` to retrieve deployed names, and
`show` to review a saved plan. Prefer `infra/deploy.sh tfplan` over manually
running `terraform plan`, because the helper preserves cumulative stage rules.

## 8. Test and source validation

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest -q tests/test_live_collector.py
terraform -chdir=infra/terraform validate
bash -n infra/deploy.sh infra/check-runs.sh infra/check-function-logs.sh start-app.sh
git diff --check
```

| Command | Use |
|---|---|
| Full pytest | Validate all Python, dashboard-export, storage, and Function behavior |
| Focused pytest | Validate the directly changed subsystem first |
| Terraform validate | Check Terraform schema and references |
| `bash -n` | Parse shell scripts without executing them |
| `git diff --check` | Detect whitespace and patch formatting errors |

## 9. Recommended sequences

### Function code-only update

```bash
./infra/deploy.sh tfdeploy function
./infra/deploy.sh tfverify function
./infra/check-function-logs.sh 1 3 --status-only
```

### Function infrastructure plus code update when Web App exists

```bash
./infra/deploy.sh tfplan webapp
terraform -chdir=infra/terraform show webapp.tfplan
./infra/deploy.sh tfapply webapp
./infra/deploy.sh tfdeploy function
./infra/deploy.sh tfverify function
```

### Web App code-only update

```bash
./infra/deploy.sh tfdeploy webapp
./infra/deploy.sh tfverify webapp
```

### Manual live collection

```bash
./infra/check-function-logs.sh 1 3 --status-only
CONFIRM_LIVE_COLLECTION=yes ./infra/deploy.sh tfinvoke function
watch -n 20 './infra/check-function-logs.sh 1 1 --status-only'
./infra/check-runs.sh 3
```

Run the invocation only if the first command does not report `ACTIVE` or
`INDETERMINATE`.

