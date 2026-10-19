# Command reference

> **Last modified:** 2026-10-08
> **Purpose:** Explain cross-platform and legacy project commands, what they change, and when operators should use them.

Run commands from the repository root unless a section says otherwise.

## 1. Quick operator decisions

| Need | Command |
|---|---|
| See whether the collector is active | `python -m vulnerability_view.operations_cli check-function-logs --hours 1 --limit 3 --status-only` |
| Show active progress plus managed-identity publication telemetry | `python -m vulnerability_view.operations_cli check-runs --limit 5 --progress` |
| Inspect recent invocation requests | `python -m vulnerability_view.operations_cli check-function-logs --hours 24 --limit 10` |
| Inspect retained Function execution, host, and deployment logs over two days | `python -m vulnerability_view.operations_cli check-function-logs --days 2 --limit 25` |
| Export sanitized Function telemetry over two days | `python -m vulnerability_view.operations_cli export-function-logs --days 2` |
| List completed publication telemetry | `python -m vulnerability_view.operations_cli check-runs --limit 10` |
| Deploy Function code only | `python -m vulnerability_view.operations_cli deploy function` |
| Deploy Web App code only | `python -m vulnerability_view.operations_cli deploy webapp` |
| Verify deployed Function | `python -m vulnerability_view.operations_cli verify function` |
| Verify deployed Web App | `python -m vulnerability_view.operations_cli verify webapp` |
| Manually start a collection | `python -m vulnerability_view.operations_cli invoke function --confirm` |
| Start the local dashboard | `./start-app.sh` |
| Check effective non-secret application configuration | `vulnerability-view show-config` |
| Validate local generated datasets | `vulnerability-view validate` |
| Collect a raw-data sample on Windows | `.\tools\collect-sample-data.ps1 -TenantId "<tenant-guid>" -OutputDirectory "E:\SecureTransfer"` |

Never manually invoke while the status checker reports `ACTIVE` or
`INDETERMINATE`.

`verify function` checks managed-identity runtime Storage configuration, the
deployed collector version, and trigger discovery. It intentionally does not
query the current data manifest, so Network Security Perimeter or operator
Storage data-plane access cannot stall deployment verification. Use
`check-runs --limit 5 --progress` for collection and immutable-publication
status.

## 2. Initial workstation setup

macOS or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
```

Windows PowerShell:

```powershell
python3 --version
python3 -m venv .venv-win
.\.venv-win\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -c "import sys, vulnerability_view; print(sys.executable)"
Copy-Item .env.example .env
```

If `python3` is not available on Windows, use `py -3.14` for the first two
commands.

The Windows verification command must print a path ending in
`.venv-win\Scripts\python.exe`. After activation, use `python -m ...` normally.
Use the exact `.venv-win` interpreter path only if activation is blocked.

| Command | Use |
|---|---|
| `python3 -m venv .venv` | Create the tested Python 3.14 project environment |
| `python3 -m venv .venv-win` | Create the tested Python 3.14 Windows environment |
| `source .venv/bin/activate` | Activate it in the current shell |
| `.\.venv-win\Scripts\Activate.ps1` | Activate the Windows environment in PowerShell |
| `python -m pip install -e '.[dev]'` | Install runtime dependencies, CLI, and tests |
| `cp .env.example .env` | Create local runtime environment variables; never commit secrets |

Azure CLI sign-in:

```bash
az login --tenant "$AZURE_TENANT_ID"
az account set --subscription "$AZURE_SUBSCRIPTION_ID"
az account show --output table
```

Use these before local live collection, Terraform, deployment, or Azure
diagnostics. `az account show` is read-only and confirms the active context.

### Collect and replay a sample

Use the Windows collection script only after the organization authorizes export
of full raw Defender and Microsoft Graph responses:

```powershell
.\tools\collect-sample-data.ps1 `
  -TenantId "<source-tenant-guid>" `
  -OutputDirectory "E:\SecureTransfer"
```

The script runs preflight and one local-only collection, validates the result,
and creates a checksum-protected ZIP. The ZIP is not encrypted and must use an
encrypted transfer channel defined by organizational policy. See
[Collect and replay a sample](sample-replay.md) for prerequisites, data
classification, import validation, replay behavior, and local use cases.

## 3. Local dashboard

```bash
./start-app.sh
./start-app.sh 8080
HOST=0.0.0.0 DASHBOARD_RELOAD=false ./start-app.sh 8000
DASHBOARD_DATA_SOURCE=azure ./start-app.sh
```

| Command | Use |
|---|---|
| `./start-app.sh` | Start the local Web App on `127.0.0.1:8000` with reload; recommendation tracking is off by default |
| `./start-app.sh 8080` | Use a different validated port |
| `HOST=...` | Override bind address; expose beyond localhost only when intentionally secured |
| `DASHBOARD_RELOAD=false` | Disable development reload |
| `DASHBOARD_DATA_SOURCE=azure` | Read the verified Azure current bundle rather than local JSON |
| `Ctrl+C` | Stop the foreground local server |

When explicitly enabled, local recommendation tracking is in memory and resets
when the server stops. It does not write Defender or Azure workflow history.

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
| `vulnerability-view collect-live --local-only --collection auto --enrichment targeted` | Local files only | Initial/weekly full vulnerability baseline with deltas between reconciliations |
| `vulnerability-view collect-live --local-only --collection delta --enrichment targeted` | Local files only | Force a delta; fails if no baseline exists or the prior snapshot exceeds 14 days |
| `vulnerability-view collect-live --local-only --collection full --enrichment full` | Local files only | Explicit full vulnerability and recommendation-machine reconciliation |
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
python -m vulnerability_view.operations_cli show foundation
./infra/deploy.sh tfapply foundation

./infra/deploy.sh tfplan function
python -m vulnerability_view.operations_cli show function
./infra/deploy.sh tfapply function

./infra/deploy.sh tfplan webapp
python -m vulnerability_view.operations_cli show webapp
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

### Interactive deployment menus

Use the menu launchers to run the same operations with reviewed apply and live
collection confirmations:

```bash
./infra/deployment-menu.sh
```

```powershell
.\infra\deployment-menu.ps1
```

Both menus can plan, display, and apply Web App infrastructure; deploy and
verify Function or Web App code; invoke a live collection; verify both hosted
applications; inspect current collector activity, in-flight progress, published
runs, and Function diagnostics; or run the complete
initial-deployment/update workflow. The read-only **Operations and
diagnostics** submenu provides standard 24-hour and extended 72-hour diagnostic
views without changing Azure resources or data. Option 1
plans the cumulative `webapp` stage, so on a clean deployment environment it
creates the foundation, protected history storage, Function infrastructure,
and Web App before deploying and verifying both code packages. On an existing
environment, the same cumulative stage preserves all deployed components while
applying reviewed updates. It does not create environment-specific
`main.tfvars.json` values or perform Azure CLI sign-in; complete those
prerequisites first.

The menus do not expose destroy operations. Option 1 displays the saved Web App
plan and requires typing `APPLY` before applying it. It then offers an optional
initial/live collection, which requires typing `COLLECT`.

All deployment, update, and verification operations run under the identity
currently signed in to Azure CLI. That operator identity must have the required
target tenant, subscription, resource, RBAC, and Entra permissions. It is
used only to perform the requested administrative operations: the scripts and
deployed application do not store the operator's user credentials. Runtime
viewer authentication uses the deployed Entra application and service
principal, while Function and Web App access to Azure resources and data uses
their configured managed identities.

The shell and PowerShell launchers are a maintained pair. Any menu option,
workflow ordering, confirmation, or wrapped operations-command change must be
made in both files in the same change. Automated tests enforce their command
and menu parity:

- `infra/deployment-menu.sh` for Linux and macOS
- `infra/deployment-menu.ps1` for Windows PowerShell and PowerShell 7

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

### One-page debugging versus complete collection

Deployment menu option **5** offers:

- **D — Debug one page** (default): choose **M — Machine vulnerability findings**
  or **V — Vulnerability catalog**, then ask for a maximum of 1-1,000 records
  (default **1** for machine findings or **1,000** for the catalog), require
  `DEBUG`, make one Defender request, and stop.
  It does not retry, follow next links, archive responses, normalize findings,
  access snapshot Storage, or publish a manifest. A missing current manifest
  remains missing after a successful debug request.
- **C — Complete collection**: ask for records per page (default **1,000**),
  require `COLLECT`, and collect the complete dataset with normal paging,
  retries, validation, and publication.

For full baselines, complete collection retrieves the paged device inventory,
CVE catalog, and recommendations first, then pages findings separately for
each Defender machine ID. The request is
`/api/vulnerabilities/machinesVulnerabilities?$filter=machineId eq '<id>'&$top=<page-size>`,
not an unfiltered tenant-wide findings query. Progress names the current device
and reports completed machines and aggregate rows. A failed device query aborts
publication. Delta collection is unchanged. The **D → M** debug probe deliberately
remains the original unfiltered one-request test; use **C** to exercise the
device-scoped full baseline when no current baseline is published, or the existing
full reconciliation action to force it when a baseline already exists.

These choices apply only to this invocation. They do not modify Terraform,
app settings, or the scheduled collector's default page size. The full
reconciliation action also accepts a per-run page size and retains its `FULL`
confirmation. The page size is a per-request maximum, not a total inventory cap.

Equivalent cross-platform commands:

```bash
python -m vulnerability_view.operations_cli invoke function --confirm --debug --page-size 1
python -m vulnerability_view.operations_cli invoke function --confirm --debug --endpoint vulnerabilities --page-size 1000
python -m vulnerability_view.operations_cli invoke function --confirm --page-size 100
```

Debug uses the dedicated `dataprep_debug_page` trigger, so it cannot fall back to
a full collection on an older deployed Function. Deploy updated Function code
before using it. Trigger acceptance is not debug completion; inspect informational
Function logs for `[debug]` messages or the final exception.

The debug API request is:

```http
GET https://api-us3.securitycenter.microsoft.com/api/vulnerabilities/machinesVulnerabilities?$top=1
GET https://api-us3.securitycenter.microsoft.com/api/vulnerabilities?$top=1000
```

It uses the collector's managed identity and configured Defender base URL.
Both paths remain distinct. The operator-selected default base URI is
`https://api-us3.securitycenter.microsoft.com`; it is not a claim that this
Explorer-displayed hostname is a documented public endpoint. Set Terraform
`defender_api_base_url` to retain another required host. Both infrastructure apply
and Function code deployment synchronize the Function's base-URI app setting from
that value (or its default), so an old deployed global host does not silently
override new code defaults. No shell environment override is required.
Debug logs print the actual request URI before making the request.
Results report requested/returned row counts, HTTP status, and elapsed time,
not raw finding contents or tokens. Debug retains the 10-second connection and
90-second read timeouts but makes no automatic retry.

### Active status only

```bash
./infra/check-function-logs.sh 1 3 --status-only
```

Possible results:

| State | Meaning / action |
|---|---|
| `ACTIVE - DO NOT INVOKE ANOTHER RUN` | Fresh collector progress exists; wait |
| Latest invocation completed | Safe to inspect the published run |
| `INDETERMINATE` | Start exists without a completion trace, completed request record, or fresh progress; this is uncertainty, not a failure or permission to invoke again |
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

`check-runs.sh` calls the key-protected Function status endpoint, which reads
the current manifest with the collector managed identity, and then queries Log
Analytics through the Azure management plane for retained publication history.
`--progress` first prints the active-run safety check. It never lists or
downloads blobs as the signed-in operator. Historical records are limited by
the Log Analytics retention period.

The status checker correlates Function execution traces, `AppRequests`,
`[publication]` telemetry, and the current manifest returned through the
managed-identity status endpoint. A successful request means only that Azure
accepted the trigger. A newer current manifest supersedes stale request
telemetry and includes the run ID, result, finding count, published-file count,
reported-issue count, and snapshot time. `IDLE` means no collector is currently
running; the displayed result describes the latest completed attempt.

The operations submenu also provides **Force full vulnerability and
relationship reconciliation**. It checks active-run safety, requires typing
`FULL`, and invokes the dedicated managed-identity Function trigger. Use it
after a missed delta window, RBAC reorganization, suspected incomplete API
evidence, or an operator-directed complete refresh. It creates a new immutable
run and does not replace retained history.

### Detailed Function diagnostics

```bash
./infra/check-function-logs.sh
./infra/check-function-logs.sh 48 20
```

Arguments are lookback hours and invocation count. Without `--status-only`, the
script also shows recent requests and retained collection traces, exceptions,
and failed dependencies. When the latest invocation published successfully,
the activity summary includes its run ID, result, finding count,
published-file count, reported-issue count, and UTC/local completion time.

Use **Pull sanitized collector logs for the last 24 hours** in the operations menu
when the summarized evidence is insufficient. It writes a new timestamped
folder under `output/diagnostics/` containing `collector-sanitized-logs.json`
and `collector-sanitized-platform-failures.json`. The first file contains
collector request records plus Function-scoped Application Insights traces,
exceptions (including stack details), dependencies, host/platform logs, and
retained deployment telemetry. Console and startup logs do not need an
invocation or operation ID; deployment-service traces with an empty app role
are included when they belong to the Function's linked Application Insights
resource. The second file contains an allowlisted summary of failed Azure
activity-log records for the Function resource. Caller identities, tokens,
email addresses, IP addresses, URLs, and configured resource identifiers are
redacted before either file is written.

The PowerShell and Bash deployment menus provide operations choices **9**
(show Function logs) and **10** (export sanitized Function logs), with **11**
(return to the deployment menu) last. Both log choices ask for a positive whole
number of lookback days; pressing Enter selects **2 days (48 hours)**. Enter
`7` when the last collection or deployment is older than the fixed 24/72-hour
shortcuts. Invalid day counts are explained and prompted again.
The cross-platform CLI accepts `--days` or `--hours`, but not both; omitting
both retains its existing 24-hour default. The cross-platform CLI's detailed display
uses the same telemetry query as the export, without message-prefix or
operation-ID filters, and prints exception stack details. The query retrieves
raw workspace rows without computed resource columns or embedded Function
string literals. Function-role/resource matching is performed locally,
case-insensitively, and the menu reports both the raw row count and the matching
Function count. Unrelated applications in a shared workspace are excluded.
The workspace scan is bounded to 5,000 rows (or the requested display limit,
if larger); a warning identifies possible omissions when that limit is reached.
Display and export limits are also explicit; narrow the window if a record
limit is reached. Recent invocations are sorted locally newest first, and
durations are calculated from raw `DurationMs` values rather than relying on
a query-computed duration column.

Diagnostics print the configured subscription, resource group, Function,
workspace ID, and Terraform variables path. The menu reads its target from
`infra/terraform/main.tfvars.json`, not ordinary PowerShell variables such as
`$SUB`, `$RG`, `$FUNC`, `$WEB`, or `$log`. By default, the workspace is resolved
from the Function's linked Application Insights resource. To select a workspace
explicitly, set `LOG_ANALYTICS_WORKSPACE_NAME` (PowerShell:
`$env:LOG_ANALYTICS_WORKSPACE_NAME = "<workspace-name>"`). An empty window is
reported explicitly and does not establish application health; Azure query
errors and warnings are shown rather than converted into empty results.

Flex Consumption can recycle the instance holding local deployment logs.
`az functionapp log deployment show` may therefore report that logs are no
longer available even for a successful deployment. The menu queries retained
Application Insights deployment telemetry, but cannot recover logs that were
never ingested or have expired.

All three diagnostic forms are read-only.

## 7. Terraform inspection commands

```bash
terraform -chdir=infra/terraform validate
python -m vulnerability_view.operations_cli output
python -m vulnerability_view.operations_cli output function_app_name
python -m vulnerability_view.operations_cli output web_app_name
python -m vulnerability_view.operations_cli output history_storage_account_name
python -m vulnerability_view.operations_cli show webapp
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
python -m vulnerability_view.operations_cli show webapp
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
## Cross-platform Azure operations

After installation and virtual-environment activation, these commands are
identical across platforms:

```text
python -m vulnerability_view.operations_cli deploy function
python -m vulnerability_view.operations_cli verify function
python -m vulnerability_view.operations_cli deploy webapp
python -m vulnerability_view.operations_cli verify webapp
python -m vulnerability_view.operations_cli check-runs --limit 10 --progress
python -m vulnerability_view.operations_cli check-function-logs --hours 1 --limit 10 --status-only
python -m vulnerability_view.operations_cli invoke function --confirm
```

See [Infrastructure operations](../infra/README.md) for command internals,
identity dependencies, Terraform boundaries, and legacy Bash equivalents.
