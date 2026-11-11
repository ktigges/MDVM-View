# Infrastructure operations and `deploy.sh` reference

This reference covers the deployment CLI, legacy Bash wrappers, cumulative
Terraform stages, and collector hosting migration. Installation is in the
[deployment guide](../DEPLOY.md); application behavior is in the
[runtime reference](../docs/application-flow.md).

`python -m vulnerability_view.operations_cli` is the shared interface.
The Bash scripts remain compatibility wrappers.

The interactive `deployment-menu.sh` and `deployment-menu.ps1` launchers are a
maintained pair over the same operations CLI. Every menu option, command
sequence, typed confirmation, and safety boundary changed in one launcher must
be changed in the other. `tests/test_deployment_menus.py` enforces parity and
ensures neither menu exposes destructive operations.

The separate GitHub workflow menus use the shared release CLI for both platforms.
Publish/promote validation displays each test name and result, the ten slowest
test durations, and elapsed validation time. Git fetch, remote lookup, staging,
commit, and push steps print flushed start/finish messages with elapsed times.
The combined publish-and-promote option runs tests once and announces the two
pushes separately. `GITHUB_WORKFLOW_TEST_COMMAND`, if set, is still executed
unchanged; its own output controls test-level progress. Validation failures stop
the workflow before subsequent publish/promotion steps.
Validation also fingerprints tracked/untracked file contents and HEAD before
and after tests. Edits or concurrent commits stop the operation before committing
or pushing, with current dirty files listed. Finish editing before starting a
release; the workflow never discards changes or promotes an unvalidated edit.

On Windows, `deployment-menu.ps1` also bootstraps menu-managed dependencies: it
creates the project virtual environment, installs project packages when
needed, and installs required Azure CLI extensions such as `log-analytics`.
Python, Azure CLI, Terraform, and Git remain explicit workstation
prerequisites.

The Operations and diagnostics submenu includes a `FULL`-confirmed complete
vulnerability baseline and recommendation-relationship reconciliation. Normal
scheduled collection uses deltas between weekly full vulnerability baselines.

Select **7 → 12** to export the latest published snapshot as a verified local
ZIP, without starting a collection, deploying code, or changing Azure Storage.
The signed-in Azure CLI identity needs blob-read access to both history and
current-pointer containers. See [snapshot export](../docs/operations-and-configuration.md#export-the-latest-published-snapshot-for-analysis)
for contents, local output location, and sensitive-data handling.

Dashboard large-data changes use the existing **Deploy and verify Web App
code** operation; no Function deployment or collection is needed. The dashboard
loads summary metrics first, then requests snapshot-pinned server-side table
pages and details. Its verified compressed downloads and SQLite indexes are
disposable local cache files. Each worker retains up to two snapshots within
an 8 GiB local budget; allow sufficient App Service local disk. A cold cache
is prepared in the background while the authenticated shell can load. Data
queries wait for snapshot readiness. With the Terraform-configured persistent
viewer cache, compatible artifacts and all nine default views, including
Reporting, are restored or prepared before the snapshot is advertised as ready.
Analytical facts are separate from compressed original evidence. Allow up to
30 minutes for cold startup (`WEBSITES_CONTAINER_START_TIME_LIMIT=1800`).
New snapshots are prepared before selection; allow space for the ready and
replacement caches together. Browser revisits reuse bounded view results.
`/api/diagnostics` includes `dashboardQueries.preparation` and `dashboardQueries`
with retained snapshot IDs, active query counts, and local cache sizes.
Nothing in cache eviction deletes or rewrites retained Azure history.

Persistent viewer cache restores stream compressed blobs directly into temporary
SQLite files, without writing a local compressed copy. Compressed SHA-256 and
size checks, expanded-size limits, and SQLite validation must all pass before
atomic installation. Startup logs report compressed/expanded byte counts,
`downloadSeconds` (initial request and chunk retrieval), and `decodeWriteSeconds`
(remaining streaming work, including hashing, decompression, and disk writes).
The separate `viewer-cache:validate-*` stage reports SQLite validation time.
Cache formats, report readiness, and download concurrency are unchanged.

For an existing App Service plan, SKU preflight preserves the explicitly
configured `web_app_sku_name` instead of copying the deployed SKU back into
`main.tfvars.json`. It still preserves the existing plan's region. If the
deployed and requested SKUs differ, it reports both; review the Terraform plan
for the tier change and its cost before approving apply.

## Cross-platform operations CLI

The same commands work in Windows PowerShell, macOS, and Linux after activating
the platform's virtual environment:

```text
python -m vulnerability_view.operations_cli plan foundation
python -m vulnerability_view.operations_cli apply foundation
python -m vulnerability_view.operations_cli deploy function
python -m vulnerability_view.operations_cli verify function
python -m vulnerability_view.operations_cli deploy webapp
python -m vulnerability_view.operations_cli verify webapp
python -m vulnerability_view.operations_cli check-runs --limit 10 --progress
python -m vulnerability_view.operations_cli check-function-logs --hours 1 --limit 10 --status-only
python -m vulnerability_view.operations_cli invoke function --confirm
python -m vulnerability_view.operations_cli invoke function --confirm --full
python -m vulnerability_view.operations_cli download-collection-diagnostics
```

Complete collections now start or resume a Durable workflow. Use
`check-runs --progress` for persisted workflow state, including before the
first publication, and `export-function-logs` for support logs. A successful
starter invocation only means the workflow was requested, not that collection
or publication completed. The local receipt is a request receipt, not a
publication receipt.

Operations submenu **12** and `download-collection-diagnostics --id <uuid>`
remain available for evidence captured by the previous synchronous collector.
New Durable runs do not produce those legacy JSONL chunks. DEBUG probes remain
one-page, synchronous, and nonpublishing.

Function deployment waits for authenticated runtime indexing before synchronizing
management-plane triggers. If the initial 24 readiness attempts expire, it tries
trigger synchronization once using the subscription from the environment values
file, then checks readiness up to six more times. A sync error or persistently
missing functions still fails deployment; recovery does not restart the app,
redeploy the package, or change collection checkpoints.
Verification checks all starter, orchestration,
activity, status, and DEBUG functions and fails on missing triggers. A successful
package upload or version app setting alone does not prove that Python loaded.

Detailed Function log diagnostics continue querying Log Analytics when the
Function's status endpoint or host-key lookup is unavailable. The status failure
is printed explicitly; it does not prevent startup/indexing errors from being
displayed. Log export also works independently of the Function status endpoint.

Collector logging displays current endpoint/count progress, processing stages,
publication results, and application errors/retry warnings. Endpoint progress is
limited to once per minute, plus endpoint transitions and completion; per-request,
per-page, pacing, and individual-device chatter is omitted. Worker logs are
forwarded through the invoking Function logger rather than unstructured stdout.
Only application status lines and concise errors are forwarded; raw HTTP request/
response dumps, headers, HTML/XML bodies, and traceback continuation lines are not.
Status/error summaries omit URLs and response bodies; collection failures still
fail their activity and retain an error summary.
Only `Function.<name>.User` categories allow Information messages. Host,
successful invocation, Durable coordination, and SDK logs are Error-only.
Successful invocation request telemetry is therefore no longer collected through
`Host.Results`; failed invocations remain visible. Lease timing, checkpoints, and
collection behavior are unchanged. Deploy Function code to apply these filters.
Function deployment removes existing `AzureFunctionsJobHost__logging__logLevel__*`
app-setting overrides so stale Trace/Information overrides cannot defeat the
packaged filters. Other monitoring and runtime-storage settings are preserved.

Install or refresh the editable project once after pulling CLI changes on
macOS or Linux:

```text
python -m pip install -e ".[dev]"
```

Activate the environment on macOS/Linux:

```bash
source .venv/bin/activate
```

On Windows PowerShell, create and activate a separate environment:

```powershell
python3 --version
python3 -m venv .venv-win
.\.venv-win\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -c "import sys, vulnerability_view; print(sys.executable)"
```

If `python3` is not available on Windows, use `py -3.14` for the first two
commands.

The verification output must end in `.venv-win\Scripts\python.exe`. After
activation, run operations as
`python -m vulnerability_view.operations_cli <command>`. If activation is
blocked, use
`.\.venv-win\Scripts\python.exe -m vulnerability_view.operations_cli <command>`
as a fallback.

The Python CLI replaces platform-sensitive Bash, `date`, `jq`, `curl`, and
external ZIP operations with Python implementations. Azure CLI, Terraform, and
Git remain external prerequisites because they perform the actual Azure,
infrastructure, and source-version operations.

The legacy equivalents remain:

```text
./infra/deploy.sh tfdeploy function
./infra/check-runs.sh 10 --progress
./infra/check-function-logs.sh 1 10 --status-only
```

Status commands show Azure UTC timestamps together with the local time zone of
the machine running the command. The dashboard similarly shows UTC and the
browser's local time for the active snapshot and recent collection runs.

On native Windows, use `python -m vulnerability_view.operations_cli`; the `.sh` scripts require WSL or
another Bash environment.

## Identity model

There are two different identities.

### Local operator identity

Terraform and Azure CLI commands normally run as the user currently authenticated
by `az login`. Before planning, applying, deploying, verifying, or invoking, check:

```bash
az account show \
  --query '{User:user.name,UserType:user.type,Tenant:tenantId,Subscription:name,SubscriptionId:id}' \
  --output table
```

The tenant and subscription must match `tenant_id` and `subscription_id` in the
environment-specific `terraform/main.tfvars.json`.

`az account set --subscription ...` selects a subscription for the current login.
It does not change the signed-in user or tenant.

Terraform's AzureRM and AzureAD providers use the current Azure CLI login unless
the workstation deliberately supplies another supported authentication method,
such as service-principal environment variables. Azure CLI operations in
`deploy.sh` always use the active Azure CLI context.

The local operator identity performs:

- Terraform initialization, validation, planning, and apply;
- role and Microsoft Entra changes described by the Terraform plan;
- Function and Web App package upload;
- deployment verification;
- source API preflight;
- explicitly confirmed manual Function invocation.

### Deployed runtime identities

Scheduled Function collections and Web App requests do not run as the interactive
operator.

- The Function uses its configured collector managed identity.
- The Web App uses its configured dashboard managed identity.
- Terraform assigns the required Azure RBAC and application permissions.

Signing out of Azure CLI after deployment does not change either runtime identity.

## Local prerequisites

Run commands from the repository root. The script expects:

| Tool or file | Used for |
|---|---|
| Python 3.12 or tested Python 3.14.7 | Cross-platform orchestration, ZIP creation, HTTP, JSON, and time handling; Azure runtimes remain on Python 3.12 |
| `az` | Azure package deployment, verification, keys, settings, and invocation |
| Terraform 1.10+ | Infrastructure initialization, plan, apply, output, and validation; on Windows it may be on `PATH` or saved as repository-root `terraform.exe` |
| `git` | Function commit metadata and fallback release version |
| `.venv/` or `.venv-win/` | Project Python, status, and Defender preflight commands |
| `terraform/main.tfvars.json` | Ignored environment names, IDs, settings, and Function version |
| Terraform state | Existing-resource identity and outputs consumed by package operations |

The supplied configuration writes Terraform state locally to
`infra/terraform/terraform.tfstate` on the deployment workstation. A shared
remote backend can be configured separately, but remote-state setup and
migration are not part of this deployment documentation.

Do not commit `main.tfvars.json`, Terraform state, saved plans, packages, or local
operator notes.

On Windows, the operations CLI first checks for `terraform.exe` in the
repository root and then checks `PATH`. This allows an operator to use an
approved standalone Terraform executable without changing the system or user
`PATH`. Keep the executable at the repository root, not in `infra/terraform/`;
it is excluded from Git.

## What the script calls

The Python operations CLI calls:

- `terraform init`, `validate`, `plan`, `show`, `apply`, and `output`;
- Azure Resource Manager container inventory through `az rest`;
- `az functionapp` settings, restart, ZIP deployment, keys, and function listing;
- Azure Resource Manager trigger synchronization through `az rest`;
- `az webapp deploy`, deployment-log queries, and Web App inspection;
- the local `vulnerability-view` CLI for preflight and current-storage status;
- Git for version metadata;
- Python `zipfile`, `requests`, `json`, and `datetime` for portable packaging,
  HTTP, configuration, and UTC timestamp handling.

`deploy.sh` calls the same Azure and Terraform surfaces but uses Bash, `zip`,
`jq`, `curl`, and platform shell utilities.

It does not directly delete retained ADLS history.

## Cumulative Terraform stages

The Terraform stages are cumulative:

1. `foundation` — resource group and protected history storage;
2. `function` — foundation plus collector Function, identities, permissions,
   runtime storage, schedule, and monitoring;
3. `webapp` — foundation and Function plus the authenticated dashboard.

For a streamlined initial deployment after configuration and Azure
CLI sign-in, select option 1 in `deployment-menu.sh` or
`deployment-menu.ps1`. It plans and applies the cumulative `webapp` stage,
deploys and verifies both code packages, and optionally starts the first live
collection. Use the separate stages when the environment requires independent
review or approval at each infrastructure boundary.

The Function stage grants its managed identity Reader once at
`collector_management_group_id`. The collector then inventories subscriptions
under that management group and nested management groups.

Once the Web App exists, use `tfplan webapp` for later infrastructure changes so
the saved plan preserves all deployed stages. The helper blocks lower-stage plans
when they would omit a known higher stage.

After Function or cumulative Web App infrastructure applies, the helper removes
the legacy `AzureWebJobsStorage` connection string that AzureRM can retain or
inject during a Flex Consumption resource update. It then verifies that only the
managed-identity runtime-storage settings remain before reporting success.

### Collector hosting and upgrading existing Flex deployments

The collector uses a separate Linux Dedicated B2 App Service plan with one
fixed worker and Always On. No autoscale policy is provisioned. This removes
consumption-driven scale-in; it does not prevent maintenance, deployment, or
failure-related restarts. Billing is continuous rather than per execution.
The schedule and append-only publication contract are unchanged. Collection
uses checkpointed Durable activities rather than one invocation carrying the
whole run. The packaged host uses `functionTimeout: "-1"`; isolated activity
workers instead enforce one six-hour deadline from the original run timestamp.
Preparation, collection, waits, retries, processing, verification, and publication
share that budget. There is no separate 20-minute processing limit. Console
warnings begin at two hours. Individual API request timeouts, retry budgets, and
cooperative collection yields remain.

### Resumable collection deployment and recovery

Pull the update, refresh project dependencies, deploy Function code, then verify
all triggers. Existing Dedicated environments with the Terraform-provisioned
runtime Blob, Queue, and Table data roles do not need a different hosting tier.
Apply the cumulative infrastructure stage first if upgrading an older hosting
configuration. Do not replace or delete either Storage account or its contents.
Code-only Function deployment and verification use the configured resource group
and Function App names, not local Terraform outputs, and validate the Azure CLI
tenant/subscription first. A stopped app is started automatically before upload;
missing local state is not a reason to reapply infrastructure.
Deploy when the old collector is idle. Pages lost from an older synchronous
worker's temporary disk cannot be recovered by this update; restart-safe
checkpoints begin with the first run of the new collector.

Redeployment does not terminate a Durable instance. For an obsolete multi-day
run, use `python -m vulnerability_view.operations_cli stop-collection --run-id <exact-live-run-id> --confirm`
before deployment. This verifies Durable termination
and then stops the Function host to end in-flight activity, without deleting
Storage history or changing the published pointer. Deployment starts the host
again. See the [operator sequence](../docs/operations-and-configuration.md#stopping-an-obsolete-run-before-deployment).

The `DvmCollectionV1` task hub uses the existing **separate runtime Storage**
account through managed-identity `AzureWebJobsStorage` settings. Durable queues,
leases, and instance tables are mutable runtime state, not retained DVM history.
The regular Azure Storage provider is used; no managed Durable Task Scheduler
service is provisioned. Keep the task hub name and runtime account stable across
restarts and redeployments. Never purge an active or failed instance to retry it.

Successful HTTP responses are checkpointed immediately to immutable, per-run
`raw/` objects. Activities bound new requests and live work; throttling schedules
a Durable timer rather than blocking a worker through long quota cooldowns.
Run settings, SLA policy, timestamp, and previous publication are frozen in a
per-run plan. A host restart can replay saved responses without downloading them
from Defender again. Delta pages additionally have append-only continuation
journals: collection resumes at the next page without replaying prior response
bodies, and restores page evidence for processing after download completes.
Delta uses 50,000 rows/page and four-second request pacing independently of the
full-findings page size. The local disk cache is only an optimization.

With `exclude_scale_sets=true`, new runs use device-scoped snapshots instead of
the global delta feed, including scheduled `auto` runs. Scale-set devices are
identified from inventory before findings requests. Per-device continuation
journals skip completed work on retry and restore bodies after all devices
finish. Snapshot comparison preserves the existing lifecycle protections and
reports resolved-between-runs evidence, not intermediate events or exact patch
times. No customer device-group changes are required.

There is one collection instance, `vulnerability-collection`. A normal, full,
or scheduled trigger retains an active run within its six-hour budget. For a
failed run still within that budget, it submits a new
Durable execution under the same instance ID with the original run input and
a reset consecutive-failure counter. The failed runtime execution/history is
replaced, while immutable DVM evidence, checkpoints, frozen policy/baseline,
run ID, and snapshot time remain unchanged. Completed work is reused.
Recovery and continuation never extend the original deadline. At expiry, the
supervisor stops the actual worker, including a silent or blocked subprocess.
The orchestration reports `timed_out` (`timedOut: true`); a Durable `Completed`
state alone is not collection success. The next trigger starts a fresh snapshot
instead of recovering expired checkpoints. History is preserved and incomplete
output cannot publish. If a trigger finds an expired instance still active, it
requests termination without starting overlapping work in that trigger.
Durable rewind is not used because this orchestration uses durable timers.
A full request does not change the scope of an already
active/failing run; let that run finish before requesting a new forced full run.
Inspect `check-runs --progress`, correct permission/configuration failures, and
invoke again to request recovery. Submission is not proof of execution;
verify state and progress advance. Missing original run identity is an explicit
recovery failure, not permission to start a fresh snapshot.
An operator can explicitly use `invoke function --confirm --fresh` for an
obsolete failed run after a newer baseline has been published; this refuses
active runs and preserves retained evidence.
Incomplete CVE metadata triggers up to three targeted refresh attempts for only
the missing IDs. Attempt responses use separate append-only checkpoint paths,
retain the original evidence, and share activity request/time limits and
throttling cooldowns. Replay does not reset that retry budget. Findings remain
intact. Missing details and metadata HTTP/transport availability failures are
non-blocking enrichment gaps: the run publishes as `PartialSuccess` after required
findings and files pass verification. Endpoint status records `MissingCveCount`,
`MissingCveIds`, and the issue. Curated findings and CVE details have
`CveMetadataStatus=Unavailable`, with null CVSS/exploit data shown as unknown in
the dashboard. No finding is dropped, marked fixed, or assigned fabricated
metadata; no raw response is invented for a failed request.
Recovery of an older missing-CVE failure can reuse its retained responses and
complete with warnings. Later full/delta runs use new immutable request paths
and retry unavailable metadata, including unavailable baseline placeholders.
Unexpected IDs, malformed responses, and corrupt evidence still fail explicitly.
Failed required endpoints and integrity conflicts
remain explicit failures; do not clear checkpoints to hide them.

Raw collection, disk-backed processing, file verification, and pointer
publication are separate stages. File verification has independent durable
activities. Only a complete, verified immutable bundle can advance
`current/manifest.json`, and its previous ETag must still match. No incomplete
run replaces the last good dashboard snapshot. Existing table schemas, SLA and
lifecycle rules, and dashboard data formats are preserved.

Processing also checkpoints normalization, reconciliation, events, summaries,
and bundle preparation to immutable, verified intermediate artifacts. A fresh
worker restores the previous stage instead of repeating completed processing.
Resume is at **stage boundaries**, not at every finding: an interrupted stage
restarts that stage. Individual processing stages still scan their whole input,
without an elapsed-time cutoff. `[processing]` traces include raw/baseline
restoration, dataset counts, compressed bytes, replay/normalization row progress,
artifact transfer, bundle verification, and checkpoint commits. A heartbeat
every 60 seconds reports activity elapsed time, CPU time, last-progress age, and
the latest substep even while a transfer or transform is blocked. A heartbeat is
evidence of a live worker, not of advancing rows or successful publication.
Platform restarts and finite memory/disk capacity still apply; stage-boundary
recovery and publication integrity checks are unchanged.

Durability prevents lost API work; it does not remove Defender quotas, guarantee
a completion time, or make Dedicated hosting scale to zero. Larger CVE filter
batches reduce round trips, but API latency, dataset size, local disk, processing,
and Storage still affect cost and duration. Validate the first customer run
before drawing production throughput or cost conclusions.

The local synthetic scale check completed **2,000,000 findings and 2,000,000
finding events** in 408 seconds, with approximately 75 MB peak native RSS.
The longest measured stage was reconciliation at 136 seconds. All 21 bundle
files passed integrity verification, including exact finding/event row counts,
schema version 2, and normalization version 3. This is a local processing
measurement, not an Azure B2 or Defender-download benchmark; API latency,
remote checkpoint transfers, and publication uploads are excluded.

To reproduce on macOS/Linux from the repository root:

```bash
PYTHONPATH=src python tests/benchmark_bounded_finalization.py \
  --findings 2000000 --budget 900 \
  --root output/benchmarks/bounded-finalization-2m
```

The benchmark uses generated local data only. Its raw inputs and checkpoint
artifacts can consume substantial local disk; deleting those specifically named
local benchmark files never authorizes deleting Azure history.

Upgrading an existing Flex deployment requires an infrastructure apply, not
just deployment-menu option 3. The collector plan name gains a `dedicated`
suffix, forcing replacement instead of attempting an unsupported FC1-to-B2
SKU update. Terraform's default destroy-before-create ordering and the
existing Function-to-plan dependency remove the old Function before creating
its Dedicated replacement under the same Function App name. Expect collector
downtime; deploy only when no collection is active.

For an environment with the dashboard already deployed:

```bash
python -m vulnerability_view.operations_cli plan webapp
python -m vulnerability_view.operations_cli show webapp
python -m vulnerability_view.operations_cli apply webapp
python -m vulnerability_view.operations_cli deploy function
python -m vulnerability_view.operations_cli verify function
```

Use the cumulative `webapp` stage to retain the existing dashboard; it does
not redeploy dashboard code. If the dashboard has never been provisioned,
use the `function` stage instead. Review the saved plan: replacement of the
collector Function, its hosting plan/name, and related diagnostics is expected.
Do not approve deletion or replacement of the history account, history/current
containers, workflow data, or resource group. Existing runtime storage,
collector identity, API grants, history permissions, and monitoring resources
should be retained. Never destroy the environment or remove Terraform state
to perform this upgrade.

The old `function_instance_memory_in_mb` value remains accepted in customer
parameter files for compatibility but is unused on Dedicated hosting. The
fixed B2 SKU determines collector capacity (2 cores, 3.5 GB); memory changes
require a separately reviewed plan/SKU change, not that legacy value.
The unused private `function-releases` container is retained during migration;
it is no longer the Dedicated app's deployment configuration.

## Command matrix

| Command | What it does | Terraform? | Azure login? |
|---|---|---:|---:|
| `plan foundation/function/webapp` | Initializes, validates, and saves the stage plan | Plan only | Yes |
| `apply <stage>` | Applies only the already-saved reviewed plan | Apply | Yes |
| `deploy function` | Builds and uploads Function code to existing infrastructure | No | Yes |
| `deploy webapp` | Builds and uploads dashboard code to existing infrastructure | No | Yes |
| `verify foundation/function/webapp` | Reads deployed resources and current state | Outputs only | Yes |
| `preflight` | Tests Defender source access as the local signed-in user | No | Yes |
| `invoke function --confirm` | Starts one live collection after explicit confirmation | No | Yes |
| `destroy function --confirm` | Plans, shows, and applies removal of replaceable Function resources | Apply | Yes |
| `check-runs --progress` | Shows active telemetry plus durable completed runs | No | Yes |
| `check-function-logs` | Queries Function invocation telemetry | No | Yes |

## `tfplan`

Example:

```bash
python -m vulnerability_view.operations_cli plan function
```

The command calls:

```text
terraform init -input=false
terraform validate
terraform plan -input=false -var-file=main.tfvars.json ... -out=function.tfplan
```

It does not apply the plan. Review it:

```bash
python -m vulnerability_view.operations_cli show function
```

Saved plans can contain environment-specific information and must not be
committed.

## `tfapply`

Example:

```bash
python -m vulnerability_view.operations_cli apply function
```

The command refuses to continue unless the matching saved plan exists. It applies
that exact plan and does not regenerate or refresh it. If configuration changed
after planning, create and review a new plan.

## `tfdeploy function`

Example:

```bash
python -m vulnerability_view.operations_cli deploy function
```

This is a code-package update. It does not run Terraform. It requires existing
Terraform outputs for the resource group and Function App.

The command:

1. Reads the release from tracked `function-version.json`, not the legacy
   `function_version` Terraform value or a `FUNCTION_VERSION` override.
2. Creates temporary build metadata with version, UTC time, and Git commit.
3. Packages `function_app.py`, `function-version.json`, `host.json`,
   dependencies, `src/`, the SLA policy, and build metadata.
4. Removes the legacy `AzureWebJobsStorage` setting that would override the
   managed-identity host-storage configuration, plus stale host logging overrides.
5. Restarts the Function and waits for configuration/RBAC propagation.
6. Uploads the ZIP using Azure Function remote build.
7. Sets `COLLECTOR_VERSION` only after successful package deployment.
8. Waits for the Python worker to index the required functions.
9. Synchronizes Function triggers through Azure Resource Manager.

The command does not invoke a collection. A scheduled run occurs only when its
timer is due; a manual run requires `tfinvoke function`.

## `tfdeploy webapp`

Example:

```bash
python -m vulnerability_view.operations_cli deploy webapp
```

This is also a code-package update and does not run Terraform. It reads
the release version from the pulled `dashboard/config.js` (or a one-command
`DASHBOARD_VERSION` override), stamps that release plus the UTC deployment
revision into the UI, packages the dashboard and Python server without local
dashboard data, uploads a clean ZIP deployment, and monitors Kudu/Oryx
deployment status. The app is not restarted while Oryx writes the package;
after Kudu succeeds, the command stamps the hosted version and starts the app.
A client-side timeout is treated as provisional until Kudu reports success or
failure.
Customers can pull the release with `git pull --ff-only` and run deployment menu
option 4 without editing local version fields or running the maintainer's version
bump script. A stale `dashboard_version` in customer Terraform values does not
block or relabel the code deployment; those customer settings are not rewritten.

Function and Web App package deployments are independent:

Web App verification checks only the Web App and its authentication/access
configuration; it does not require Function outputs or check or restart the
collector. If the Web App package deployed successfully but verification failed,
rerun `verify webapp` after correcting the local verification tool, without
redeploying the package. Function verification retains its managed-identity
storage and trigger checks.

```bash
./infra/deploy.sh tfdeploy function  # collector only
./infra/deploy.sh tfdeploy webapp    # dashboard only
```

## `tfverify`

Verification is read-only against the deployed resources.

Function verification prints the configured collector version, lists keys and
timer triggers, then uses the local CLI with the current local Azure credential
and Terraform-provided storage names to report the current durable run.

Web App verification shows the site state and hostname, checks that an anonymous
request receives the expected authentication redirect, and prints the Enterprise
Application assignment details.

## `tfpreflight`

```bash
./infra/deploy.sh tfpreflight
```

This tests Defender endpoints as the current local Azure CLI identity. A successful
preflight does not prove that the Function managed identity has the same access;
verify the deployed Function separately.

## `tfinvoke function`

First confirm that no run is active:

```bash
python -m vulnerability_view.operations_cli check-runs --limit 5 --progress
```

Then explicitly acknowledge that the invocation writes a new immutable run:

```bash
python -m vulnerability_view.operations_cli invoke function --confirm
```

The script retrieves the Function host key using the current Azure CLI identity and
posts to the Function administration endpoint. The collector itself then runs as
the Function managed identity.

Never invoke when status is `ACTIVE` or `INDETERMINATE`.

## `tfdestroy function`

This is not part of normal deployment or code updates. It requires:

```bash
python -m vulnerability_view.operations_cli destroy function --confirm
```

The command targets replaceable Function resources only, displays its destruction
plan, and preserves the protected history account and retained evidence. Always
review the plan. Never interpret “start over,” “reset,” or “redeploy” as approval
to delete retained Azure Storage data.

## Common workflows

### Initial deployment

```bash
python -m vulnerability_view.operations_cli plan foundation
python -m vulnerability_view.operations_cli show foundation
python -m vulnerability_view.operations_cli apply foundation
python -m vulnerability_view.operations_cli verify foundation

python -m vulnerability_view.operations_cli plan function
python -m vulnerability_view.operations_cli show function
python -m vulnerability_view.operations_cli apply function
python -m vulnerability_view.operations_cli deploy function
python -m vulnerability_view.operations_cli verify function

python -m vulnerability_view.operations_cli plan webapp
python -m vulnerability_view.operations_cli show webapp
python -m vulnerability_view.operations_cli apply webapp
python -m vulnerability_view.operations_cli deploy webapp
python -m vulnerability_view.operations_cli verify webapp
```

### Function code only

Pull the published source containing the intended `function-version.json`, then:

```bash
python -m vulnerability_view.operations_cli deploy function
python -m vulnerability_view.operations_cli verify function
```

Changing the source version or applying Terraform alone does not upgrade the
running collector. Deployment menu option **3** performs this Function
deploy/verify sequence; Web App option **4** does not deploy the collector.
Existing run metadata retains its original collector version.

### Dashboard code only

```bash
python -m vulnerability_view.operations_cli deploy webapp
python -m vulnerability_view.operations_cli verify webapp
```

### Infrastructure change after the Web App exists

```bash
python -m vulnerability_view.operations_cli plan webapp
python -m vulnerability_view.operations_cli show webapp
python -m vulnerability_view.operations_cli apply webapp
```

Deploy code afterward only when application code or its package changed.

## Safety boundaries

- `tfplan` does not apply.
- `tfapply` applies only a saved reviewed plan.
- `tfdeploy` does not create infrastructure or invoke collection.
- `tfinvoke` writes a new immutable run.
- Package updates do not delete Azure history.
- Local `output/` cleanup does not authorize Azure deletion.
- Paths under `raw/`, `curated/`, and `runs/` remain append-only.
- Only `current/manifest.json` is replaceable after successful run validation.
- The protected history account must survive Function or Web App replacement.

## Related documentation

- [Complete Azure deployment guide](../DEPLOY.md)
- [Greenfield deployment checklist](../docs/greenfield-deployment.md)
- [Command reference](../docs/command-reference.md)
- [Operations and monitoring](../docs/operations-and-configuration.md)
- [Troubleshooting](../docs/troubleshooting.md)
- [Configuration reference](../docs/configuration-reference.md)
