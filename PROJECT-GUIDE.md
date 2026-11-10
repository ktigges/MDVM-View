# Vulnerability View: project and engineering handoff

## Purpose and boundaries

This project keeps Defender Vulnerability Management evidence and reports what
is vulnerable, what changed, and whether confirmed remediation met the retained
SLA. Defender remains the detection and reassessment system. This application
does not patch machines, change Defender detections, or submit remediation tasks.
Dashboard work status is shared coordination, not a Defender assignment.

There are two deployed applications:

- The collector runs in Azure Functions with Durable Functions. It reads source
  APIs, retains evidence, reconciles history, and publishes completed snapshots.
- The viewer runs FastAPI and Uvicorn in a Web App. It prepares SQLite indexes
  and serves bounded, snapshot-specific reports to the browser.

They have separate identities, releases, and deployment packages. Deploying
either application does not itself collect fresh data.

## Counting rules

**A machine is vulnerable to a CVE regardless of how many affected products or
versions are installed.** One machine/CVE relationship is one vulnerability.
Software records support detection, confirmation, and audit; they do not
multiply the vulnerability.

The dashboard reports distinct CVEs and distinct machines separately. It does
not use software-record totals or machine/CVE relationship totals as headline
metrics. For example, 100 CVEs affecting 100 machines remain 100 CVEs and
100 machines, not a headline of 10,000 outcomes.

These are different questions:

| Question | Count |
|---|---|
| How many vulnerabilities are represented? | Distinct CVE IDs |
| How many machines are affected? | Distinct machine IDs |
| What work may address them? | Distinct recommendations |
| Is this particular vulnerability gone from this machine? | All supporting evidence for that machine/CVE |
| Is a CVE fully cleared? | No unresolved machine remains in the selected scope |
| Is a machine fully cleared? | No unresolved CVE remains in the selected scope |

These rules apply to summaries, severity breakdowns, SLA, details, reporting,
and entity CSV exports. A recommendation may address many machines and CVEs.
Recommendations, CVEs, and machines are not interchangeable units.

### Internal evidence identity

The retained `findings` dataset is intentionally more detailed. `FindingKey`
uses the source row ID where available, otherwise a SHA-256 identity from
machine ID, CVE ID, product name, and product version. A version change can
retire one evidence key and introduce another without clearing the machine/CVE.

That schema is needed for reconciliation and replay. Removing these records
because their counts are not displayed would lose evidence and break
confirmation. [LOGIC.md](LOGIC.md) defines the calculation rules.

## Getting the project onto another computer

The handoff is a GitHub checkout at an agreed commit, not a copy of an existing
workstation directory. The incoming engineer needs repository access. Unpushed
changes are not available in a clone.

```bash
git clone https://github.com/ktigges/MDVM-View.git
cd MDVM-View
git checkout <handoff-commit>
```

The source workflow uses `main` for development and `latest` for customer
distribution. The handoff record identifies the intended branch, commit,
deployed Web App version, and deployed Function version.

### Local Python environment

The package supports Python 3.12 and later; both hosted applications use 3.12.
An incoming engineer creates a new virtual environment rather than copying one.

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

Windows PowerShell:

```powershell
py -3.12 -m venv .venv-win
.\.venv-win\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Python, Git, and Node.js with `node:test` support cover development and tests.
There is no front-end package install or JavaScript build step. Azure CLI,
Terraform, and deployment packaging tools are needed for hosted operations;
[DEPLOY.md](DEPLOY.md) has their prerequisites.

Local test data does not require customer credentials:

```bash
vulnerability-view generate-synthetic
vulnerability-view validate
```

The generated data is labeled synthetic. A clean local workspace keeps it
separate from imported customer data. Local configuration uses
[.env.example](.env.example); environment variables already present in the
shell take precedence over values loaded from an environment file.

```bash
DASHBOARD_AUTH_ENABLED=false ./start-app.sh
```

Windows uses the activated environment:

```powershell
$env:DASHBOARD_AUTH_ENABLED = "false"
python -m uvicorn vulnerability_view.dashboard_server:app --app-dir src --host 127.0.0.1 --port 8000 --reload
```

Authentication is disabled only for an isolated local viewer, not the hosted
application. Local tracking, when explicitly enabled, is in memory and resets
on restart. [Local evaluation](docs/local-evaluation.md) and
[development](docs/development.md) cover the other supported local paths.

### What transfers separately

The repository does not contain the operational authority for an existing
deployment. The protected handoff record contains:

- Azure tenant/subscription and exact resource targets.
- The authoritative Terraform state, its backup location, and environment values.
- Managed identities, Entra applications, access groups, roles, and administrators.
- Approved SLA policy, schedule, monitoring, and recovery responsibilities.
- The current immutable run and pointer, and any authorized sample transfer.

Terraform state is local by default. A fresh clone is not replacement state
and must not be used to recreate existing infrastructure by assumption.
Credentials, state, private configuration, customer ZIPs, diagnostic exports,
and virtual environments do not belong in Git. Customer samples require
authorized encrypted transfer; a checksum-protected ZIP is not encrypted.

## Collection and publication

### Source APIs

Required Defender evidence includes machine inventory, device vulnerability
relationships, and recommendation data. Inventory is collected before full
device-scoped vulnerability calls. CVE catalog enrichment supplies descriptions,
scores, and exploit context; a missing catalog record does not erase the
machine's vulnerability.

Optional sources include Microsoft Graph Secure Score, Azure subscription
inventory, and experimental remediation-task evidence. Their availability is
recorded separately. A failed required device query fails the run; it does not
silently produce a successful snapshot with that device omitted.

Missing CVE enrichment can produce a partial-success collection with explicit
unavailable metadata and unknown values. Invalid IDs, malformed responses,
corrupt evidence, and missing required data remain errors.

[Application flow](docs/application-flow.md) lists the exact endpoints, retry
behavior, stages, and files.

### Full and delta

Automatic collection uses deltas against a valid prior baseline. Initial
collection, a baseline beyond the source's 14-day delta lookback, and weekly
reconciliation require full collection. The supplied weekly setting is Sunday.
A later collection that day can use the completed full baseline.

Automatic full collection still uses targeted recommendation enrichment.
An explicit new manual full request also requests full relationship enrichment.
An active or retried run keeps its original frozen scope; changing a requested
mode does not rewrite work already in progress.

Delta source responses are applied to the prior baseline. Completed full and
delta runs publish the same normalized snapshot contract. A new customer ZIP
is not necessarily a delta: its retained baseline, timestamps, events, and
collection metadata determine what can be compared.

### Continuation and failure

Durable orchestration coordinates one active collector workflow. API paging,
quota waits, retries, and checkpointed processing can span activities and worker
restarts. Frozen run settings, policy, baseline, and retained work keep a
continuation consistent.

The activity supervisors enforce a six-hour limit from the original run time;
retries and quota waits do not restart that clock. Failed or expired evidence
is retained. A successful trigger request is not proof of completed publication.
The operations status and completed manifest are authoritative.

### Publication transaction

Raw pages, curated datasets, the exact policy, indexes, and the run manifest
belong to a new immutable run. Sizes and hashes are checked before the separate
current pointer advances. A failed upload or incomplete run does not replace
the previous completed dataset.

**Storage protections are part of the project contract:**

- `raw/`, `curated/`, and `runs/` are append-only, using `overwrite=False`.
- Only `current/manifest.json` in the separate pointer container is replaceable
  in the retained-data publication process.
- Application code does not call history deletion APIs or configure automatic
  lifecycle deletion for retained DVM history.
- A reset, rebuild, cleanup, redeployment, or local output cleanup is not
  approval to delete Azure evidence.
- Any destructive operation requires separate human approval naming the exact
  operation and target.
- Replacing application hosting preserves the history account as a separately
  protected data resource. Function runtime storage is separate.

Starting over means a new immutable run and, after validation, a pointer update.
The [data reference](docs/data/README.md) defines the storage layout and schemas.

## Scope and lifecycle

Inventory and vulnerability coverage are different. An inventory machine can
have no current CVE evidence; a discovered-only device is not automatically
assessed as clean. Missing metadata is unknown, not zero risk.

Configured scale-set exclusion affects collection scope. A device can remain
in raw inventory yet disappear from curated scope when better metadata first
identifies it as a scale-set instance. A lower machine total is not, by itself,
proof of remediation. Configurable workload grouping is a presentation rule,
not permission to discard retained evidence.

Asset class and operating queue are derived from Azure metadata, subscription
context, cloud tags, and platform evidence. They are not authoritative work
assignments. The default recommendation filter is Vulnerability; classifier
limitations can place some end-of-support uninstall guidance in Misconfiguration.

Lifecycle distinguishes current detection, qualified absence, confirmation,
returned detection, and reopening:

| State | Meaning |
|---|---|
| Open / Reopened / DetectionReturned | Current detection |
| PendingConfirmation / PendingVerification | Unresolved; absence is not yet a confirmed fix |
| Fixed | Qualified absence confirmed by a subsequent qualified collection |

The first qualified absence is the effective remediation observation. It is
not an exact patch-installation time. Consecutive qualified collections confirm
it while the machine remains active and fresh. Whole-device disappearance or
stale/offline evidence does not establish a fix by itself. A returned detection
revokes an unconfirmed fix; reopening follows an earlier confirmed fix.

Comparison requires compatible prior evidence. One point-in-time import cannot
establish a new remediation history by itself. Sample import and replay follow
[the sample guide](docs/sample-replay.md); diagnostic replay stays local unless
publication is explicitly authorized.

## SLA and progress

The SLA clock starts at the collector's first observation, not CVE publication
or a Defender remediation-task due date. Existing recorded policy, clock, and
deadline survive later collections and policy changes. A machine/CVE uses its
earliest applicable retained deadline across supporting software evidence.

The checked-in thresholds are examples until approved. Their exact matches
and durations are in [config/sla-policies.json](config/sla-policies.json).
Exploit-specific matches take precedence; the shortest matching duration is
used within the selected group.

The dedicated SLA page counts CVEs and machines separately:

- Each unresolved entity appears once, at its highest unresolved severity.
- Overdue takes precedence over unknown deadline, then not yet due.
- Not yet due is remaining time, not remediation success.
- Pending fixes remain unresolved.
- Partial removal is improved, not fully cleared.
- A full clearance is late if any component was late; otherwise unknown if a
  required deadline/completion is missing; otherwise on time.
- Earlier retained component clearances are included in that full-clearance
  assessment. The last component alone does not determine success.

On-time percentage uses assessed full clearances, excluding unknown deadlines.
No assessed completions means no percentage, not 100%. Unknown deadlines are
shown separately. Missing historical coverage produces unavailable values,
not invented zeros.

Dedicated periods include month-to-date and completed UTC calendar weeks and
months. Executive Snapshot has its own timeframe, subscription, and operating
owner selectors. Applicable workspace filters still constrain it. A scoped
clearance is not a claim that the vulnerability is gone from the whole tenant.

Activity tiles count distinct entities with observations in a selected window.
A machine with one observed fix may still have other CVEs. A recommendation
with observed progress may still need substantial work. Those activity counts
are not full-clearance totals.

## Viewer startup, indexes, and caches

The viewer selects a completed manifest, verifies evidence, and restores or
builds the primary query index, historical index, read model, search projection,
and prepared reports. Shared preparation runs in the background. Restarting
the Web App may repeat preparation; it does not recollect Defender.

The primary index keeps detailed source evidence. The read model stores shared
aggregate structures. Search has a separate projection. Prepared query products
reuse completed report work. Persistent viewer-cache artifacts are disposable
derivatives in a separate container, not replacements for raw or curated history.

Compatibility depends on snapshot identity, content verification, query/read
model versions, filter identity, policy, and workload grouping. Corrupt artifacts
and storage failures are explicit errors. A missing compatible cache may be
built from retained source data.

The browser requests one ready snapshot, then bounded pages through
`POST /api/dashboard/query`. CSV uses `POST /api/dashboard/export` and streams
all matching rows from that snapshot. Normal tables use 100-row pages with a
200-row API ceiling; management entity tables use their own smaller pages.
The browser does not load and aggregate the entire findings dataset.

Search is debounced. Obsolete work is cancelled, equivalent in-flight work is
shared, and saved results are bounded. Reports/exports use separate heavy-work
admission from interactive queries. HTTP 202 is continuing preparation, not a
partially completed report. Exhaustion and deadline failures are visible.

The previous ready snapshot remains available while its replacement prepares.
Existing browser sessions remain pinned to their selected `snapshotId`.
Evicted or stale evidence produces HTTP 409 and an explicit reload; a request
does not silently switch snapshots.

The default is one Uvicorn process. Additional workers or instances repeat their
own preparation and cache work. Component limits do not cap total process
memory or disk, and two large snapshots may not fit. Local timings are not
hosted capacity guarantees. [Development](docs/development.md) describes the
isolated benchmarks; [application flow](docs/application-flow.md) records limits.

## Authentication and dashboard-owned data

Hosted access uses Entra sign-in and App Service Easy Auth. The server validates
the platform principal; a browser cannot choose the recorded user identity.
`Dashboard.Viewer` grants normal dashboard access.

When enabled, all authenticated dashboard users can update shared recommendation
tracking. The legacy tracker role is not an additional requirement. Events are
immutable in a separate private workflow container and never change source
findings, SLA evidence, or the current pointer.

An in-progress or marked-fixed status is not a confirmed remediation. New
collection evidence determines confirmation and reassignment. The seven-day
reassignment clock uses successful collection time, not wall-clock time over
stale evidence.

Branding requires `Dashboard.Administrator`. The optional diagnostic evidence
browser requires its configured `Data.Evidence.Reader` authorization. Workflow,
branding, viewer-cache, history, and pointer permissions have separate purposes.
[DEPLOY.md](DEPLOY.md#runtime-identities-and-permissions) defines runtime access.

## Source map and change boundaries

| Responsibility | Maintained source |
|---|---|
| Triggers and orchestration entry points | [function_app.py](function_app.py) |
| Run state, paging, transport, continuation | [collection_workflow.py](src/vulnerability_view/collection_workflow.py), [collection_worker.py](src/vulnerability_view/collection_worker.py), [collection_transport.py](src/vulnerability_view/collection_transport.py) |
| Normalization and lifecycle | [normalizer.py](src/vulnerability_view/normalizer.py), [live_collector.py](src/vulnerability_view/live_collector.py), [bounded_processing.py](src/vulnerability_view/bounded_processing.py), [resumable_processing.py](src/vulnerability_view/resumable_processing.py) |
| Publication and evidence | [storage_writer.py](src/vulnerability_view/storage_writer.py), [export_writer.py](src/vulnerability_view/export_writer.py) |
| Query and management semantics | [dashboard_queries.py](src/vulnerability_view/dashboard_queries.py), [dashboard_management.py](src/vulnerability_view/dashboard_management.py) |
| Indexes, aggregates, filters, search | [dashboard_index.py](src/vulnerability_view/dashboard_index.py), [dashboard_read_model.py](src/vulnerability_view/dashboard_read_model.py), [dashboard_filter_cube.py](src/vulnerability_view/dashboard_filter_cube.py), [dashboard_search.py](src/vulnerability_view/dashboard_search.py) |
| Readiness, snapshot retention, persistent cache | [dashboard_preparation.py](src/vulnerability_view/dashboard_preparation.py), [dashboard_snapshots.py](src/vulnerability_view/dashboard_snapshots.py), [dashboard_cache.py](src/vulnerability_view/dashboard_cache.py), [dashboard_publication.py](src/vulnerability_view/dashboard_publication.py) |
| API, access, cancellation and admission | [dashboard_server.py](src/vulnerability_view/dashboard_server.py), [dashboard_control.py](src/vulnerability_view/dashboard_control.py), [dashboard_jobs.py](src/vulnerability_view/dashboard_jobs.py) |
| Browser | [app.js](dashboard/app.js), [index.html](dashboard/index.html), [styles.css](dashboard/styles.css), [config.js](dashboard/config.js) |
| Work status and branding | [recommendation_tracking.py](src/vulnerability_view/recommendation_tracking.py), [dashboard_branding.py](src/vulnerability_view/dashboard_branding.py) |
| Settings and operator commands | [config.py](src/vulnerability_view/config.py), [dataprep_cli.py](src/vulnerability_view/dataprep_cli.py), [operations_cli.py](src/vulnerability_view/operations_cli.py) |
| Infrastructure and packages | [infra/](infra/), [pyproject.toml](pyproject.toml), [requirements.txt](requirements.txt) |

The maintained Python package is under `src/`. Build output and setuptools
metadata are generated, ignored artifacts, not another source tree.
Supported local, synthetic, sample/replay, and scale-test tools remain under
[tools/](tools/) and [tests/](tests/). Backend compatibility and diagnostic
evidence routes are not the dashboard's reporting model.

## Making and releasing changes

Changes to counting or confirmation require backend tests as well as browser
checks. A renamed label does not correct a duplicated aggregate. Important
cases include duplicate software versions, pending fixes, a returned detection,
missing deadlines, partial clearance, full clearance, prior late components,
scope filters, historical gaps, paging, and all-row CSV exports.

```bash
DASHBOARD_AUTH_ENABLED=false python -m pytest -q
node --test tests/dashboard_queries.test.cjs
git diff --check
```

The auth override isolates tests from a workstation environment file configured
for Azure. It does not change deployed authentication. Performance tests are
opt-in; [development](docs/development.md) lists their selectors.

Web and Function release labels are independent:

```bash
./bump-version.sh web
./bump-version.sh function
```

They read the selected application's source metadata and can run without private
Terraform values. `--dry-run` previews a change. Shared Python changes may
require both releases. A persisted schema/identity change needs the corresponding
index, read-model, prepared-response, or query-product invalidation; a
format-compatible algorithm improvement does not automatically require every
format version to change.

Application-only updates use the existing Web App or Function deployment
command, not a speculative Terraform apply. Infrastructure changes require a
reviewed plan against authoritative state at the highest deployed cumulative
stage. The deployment guides distinguish code, settings, and collection.

Handoff acceptance includes the source commit, passing tests, deployed versions,
correct target/state access, a ready snapshot, verified distinct-entity metrics,
and an understood recovery path. Code transfer alone does not grant Azure
deployment or customer-data access.

## Design decisions and limitations

- Immutable runs and a final pointer switch keep incomplete data out of reports.
- Raw evidence allows audit and replay without repeated source downloads.
- Delta collection reduces API work; full reconciliation re-establishes the baseline.
- Detailed evidence supports confirmation; distinct entities keep reporting clear.
- Pending evidence avoids claiming fixes from incomplete or stale observations.
- SQLite and bounded pages keep customer-sized datasets out of browser memory.
- Separate viewer caches improve restart behavior without modifying evidence.
- Snapshot pinning keeps reports, details, exports, and policy consistent.
- Separate workflow metadata prevents user coordination from rewriting facts.

Retained observation time is not the exact installation time or the original
worldwide discovery date. Historical reconstruction is limited by retained
evidence and is not a replay of every remediation/reopening cycle. Unknown
source metadata stays unknown. Scope/classification changes can move totals
without a fix. Broadly shared workflow tracking is coordination, not an
exclusive work lock. The supplied thresholds and hosting sizes require approval
and validation for the environment.

Detailed references are indexed in [docs/README.md](docs/README.md).
