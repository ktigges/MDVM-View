# Operations and monitoring

This guide covers the running application. Installation is in
[DEPLOY.md](../DEPLOY.md), settings are in the
[configuration reference](configuration-reference.md), and symptoms are in
[Troubleshooting](troubleshooting.md).

Commands below run from the repository root with the project environment
activated. They use the signed-in Azure CLI identity for management operations;
the hosted applications use their managed identities.

## Collection status

```bash
python -m vulnerability_view.operations_cli check-function-logs --hours 1 --limit 3 --status-only
python -m vulnerability_view.operations_cli check-runs --limit 5 --progress
python -m vulnerability_view.operations_cli check-runs --watch
python -m vulnerability_view.operations_cli check-runs --watch --logs
```

The watcher prints a compact line with state, phase, elapsed time, and available
progress rather than the full workflow payload. Menu option 15 enables `--logs`,
adding the latest run-correlated trace from the existing Log Analytics workspace:
for example, `stage=normalize step=write-dataset source=current dataset=findings rows=420,000`.
`source=baseline` distinguishes prior-snapshot scans from `source=current`;
each dataset scan has its own row counter, so counts can reset between inputs.
`logAge` is the age of that trace; heartbeat `stepAge` is the reported age of the
last work-progress update. Neither alone proves the worker is stalled. Ingestion
can lag, and row counts and `stepComplete` describe the reported step, not overall
completion percentage or whole-run success.
Missing or inaccessible telemetry is labeled explicitly; Durable status remains
authoritative. Plain `--watch` requires no telemetry query. Refreshes target
30-second intervals without overlapping requests; slow Azure responses can delay
them. A status connection/read timeout or Azure CLI timeout prints
`STATUS UNAVAILABLE`, explicitly marks collector state unknown, and retries after
30 seconds instead of closing the watcher. This neither restarts nor retriggers
collection. Confirmed workflow failures/timeouts and permanent status errors
still report failure. Ctrl+C stops only watching. Existing detailed diagnostics
remain available.
This is a local console change; no Function deployment or infrastructure update
is needed.

Status combines workflow progress, telemetry, and publication reported through
the collector's managed identity. A trigger request can succeed before work
starts or finishes. The current completed manifest is the publication evidence;
it includes run identity, time, endpoint results, counts, files, and hashes.

`ACTIVE` means work is in progress. `INDETERMINATE` means the available evidence
does not establish completion or inactivity. Neither is permission to start
another collection.

`--watch` prints authoritative workflow progress every 30 seconds without waiting
for Log Analytics. It shows the collection mode, delta `sinceTime`, new requests,
newly downloaded rows/bytes for the latest activity, throttle delays, and the
processing/publication phase. Ctrl+C stops the watcher, not the collector.
An active run older than the two-hour operating target produces a console
warning. A separate six-hour maximum covers the entire original run: preparation,
collection, throttle waits, retries, processing, verification, and publication.
Stage changes, host restarts, checkpoint recovery, and continuation do not reset
that budget. Supervisors stop even silent activity workers at the deadline.
Function logs also report saved-page resume positions and raw-page restoration;
continuation URLs and credentials are not printed.

An expired run reports `timed_out` with `timedOut: true`; Durable may label its
orchestration `Completed`, but the console watcher reports failure, not success.
No new publication is begun after expiry, and incomplete output is never eligible
for publication. Retained evidence is preserved, and the dashboard continues
using completed data. An already submitted atomic pointer update can finish
during cancellation; the deadline is not a rollback.

### Manual collection and recovery

```bash
python -m vulnerability_view.operations_cli invoke function --confirm
python -m vulnerability_view.operations_cli check-runs --limit 5 --progress
```

Manual triggers, status/history checks, console watching, and exact-run stopping
use the configured Function App/resource group names and verify the Azure CLI
tenant/subscription; they do not require local Terraform outputs. Host readiness
checks use the same target. Manual triggering does not start a stopped app:
deployment starts it automatically, or an operator can start it before invoking.
Read-only status checks never start the app.

An intentional new full baseline uses `invoke function --confirm --full`.
The menu's full operation requires `FULL` confirmation.

There is one Durable collection instance. An active run keeps its original
scope; retrying a failed run within its six-hour budget reuses its run ID, timestamp, frozen policy,
baseline, and verified checkpoints. A full request does not change an already
active or failing run into a new full collection.

The next manual or scheduled trigger starts a fresh snapshot after a timed-out
run, or after a failed run's original deadline expires. Expired checkpoints remain
retained but are not repeatedly resumed. As a fallback, a trigger finding an
expired run still marked active requests termination and starts no overlapping
replacement in that trigger; confirm termination before invoking again.

Permission/configuration failures need correction before retry. Runtime state
and retained checkpoints are not purged as a recovery shortcut. The
[recovery reference](../infra/README.md#resumable-collection-deployment-and-recovery)
explains stage boundaries and failed execution replacement.

### Stopping an obsolete run before deployment

Redeployment is not cancellation: Durable state survives host restarts. Stop the
exact run before deploying collection-logic changes:

```bash
python -m vulnerability_view.operations_cli stop-collection --run-id live-20261103T050000Z --confirm
python -m vulnerability_view.operations_cli deploy function
python -m vulnerability_view.operations_cli verify function
python -m vulnerability_view.operations_cli invoke function --confirm
python -m vulnerability_view.operations_cli check-runs --watch
```

Replace the example run ID with the authoritative active run ID. The stop
command checks that identity, requests Durable termination, verifies the
`Terminated` state, then stops the Function host so an already executing activity
cannot keep running. Termination alone does not interrupt an executing activity.
This uses the existing Durable management endpoint and also works before the
updated Function package is deployed. If verification fails, the command reports
an error rather than claiming the collector stopped.

The command never deletes Storage history, purges Durable history, or changes the
current manifest. It requires Azure CLI access to the configured customer tenant
and Function management keys. The Function remains stopped until deployment or
an explicit host start; the deployment command starts it again. The dashboard
continues serving the last completed publication. An activity already publishing
when the stop begins may finish before host shutdown; stop is not a rollback.

Deployment-menu Operations options 14 and 15 provide stop and console watch.
After termination, a new collection freezes the latest published baseline rather
than recovering the old run. A worker rejects a baseline superseded by another
complete publication before beginning more collection or processing.
If an obsolete run has already failed, use
`invoke function --confirm --fresh` after deployment to create a new run from the
latest publication instead of recovering its frozen baseline. This explicit
option refuses to replace an active run and retains the failed run's evidence.

### Nightly collection with scale-set exclusion

With `EXCLUDE_SCALE_SETS=true`, all new live runs use device-scoped snapshots,
including requests made with `auto` or `delta`. Inventory is collected first,
recognized scale-set devices are removed, and findings are requested only for
the remaining devices. The tenant-wide vulnerability delta endpoint is not
called. The architecture, schedule, current-pointer publication, and supporting
inventory/aggregate endpoints are unchanged. Metadata recognition still depends
on Azure resource IDs, not device names; this is not a promise to avoid all
tenant-wide inventory or aggregate API traffic.

Each included device/page has immutable continuation metadata. On interruption,
completed devices and pages are skipped without parsing their saved response
bodies; after all included devices finish, raw pages are restored with integrity
checks for catalog enrichment and processing. The existing per-device paging,
machine-ID response validation, request pacing, and required-endpoint failure
handling remain in force. A failed findings request prevents publication.

Snapshots are compared with the previous publication. A confirmed absent finding
is described as **resolved between runs**, not as having an exact patch timestamp.
The existing two-qualified-snapshot confirmation, 48-hour device freshness,
missing/stale/offboarded-device classification, and wholesale-disappearance
corroboration protections are unchanged. Intermediate changes between snapshots
are not reconstructed. Prior scale-set findings are removed from scope before
reconciliation, not credited as remediation.

The flag is frozen in a run's plan. Stop an old active run before deployment,
then start a fresh run to use updated settings. An old immutable run with
scale-set exclusion and a frozen delta input fails explicitly rather than
silently switching the meaning of its saved evidence.

### Nightly collection without scale-set exclusion

With `EXCLUDE_SCALE_SETS=false`, the automatic full/delta policy is unchanged. With a valid baseline,
nightly deltas request 50,000 rows per page independently of the 1-2,500 full
findings page setting. Delta HTTP requests are paced at least four seconds apart
within an activity (below the documented 30/minute and 1,000/hour limits), and
server retry delays remain authoritative.

Each completed delta page and its continuation metadata are append-only. A
retry lists compact checkpoint metadata and resumes at the next page, instead
of parsing and archiving all previous responses again. Completed page bodies
are restored with integrity checks when the endpoint download finishes. Processing
still applies the complete delta to the frozen baseline; no rows are truncated
to meet a deadline. Old request-only checkpoints remain retained; the new
continuation journal does not rewrite an old run's immutable plan.

The `downloadedRows`/`downloadedBytes` counters describe new HTTP work in the
latest activity (decoded response-body bytes, not measured wire traffic), not
the entire delta or compressed Storage size. The endpoint
progress reports cumulative rows. Defender's six-hour reporting buckets can
overlap successive delta windows; repeated changes are applied by finding
identity and event order.

`PartialSuccess` can mean missing CVE enrichment or optional supporting data.
It does not mean findings were silently dropped. Endpoint details and
`CveMetadataStatus` identify the gaps. A failed required finding call or corrupt
evidence still blocks publication.

## Application updates

The deployment menu keeps Function and Web App updates separate:

| Menu choice | Operation |
|---|---|
| 2 | Review/apply cumulative Web App infrastructure |
| 3 | Deploy and verify Function code |
| 4 | Deploy and verify Web App code |
| 5 | Request a collection after active-run checks |
| 6 | Verify both applications |
| 7 | Operations and diagnostics |

Equivalent code-only commands:

```bash
python -m vulnerability_view.operations_cli deploy function
python -m vulnerability_view.operations_cli verify function
python -m vulnerability_view.operations_cli deploy webapp
python -m vulnerability_view.operations_cli verify webapp
```

Only the affected package needs deployment. Publishing dashboard code does
not collect new data or restart the collector. Function deployment does not
start collection; collector updates are made with its active workflow in mind.

Infrastructure changes use a saved, reviewed plan for the highest deployed
cumulative stage. After the Web App exists, that stage is `webapp`. A code-only
update does not need Terraform.

## Dashboard startup and cache

The shell can load while the server restores or builds its data indexes.
The startup notice identifies first load, a restart, or a new snapshot as
possible reasons. It retains actual stage information, elapsed time, and an
expandable index checklist.

| Check | Meaning |
|---|---|
| `GET /api/health` | Process liveness; `dashboardReady` distinguishes data readiness |
| `GET /api/dashboard/snapshot` | HTTP 202 during initial preparation; HTTP 200 for a ready snapshot |
| `GET /api/dashboard/status` | Preparation stage, rows/bytes, timings, errors, and retry state |
| `GET /api/diagnostics` | Snapshot/cache sizes, active work, preparation, and bounded request timings |
| `GET /api/status` | Published-source metadata and availability |

Only `/api/health` permits anonymous dashboard API access. The other endpoints
require normal hosted authentication.

The configured persistent viewer cache restores compatible completed artifacts
after a restart. Missing compatible entries are built; corrupt entries and
storage failures are explicit errors. Without persistent caching, additional
history/search/report work stays on demand after shared preparation.

The current ready snapshot remains served while a replacement is prepared.
An open browser keeps its `snapshotId` until reload. A newer Storage pointer
does not prove every viewer has switched to that run.

Each worker has its own disposable local cache, capped at two snapshots and
8 GiB, with additional temporary disk requirements. More workers multiply this
work. Cache eviction never deletes retained Azure evidence.
The [runtime reference](application-flow.md#7-web-app-startup-indexing-memory-and-caches)
contains the limits and request sequence.

## Logs

Operations submenu **12** exports the latest snapshot; **13** reads Web App
startup logs; **14** returns to the deployment menu.

```bash
python -m vulnerability_view.operations_cli check-webapp-startup-logs
python -m vulnerability_view.operations_cli check-function-logs --days 2 --limit 25
python -m vulnerability_view.operations_cli export-function-logs --days 2
```

The startup-log command reads the latest retained Linux container log, preferring
failures on the latest date. It does not restart the app or change logging.
It requires Azure CLI support for `az webapp log startup show`. An older failure
is not proof of a current outage; timestamps matter.

### Reading application startup progress

`[dashboard-startup]` lines include stage starts, completions, failures, and
timings. Heartbeats report active stage, rows/bytes, and available process or
resource readings. High CPU during index work is not proof of a hang; low CPU
and unchanged rows can indicate a wait, not its cause.
Unavailable counters are reported as unavailable. An abruptly killed process
cannot log its own termination; platform logs and metrics supply that evidence.

Collection traces identify request progress, processing stages, and publication.
`[processing]` heartbeats establish a live worker, not necessarily advancing
rows or a successful publication.

Sanitized collector export and unredacted platform/startup logs are different
outputs. Diagnostic files still need review under the organization's data
policy before sharing.

## Export the latest published snapshot for analysis

```bash
python -m vulnerability_view.operations_cli export-latest-snapshot
```

The signed-in operator needs Blob Data Reader access to the history and pointer
containers plus network access. Management-plane Reader alone does not grant
blob reads.

The exporter reads the current manifest once, fixes the export to that run,
downloads its referenced raw/curated/policy/index files, and verifies compressed
size and SHA-256. A successful ZIP and summary are written under a unique
`output/snapshots/` directory. A failed partial ZIP is removed.
Azure files and the current pointer are never changed.

The export is the latest **published** run, not an in-progress collection or
necessarily the run still selected by an open dashboard. It excludes unlisted
checkpoints, other runs, live workflow state, and Web App timing diagnostics.
Hashes prove file integrity, not calculation accuracy or performance.

The ZIP contains sensitive, unredacted device and vulnerability data. It is not
an appropriate public issue attachment.

## Access and identities

The collector identity reads Defender, Graph, and configured Azure inventory
and publishes retained runs. The dashboard identity reads that evidence.
Workflow/branding and persistent viewer-cache writes have separate container
scopes; the dashboard does not get write access to retained run evidence.

Entra application assignments are managed outside Terraform:

| Role | Current purpose |
|---|---|
| Dashboard Viewer | Open the dashboard and protected APIs |
| Data Evidence Reader | Use the optional read-only curated evidence browser |
| Dashboard Administrator | Upload organization branding when enabled |
| Recommendation Tracker | Retained compatibility role; enabled shared tracking currently permits authenticated dashboard users |

Assignment-required sign-in and the application's principal checks are separate
controls. The hosted app does not use a workstation's Azure CLI session.
Hosted client-secret collection is rejected; the explicit local-only bridge
and its permissions are in the [configuration reference](configuration-reference.md).

Easy Auth's application credential has a two-year lifetime with an annual
Terraform rotation trigger. Renewal is part of the deployment maintenance
process, not an in-app update.

## Shared recommendation status and branding

Tracking is optional and separate from Defender. Append-only workflow events
record who changed a recommendation and when. A user-marked fix remains
awaiting collection until a newer run supports it; it does not itself close
findings or change SLA evidence. The latest status is shared, not a lock or
exclusive assignment. [LOGIC.md](../LOGIC.md#8-shared-recommendation-work-tracking)
defines effective states, confirmation, and reassignment.

Branding uploads are role-restricted PNG files, up to 2 MB and 4096 pixels per
dimension. New versions are retained under the workflow container's
`branding/logos/` path. Previous versions are not deleted.

Hosted settings are maintained through Terraform values so a later apply
does not undo a one-off portal/CLI change. Presentation and default filters are
in `dashboard/config.js`; their definitions belong in the
[configuration reference](configuration-reference.md#8-dashboard-presentation).

## Operational handoff

The environment record needs the installed versions, latest completed run,
any active/failed workflow, approved policy, schedule, access owners, monitoring
contacts, and protected state/configuration backups. These are not supplied
by a repository clone.

Application replacement, local cleanup, or a request to start over does not
authorize deleting Azure history. The [data reference](data/README.md)
defines the retained-data boundary.
