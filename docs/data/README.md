# Data structure and retention

This reference defines the stored evidence, dataset fields, and lineage.
[Application flow](../application-flow.md) covers API calls and processing;
[LOGIC.md](../../LOGIC.md) covers lifecycle, priority, and SLA calculations.

## Durable retention requirement

Retained vulnerability history belongs in Azure Storage, not a Function or
Web App's temporary filesystem. Local bundles support development and replay
but do not provide hosted retention.

### No-delete rule

Retained `raw/`, `curated/`, and `runs/` paths are append-only and use
`overwrite=False`. Application code does not delete historical evidence or
configure lifecycle deletion. A reset, rebuild, cleanup, redeployment, or
request to start over does not authorize removal.

The history storage account survives application replacement. Within run
publication, only `current/manifest.json` in the separate pointer container is
replaceable. Any destructive exception requires explicit human approval naming
the operation and exact target.

Terraform's default history protection is an unlocked 365-day WORM policy and
30-day blob/container soft delete. Environment inputs determine the actual
values. WORM prevents eligible changes/deletion during its protection period;
soft delete supplies a recovery window after an eligible deletion. Neither
policy automatically deletes active history at the end of WORM retention.
Locking the WORM policy is an explicit irreversible choice.

## Three forms of data

| Form | Hosted purpose | Local equivalent |
|---|---|---|
| Raw response pages | Original source evidence and replay | `output/raw/<run-id>/` |
| Curated run bundle | Normalized snapshot, event history, policy, and manifest | `output/history/<run-id>/` |
| Presentation exports | Local development and compatibility tools, not hosted evidence storage | `dashboard/data/` JSON and `output/curated/` CSV |

Hosted dashboards query verified SQLite indexes. They do not read raw pages
or require a complete findings JSON download into each browser.
Published indexes and persistent viewer caches are additional derived data,
not replacements for retained source evidence.

## Required ADLS layout

Two containers separate immutable evidence from the current pointer:

```text
dvm-history:
  raw/YYYY/MM/DD/<run-id>/*.json.gz
  curated/YYYY/MM/DD/<run-id>/*.json.gz
  runs/YYYY/MM/DD/<run-id>/sla-policies.json
  runs/YYYY/MM/DD/<run-id>/index/dashboard-primary.sqlite3.gz
  runs/YYYY/MM/DD/<run-id>/index/dashboard-history.sqlite3.gz
  runs/YYYY/MM/DD/<run-id>/manifest.json

dvm-current:
  current/manifest.json
```

Container names are configurable. Existing retained containers with older names
remain valid when explicitly configured; a naming change does not authorize
deleting or replacing them.

Hosted collection also retains per-run plans, response checkpoints, and
processing continuations on immutable run paths. Durable task-hub tables,
queues, and leases use the **separate Function runtime account**.
Worker `/tmp` files are disposable caches, not the only copy of completed work.

Optional shared workflow/branding uses a separate `dvm-workflow` container.
Terraform also enables `dvm-viewer-cache` for compatible completed reporting
artifacts. Viewer cache writes do not modify evidence or the current pointer.
The [runtime reference](../application-flow.md#7-web-app-startup-indexing-memory-and-caches)
explains cache compatibility and limits.

### Run manifest

The completed manifest records run/snapshot identity, completeness, schema and
normalization versions, policy version, endpoint results, file paths, dataset
row counts, sizes, and SHA-256 checksums. Published query indexes also carry
format and evidence identity.

Files are uploaded and verified before the current pointer advances. Publication
checks the expected prior pointer ETag. Immutable collisions, corrupt evidence,
and concurrent pointer changes fail explicitly; incomplete output is not
selected as a successful snapshot.

## Live data sources

Required Defender data establishes the finding baseline. Secure Score and
Azure subscription inventory are supporting sources. Optional experimental
remediation-task data is separate from finding-remediation evidence.

The [API table](../application-flow.md#3-exactly-what-the-collection-job-calls)
defines endpoint scope, full/delta behavior, and enrichment. Successful hosted
responses are checkpointed before transformation. Missing CVE enrichment can
produce a warning without losing the underlying finding; malformed evidence
and failed required finding calls do not.

## Daily retained data

Every successful run has its own immutable raw/curated paths and manifest.
The current pointer selects one completed run. It is not a roll-up that adds
the same finding again for every scan.

Local presentation exports are different: publication rewrites the configured
JSON and CSV filenames. Empty or unavailable datasets clear those local files
rather than leaving an older dataset in place. Hosted Function processing can
skip these uncompressed local exports after durable publication.

## Replay behavior

Replay reads archived responses through current normalization and lifecycle
logic. Delta archives include reconstructed finding/CVE state so they can be
replayed without asking Defender to reproduce an older response.

Replay can change calculated output when application logic has changed; it
does not rewrite the original retained evidence. Local-only replay does not
call Azure or Defender. Publication/backfill commands have separate write
behavior and are not ordinary read-only inspection tools.

## Shared recommendation workflow events

Each user action appends a JSON event with `overwrite=False`:

```text
events/<recommendation-id-sha256>/YYYY/MM/DD/<timestamp>-<uuid>.json
```

Events retain `RecommendationId`, `UserStatus`, `MarkedAtRunId`,
`MarkedAtSnapshotUtc`, `UpdatedUtc`, `UpdatedByObjectId`, and
`UpdatedByDisplayName`. The authenticated identity comes from Easy Auth, not
browser-supplied actor fields. `Clear` hides prior display state without
deleting its history.

User-marked fixes await newer collection evidence. Status is shared
coordination, not a Defender assignment, lock, finding transition, or SLA input.
The [work-status rules](../../LOGIC.md#8-shared-recommendation-work-tracking)
define confirmation and reassignment.

Disabling tracking hides its controls/API, not its retained container or events.
Branding versions are also append-only, under `branding/logos/`.

## Published datasets

Applicable records carry these lineage fields:

| Field | Meaning |
|---|---|
| `DataOrigin` | `Live` or `Synthetic` |
| `ScenarioId` | Synthetic scenario or live snapshot family |
| `SnapshotTimeUtc` | Observation time represented by the record |
| `CollectionRunId` | Run that produced the record |

### Findings

One row represents a device/CVE/software-product/version relationship.
The same CVE on many devices or affected products can produce many instances.

#### Identity and device

| Field | Meaning |
|---|---|
| `FindingKey` | Defender row ID, or deterministic fallback hash |
| `DeviceId`, `DeviceName` | Machine identity and display name |
| `OSPlatform`, `OSVersion` | Operating system |
| `LastSeenUtc` | Machine inventory last-seen time |

#### Software and vulnerability

| Field | Meaning |
|---|---|
| `SoftwareVendor`, `SoftwareName`, `SoftwareVersion` | Affected software |
| `CveId` | CVE identifier |
| `Severity`, `CvssScore` | Severity and available CVSS value |
| `CveMetadataStatus` | Whether referenced CVE details were available |
| `ExploitabilityLevel` | Known/no-known exploit classification, or unknown metadata |
| `PublicExploitAvailable` | Public exploit evidence; null if unavailable |
| `VerifiedExploitAvailable` | Defender-verified exploit evidence; null if unavailable |
| `ExploitKitAvailable` | Exploit-kit evidence; null if unavailable |

Unknown metadata is not evidence of no exploit or a zero CVSS score.

#### Recommendation and update

| Field | Meaning |
|---|---|
| `RecommendationId`, `RecommendationName` | Linked Defender recommendation |
| `SecurityUpdateAvailable` | A fixing KB or related recommendation is available |
| `RecommendedSecurityUpdate` | Fixing KB or recommended version |

#### Asset context

| Field | Meaning |
|---|---|
| `AssetClass` | `AzureCloud`, `TraditionalIT`, or `Unknown` |
| `AzureResourceId`, `SubscriptionId` | Available Azure ownership metadata |
| `OwnerTeam` | Derived operating queue |
| `ClassificationReason` | Evidence used for asset classification |
| `AssetCriticality` | Priority-score input |
| `InternetFacing` | Recommendation tag evidence |
| `DeviceRiskScore`, `DeviceExposureLevel` | Defender device context |

#### Lifecycle

| Field | Meaning |
|---|---|
| `FirstSeenUtc` | Source vulnerability metadata, not the collector-owned SLA start |
| `FirstObservedUtc`, `LastObservedUtc` | First/latest collector observation |
| `FindingStatus` | `Open`, `PendingConfirmation`, `PendingVerification`, `Fixed`, `Reopened`, `DetectionReturned`, `StaleDevice`, `OutOfScope`, or `Unknown` |
| `FirstAbsentUtc`, `ConsecutiveAbsentCount` | Qualified absence evidence |
| `EffectiveRemediationUtc` | First qualified absence used for SLA; blank when insufficient or revoked |
| `ConfirmationRunsCompleted`, `ConfirmationRunsRequired` | Confirmation progress |
| `FixedUtc`, `FixedConfirmedUtc` | Effective remediation time and later confirmation time |
| `VerificationFailedUtc` | Return before confirmation |
| `SlaEvidenceStatus` | Evidence qualifier for the reported SLA result |
| `ReopenedUtc` | Latest reappearance after confirmed fixed |
| `LifecycleReason` | Explanation of the current status |

#### SLA and priority

| Field | Meaning |
|---|---|
| `SlaPolicyName`, `SlaDays` | Selected policy and allowance |
| `SlaPolicyVersion`, `SlaStartUtc` | Policy version and collector-owned start |
| `SlaDueUtc` | Calculated due time |
| `SlaStatus` | Within/outside-SLA or unknown result |
| `PriorityScore` | Application score, 0 through 100 |
| `PriorityExplanation` | Components of that score |

`PendingConfirmation` means a fix was observed at its first qualified absence,
not that remediation is confirmed. Its `EffectiveRemediationUtc` supports daily
progress, while `SlaStatus` remains open and the row is excluded from completed
SLA outcomes. A second consecutive qualified absence confirms it by default;
the first absence remains the effective clearance date. An interruption in
qualified observations restarts the absence sequence. Older retained rows with
provisional fixed-SLA labels are not treated as completed merely because of
that label.

#### Assignment placeholders

Live normalization leaves `AssignedTeam`, `AssignedEngineer`, and
`ExternalTicketId` empty and uses `AssignmentStatus=NotAssigned`.
Synthetic data can populate them for demonstrations. These fields are not
the shared recommendation workflow store.

### Finding events

`finding-events.json.gz` carries the retained transition ledger into each new
run. Events include New, PendingConfirmation, PendingVerification, Fixed,
Reopened, DetectionReturned, StaleDevice, OutOfScope, Unknown, and Open.

An event records prior/new state, finding/device/CVE/recommendation identity,
ownership, policy/SLA result, reason, time, and lineage.
New finding events also retain `OSPlatform` and `OSVersion` from the finding
when the collector records the transition. These describe the observation,
not necessarily the earlier effective-remediation instant. Existing event
records are preserved unchanged; older events may lack these optional fields.
Historical OS breakdowns identify **Event observation** versus fallback
**Snapshot attribution**. Recommendation events are tenant-level and can span
multiple operating systems; their OS groups use matching snapshot findings,
not a single OS assigned to the recommendation.
`EventTimeUtc` is when the collector learned the transition.
`EffectiveTimeUtc` is when it counts for reporting; a confirmed fix can be
learned later than its first qualified absence.

The ledger preserves repeated fix/reopen cycles even though the current
finding row has only one latest timestamp for each field.

### Recommendation events and run history

`recommendation-events.json.gz` retains baseline, activation, inactivity,
and reopening events. `run-history.json.gz` carries compact run-level metrics
for findings, CVEs, devices, recommendations, movement, and SLA.
These are separate from current recommendation inventory and per-endpoint status.

### Devices and vulnerabilities

`devices.json.gz` retains normalized device inventory, including devices with
no current finding. Discovery without assessment is not proof of zero
vulnerabilities.

`vulnerabilities.json.gz` retains referenced CVE detail. Unavailable details are
identified explicitly; finding evidence remains present.

### Recommendations

Current recommendation records contain:

- Identity and product: `RecommendationId`, `RecommendationName`, `ProductName`,
  `Vendor`, `RecommendedVersion`.
- Classification: `Category`, `SubCategory`, `RemediationType`, `RelatedComponent`.
- Scope and risk: `ExposedMachinesCount`, `TotalMachineCount`, `SeverityScore`,
  `PublicExploitAvailable`, `ActiveAlert`, `HasUnpatchableCve`.
- Impact/context: `ExposureImpact`, `ConfigScoreImpact`, `AssociatedThreats`,
  `Weaknesses`, `Tags`.
- Optional task evidence: `RemediationTriggered`, task ID, status, priority,
  target count, and fixed count.

The inventory is current state. Recommendation events retain its transitions.
The [filtering limitation](../../LOGIC.md#2-finding-identity-and-scope) explains
why some end-of-support uninstall guidance is excluded by Vulnerability-only scope.

### Recommendation machines

Each row connects a recommendation and device with device name/OS/group,
exposure, last seen, asset class, Azure ownership, classification reason, and
lineage. Relationships can be derived from findings or collected from the API.
This is a current-snapshot dataset.

### Remediation activities

Optional task rows contain task/recommendation identity, status, priority,
created/due times, target/fixed counts, progress, requester/completer,
completion method, last modification, device groups, and lineage.
Task completion does not by itself make a finding fixed.

### Daily summary

Derived daily rows group by date, asset class, subscription, owner, severity,
and origin. Measures include movement, backlog, exploit context, pending
evidence, SLA outcomes, assignment states, and median time to fix.
The default window is 90 days through the latest represented snapshot.
These are calculated results, not raw daily Defender observations.

### Collection runs

Per-endpoint rows record run/snapshot time, endpoint, status, counts, duration,
error, and lineage. They describe the current collection, not every historical
invocation. Run manifests and run-history data provide the retained context.

### Reconciliation

Monthly severity control totals compare previous, new, fixed, reopened, and
remaining findings:

```text
CurrentRemaining = PreviousRemaining + New - Fixed + Reopened
```

Direct live processing builds live reconciliation. Combined sample builds
retain their synthetic reconciliation population. Empty local exports are
cleared rather than preserving an old file.

### Secure Score and subscriptions

Secure Score contains the latest Graph score, maximum/percentage, user counts,
services, category scores, tenant comparison, and lineage. `$top=1` is one
current observation, not a collected score time series.

Subscriptions describe configured management-group descendants, or subscriptions
visible to the collector when no group is configured. Zero-finding subscriptions
can still appear as inventory; visibility is not proof of vulnerability coverage.

## Finding identity

`FindingKey` uses the source machine-vulnerability ID when supplied. Otherwise:

```text
SHA-256(machineId | cveId | productName | productVersion)
```

A version change can close one identity and create another. Duplicate published
finding keys fail validation. A CVE appearing on different devices is not a
duplicate finding.

## Lifecycle state determination

Current detection, qualified absence, whole-device disappearance, stale/missing
inventory, return before confirmation, and reopening are different states.
A missing finding alone does not establish a fix.

[LOGIC.md](../../LOGIC.md#6-finding-completion-and-reopening) contains the rules,
and the [daily workflow examples](../daily-vulnerability-remediation-workflow.md#simple-sla-lifecycle-examples)
show how effective time and later confirmation differ.

## SLA tracking

The policy retained with a run defines that run's targets. The collector-owned
`FirstObservedUtc` supplies the normal live SLA start. First qualified absence
can establish an effective outcome while confirmation remains pending.

Current finding rows retain latest timestamps; event history preserves repeated
transitions. Historical reports use the available evidence, not an assertion
that every day was independently observed.
The [SLA rules](../../LOGIC.md#5-sla-targeting) define policy precedence and dates.
The checked-in thresholds remain examples until adopted.

## Command-specific overwrite behavior

| Command/path | Behavior |
|---|---|
| `collect-live` | Live collection/replay and lifecycle reconciliation; a new run bundle and current local exports unless explicitly skipped |
| `build-sample --mode synthetic` | Deterministic local scenarios using retained live CVE references; no live API collection |
| `build-sample --mode live` | Attempts live output; can retain synthetic output with a recorded warning if live collection is absent/fails |
| `build-sample --mode combined` | Separate labeled synthetic and live populations; synthetic reconciliation is retained |
| Hosted scheduled collection in combined mode | Carries seeded synthetic rows forward; does not generate them |
| Local presentation publication | Rewrites configured JSON/CSV files, including clearing empty datasets |

Sample-build fallback is demonstration behavior, not evidence that a live
collection succeeded. `DataOrigin` and the run summary identify the result.
The strict live collector is the appropriate source of live publication status.

## History maintenance commands

The [command reference](../command-reference.md) defines replay/backfill,
verification, and restore options. The [development guide](../development.md#query-index-maintenance)
covers index-only revisions without recollection.

Backfill can create new immutable bundles and advance the pointer; it is not
a read-only schema inspection. `restore-current` verifies the selected Azure
run and recreates local presentation files, without rewriting that evidence.

## Code map

Models are defined in [models.py](../../src/vulnerability_view/models.py).
Collection, query, storage, and browser responsibilities are mapped in the
[runtime source map](../application-flow.md#source-of-truth-implementation).
