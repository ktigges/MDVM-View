# Dashboard and collection logic

This document defines the implemented calculation rules. Configuration files
and source code determine the values used by a particular deployment.

For the straight-through runtime sequence—including exact API calls, raw and
curated files, compression, weekly full behavior, dashboard startup, caching,
and lazy CVE detail—start with
[Application flow](docs/application-flow.md). This document focuses on how the
application calculates and interprets results after the source data is
available.

## 1. Data runs and publication

Each successful collector execution creates a new immutable run. It does not
replace an earlier run.

1. Source API pages are retained under the new run path.
2. Normalized datasets, lifecycle results, summaries, and the SLA policy are
   written under that same immutable run.
3. The run manifest is completed only after all required output is durable.
4. `current/manifest.json` is replaced last so readers see either the prior
   complete run or the new complete run.

Paths under `raw/`, `curated/`, and `runs/` are append-only. Application code
does not delete retained DVM history. Local `output/` cleanup has no effect on
Azure history.

Publishing Web App code does not run the collector and does not change the
current dataset. Publishing Function code also does not run a collection unless
the Function is subsequently invoked or its timer fires.

For live-only collection, lifecycle reconciliation reads only prior findings
and finding events from the current immutable run. It does not load unrelated
prior datasets such as the vulnerability catalog. Large vulnerability and
machine-finding API pages are written to the immutable raw spool without also
being retained as endpoint-sized Python lists. Normalization scans those pages
in collection order and retains the same normalized row order and duplicate-CVE
replacement behavior. Azure Function runs also skip redundant uncompressed
dashboard exports after the verified bundle has been uploaded. Combined mode
still reads all current datasets because it must carry every labeled synthetic
dataset forward. These memory optimizations do not change the published schema,
manifest contents, lifecycle results, SLA results, or dashboard behavior.

## 2. Vulnerability identity, evidence identity, and scope

A vulnerability is one machine vulnerable to one CVE, regardless of software
products or versions. Dashboard totals count distinct CVEs and distinct
machines separately. Software-record totals and machine/CVE relationship totals
are not dashboard headline metrics.

An internal finding records the device, CVE, product, and version evidence
needed for reconciliation. `FindingKey` uses the Defender machine-vulnerability row ID when
available. Otherwise it is the SHA-256 hash of:

```text
machineId | cveId | productName | productVersion
```

A product-version change can therefore close one key and open another.

The same CVE on 100 machines is one distinct CVE and 100 affected machines.
Several software records for that CVE on one machine do not add vulnerabilities.
Dashboard totals use the selected snapshot and filters, not repeated scans.

The dashboard separates current detections from evidence confirmation.
`Open`, `Reopened`, and `DetectionReturned` are current detections.
`PendingConfirmation` and `PendingVerification` remain visible as pending
evidence but can be hidden or isolated with the Exposure status filter.
Confirmed fixed evidence remains available in SLA and lifecycle reporting.

The default recommendation-type filter is Vulnerability. Its current
classifier recognizes update/security-update remediation or vulnerability wording;
some end-of-support uninstall recommendations fall into Misconfiguration instead.
Their linked findings can be excluded from this default scope even though
Defender supplied vulnerability evidence. This is a known classification
limitation, not a lifecycle or retention rule.

## 3. Asset classification and operating queue

Rules are evaluated in this order:

1. Azure resource metadata, a subscription ID, or a recognized cloud tag
   (`azure`, `azurecloud`, or `cloud-owned`) produces `AssetClass=AzureCloud`
   and the derived queue `Cloud Operations`.
2. Other records with machine metadata produce `AssetClass=TraditionalIT`.
3. Traditional Windows machines use `Endpoint Operations`; other traditional
   platforms use `Server Operations`.
4. Missing machine evidence produces `AssetClass=Unknown` and `Unassigned`.

The operating queue is inferred from evidence. It is not a Defender assignment
and does not identify the person working an item.

## 4. Finding priority

`PriorityScore` is a dashboard score, not a native Defender score. It is capped
at 100 and is the sum of:

| Signal | Points |
|---|---:|
| Critical / High / Medium / Low severity | 40 / 30 / 18 / 8 |
| CVSS | CVSS multiplied by 2 |
| Verified exploit | 18 |
| Public exploit when not verified | 12 |
| Internet facing | 12 |
| High / Medium / Low device exposure | 8 / 4 / 1 |
| Critical / High / Standard asset criticality | 10 / 6 / 2 |

`PriorityExplanation` retains the component calculation.

All recommendation-oriented dashboard surfaces use the same primary order:
effective severity, Defender recommendation `SeverityScore`, `ExposureImpact`,
current open impact, `ConfigScoreImpact`, then recommendation name. Effective
severity is the higher of the Defender recommendation score band and the
highest linked open finding severity in the current filtered scope. This
includes executive impact, recommendation inventory, priority workbench,
remediation outcomes, SLA recommendation lists, related recommendations, and
recommendation-detail navigation. Remediation outcome tables then use
new/reopened and confirmed-fix
counts as additional ties. Remediation task tables place active tasks before
completed tasks, then order by task priority, overdue state, earliest task due
date, and most recently modified.

The optional **Hide non-reporting devices** filter compares `LastSeenUtc` with
the latest `SnapshotTimeUtc` in the loaded dataset. Supported windows are 7,
14, 30, 60, and 90 days. Missing or invalid last-seen values are considered
non-reporting while the filter is enabled. The filter is off by default and
changes presentation scope only: retained raw, curated, and historical
evidence is never removed. Findings, recommendations, remediation scope,
asset inventory, SLA calculations, trends, and detail views use the same
reporting-age scope.

The **Assets** view starts from the normalized `devices` dataset rather than
deriving inventory from vulnerability findings. Active Azure/Cloud and
traditional devices therefore remain visible even when they have no current
finding rows. Distinct CVE counts are joined onto the inventory, and configured
scale-out workloads remain grouped. Onboarded assets are shown by default.
The optional **Include discovered-only assets** control adds non-onboarded
inventory records, which display `Not assessed` instead of a zero vulnerability
count because passive discovery does not establish complete CVE coverage. If
Defender supplies a device-CVE relationship for a non-onboarded asset, the
dashboard displays the finding and labels its coverage `Limited evidence`.

## 5. SLA targeting

The source of truth is `config/sla-policies.json`. The checked-in policy
currently contains:

| Policy | Match | SLA days |
|---|---|---:|
| CriticalKnownExploit | Critical with known-exploit evidence | 4 |
| Critical | Critical | 2 |
| High | High | 7 |
| Medium | Medium | 30 |
| Low | Low | 60 |

An exploit-specific match takes precedence over general severity policies.
Within the selected group, the shortest matching SLA is used. These are sample
configuration values until adopted as operating policy.

For live data, the SLA starts when Defender first saw the vulnerability on the
device. When Defender supplies its per-device `firstSeenTimestamp` (delta change
rows), that time is the start; otherwise the start is the first collection that
observed the finding:

```text
SlaStartUtc = Defender firstSeenTimestamp, else FirstObservedUtc
SlaDueUtc   = SlaStartUtc + SlaDays
FirstSeenUtc = SlaStartUtc   (a device-level time, not the CVE's tenant-wide first detection)
```

Defender timestamps without an offset are UTC. This is a calculated SLA target,
not a manually assigned remediation-task due date. Existing findings preserve
their policy name, policy version, and duration across later runs. When
Defender later supplies a first-seen time for an open finding, its start moves
to that time and its target is recalculated with the retained duration.

Possible finding SLA states are:

- `OpenWithinSla`
- `OpenOutsideSla`
- `FixedWithinSla`
- `FixedOutsideSla`
- `Unknown`

`Unknown` means the application lacks a reliable first-observed time or a
matching policy. Defender remediation task `DueOnUtc` is separate and is used
only in task-specific due-date reporting.

## 6. Finding completion and reopening

The collector matches current and prior findings by identity — device, CVE,
software, and software version — not by the API row ID, which differs between
full and delta collections. A matched finding keeps its existing `FindingKey`.
Every finding row is either `Open` or `Fixed`.

| Observation | Result |
|---|---|
| Present in both snapshots | `Open`; keep the first observation and SLA clock |
| Previously fixed finding appears again | A new episode: the fixed row is retained, and a new `Open` row (key suffix `#e2`, `#e3`, …) starts a new SLA clock and sets `ReopenedUtc` |
| Defender delta reports the finding `Fixed` | `Fixed`; `FixedUtc` is Defender's `eventTimestamp` (accurate to about six hours), even if the device has since gone inactive |
| First qualified absence | `Fixed`; `FixedUtc` is that collection's snapshot time |
| Inventory or vulnerability collection is incomplete | `Open`; no fix credit for newly absent evidence |
| Device inactive (not active, or not seen within 7 days), offboarded, unsupported, or missing from inventory | `Open` with a lifecycle reason; no fix credit. The dashboard flags the device as inactive |

An absence is qualified only when inventory and vulnerability collection both
succeeded, the device remains active, and its last-seen time is within the
configured freshness window (`deviceFreshnessHours`, 168 hours = 7 days). The
default required absence count is one: there is no extra confirmation run. A
Defender task being completed does not by itself mark evidence fixed. Without a
Defender fix event, the timestamp establishes clearance observed between
collections, not an exact patch-installation time.

In delta collections, only findings Defender still reported in the previous run
are carried forward; a finding whose absence was already recorded is not
re-asserted as detected, because Defender sends its Fixed event only once.

Rows written by earlier versions are read with these rules: `Reopened`,
`DetectionReturned`, `PendingConfirmation`, `PendingVerification`,
`StaleDevice`, `OutOfScope`, and `Unknown` are all unresolved. Duplicate
unresolved rows for one identity (left by earlier key changes) merge into the
earliest, and a `Fixed` row whose fix time equals another row's first
observation — a key change, not a real fix — merges back so the original SLA
clock is kept. Retained historical runs are never rewritten.

A machine/CVE is fixed only when all its software evidence is gone. A CVE still
detected through another product/version on the same machine remains open.
Across the dashboard, a distinct CVE is fully cleared only when no machine
in scope remains vulnerable. Software evidence removals do not multiply either
the distinct-CVE or distinct-machine totals.

An explicitly configured `fixedConfirmationRuns` greater than one keeps the
finding `Open` until that many consecutive qualified absences, then records it
`Fixed` at the first absence. Retained snapshots keep their original policy and
are not rewritten; missing, inactive, or incomplete evidence never becomes a
fix merely through a configuration change.

A run is `PartialSuccess` only when a required source failed or a source
returned incomplete data. An unavailable optional source (Secure Score, Azure
subscription inventory) is reported as an optional note and leaves the run
`Success`.

## 7. Remediation outcome

Recommendation remediation outcomes are derived from finding evidence:

- `BeforeLatestRefresh = CurrentThingsToFix + FixedToday - NewToday - ReopenedToday`
- Confirmed fixed findings are findings whose `FixedUtc` falls in the latest
  refresh.
- A device is counted as remediated only when it had a fixed finding for the
  recommendation and no current open finding for that recommendation.
- The recommendation remains open while current exposure remains.

Remediation-task status and task due dates are supporting Defender context.
They do not override finding lifecycle or SLA state.

## 8. Shared recommendation work tracking

Tracking is optional and is enabled by
`DASHBOARD_RECOMMENDATION_TRACKING_ENABLED=true`. It applies only to live
recommendations. It is local to this dashboard and does not create or update
Defender assignments, remediation tasks, or recommendation state. Every
authenticated dashboard user can read and update this shared coordination
state.

When `start-app.sh` runs locally without App Service Authentication, tracking
uses an in-memory preview store and records `Unknown dashboard user`. Local
preview state resets on restart and never writes to Azure. Azure-hosted
tracking continues to require App Service Authentication and uses the private
workflow container.

### Identity

The server reads the authenticated user from the validated App Service
Authentication principal. A browser cannot supply or override the recorded
identity. If that authenticated principal has no usable object ID or display
name claim, the server records `unknown` and `Unknown dashboard user` instead
of blocking the workflow update. Each event stores:

- Recommendation ID
- User-selected status
- Entra object ID
- Display name
- Update time
- Run ID and snapshot time at the update

### Persistence

Tracking events are immutable JSON blobs in the private `dvm-workflow`
container. Every update uses `overwrite=False`. A later event supersedes an
earlier event for current display, but historical events are retained. Tracking
does not modify curated datasets, finding history, SLA results, or
`current/manifest.json`.

### State transitions

| Current action/state | New collection evidence | Effective state |
|---|---|---|
| No tracking event or latest event is Clear | Any | Untracked / not started |
| Mark in progress | Same run | In progress |
| In progress | Newer run still has active findings and update is under 7 days old | In progress |
| In progress | Newer run has no active findings | Confirmed fixed; removed from active work |
| In progress | Fresh evidence still shows active findings 7 days after the update | Needs reassignment |
| Mark fixed | Same run | Marked fixed / awaiting collection |
| Mark fixed | Newer run has no active findings | Confirmed fixed |
| Mark fixed | Newer run still has active findings and update is under 7 days old | Still detected after validation |
| Mark fixed | Fresh evidence still shows active findings 7 days after the update | Needs reassignment |

The seven-day clock uses the latest successful collector snapshot rather than
the Web App wall clock. Failed or stopped collection therefore cannot release
an assignment based on stale evidence.

Needs reassignment returns the item to the attention queue while retaining the
previous user and timestamp. Selecting Mark in progress again appends a new
event, changes the displayed person to the current signed-in user, and restarts
the seven-day clock. Tracking is shared workflow metadata, not an exclusive
lock; another authorized tracker can update the item.

### Work-status filters

The global work-status filter provides:

- All work statuses
- Needs attention
- Untracked / not started
- In progress
- Needs reassignment
- Marked fixed / awaiting collection
- Confirmed fixed
- Still detected after validation

All statuses are shown by default. Needs attention includes Untracked, In
progress, Still detected, and Needs reassignment; it excludes items awaiting a
new collection and items confirmed fixed.

## 9. Global filtering

Dashboard filtering uses the selected severity/task priority, recommendation
type, asset classification, subscription, derived operating queue, search
text, asset domains, and optional work status.

- Recommendation filters use recommendation metadata plus linked finding and
  recommendation-machine evidence.
- Finding filters use normalized finding fields.
- Remediation task filters use task fields plus linked recommendation,
  finding, and machine evidence.
- `Vulnerability` versus `Misconfiguration` is derived from remediation type
  and recommendation subcategory.
- Cloud versus device domain follows normalized asset classification.

Statistics and detail pivots retain the same global scope unless a metric
explicitly describes an unfiltered source count.

## 10. Executive Snapshot

Executive Snapshot is a separate management report. It does not replace the
operational Reporting screen.

The report uses its own UTC timeframe and local subscription and operating-team
selectors. Severity, asset classification, recommendation type, domain,
reporting-age, origin, and search filters still apply. The report compares the
selected period with the immediately preceding equal period.

### Entity progress and SLA position

The report presents distinct machines, CVEs, and recommendations together.
Its export selector chooses an entity-detail CSV; it does not change the
summary's counting units. The dashboard has no finding-instance reporting mode.

An unresolved entity appears once, at its highest remaining severity. Overdue
takes precedence over unknown deadline, then not yet due. Pending evidence
remains unresolved. Removing software evidence without clearing the machine/CVE
does not establish a completed vulnerability.

Full clearance requires no unresolved vulnerability in the selected scope:
no affected machine for a CVE, and no remaining CVE for a machine. Confirmed
partial removal is improved, not fully cleared. Recommendation progress is
shared workload context, not a separate SLA clock.

An entity's full-clearance SLA result includes retained component clearances,
not only the final removal. Any late component makes it late. Otherwise a
missing deadline or completion makes it unknown; otherwise it is on time.
The on-time percentage is on-time full clearances divided by on-time plus late
full clearances. Unknown results are shown separately and excluded. An empty
assessment is unavailable, not 100%. Not yet due is not a remediation result.

The dedicated SLA page uses the same distinct CVE/machine semantics for
month-to-date and completed UTC calendar weeks and months. Historical coverage
gaps produce unavailable values rather than zero totals. Existing deadlines
remain in force across policy changes.

PDF output contains the management report. CSV contains all matching rows for
the selected machine, CVE, or recommendation representation, with the pinned
snapshot and report scope. Earlier periods are reconstructed from retained
lifecycle evidence, not a replay of every historical remediation/reopening cycle.

## 11. Deployment effects

| Operation | Code changes | Infrastructure/settings | Creates a dataset run |
|---|---:|---:|---:|
| `tfplan` / `tfapply webapp` | No | Yes | No |
| `tfdeploy webapp` | Web dashboard and server | No | No |
| `tfdeploy function` | Collector Function | No | No |
| Scheduled Function execution | No | No | Yes |
| `CONFIRM_LIVE_COLLECTION=yes ./infra/deploy.sh tfinvoke function` | No | No | Yes |

For persistent tracking enablement, set
`dashboard_recommendation_tracking_enabled` to `true` in
`infra/terraform/main.tfvars.json`, plan and apply the Web App stage, publish
the Web App package, and ensure users have the normal `Dashboard.Viewer`
application role.
