# Dashboard and collection logic

> **Last modified:** 2026-09-27  
> **Purpose:** Define the implemented rules that determine collection state, finding lifecycle, SLA results, prioritization, filtering, remediation outcomes, and shared recommendation workflow.

This document describes current application behavior. Configuration files and
source code remain authoritative when a value shown here changes.

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

## 2. Finding identity and scope

A finding represents a device, vulnerability, product, and version
relationship. `FindingKey` uses the Defender machine-vulnerability row ID when
available. Otherwise it is the SHA-256 hash of:

```text
machineId | cveId | productName | productVersion
```

A product-version change can therefore close one key and open another.

The dashboard identifies open workload as any finding whose `FindingStatus` is
not `Fixed`. States such as `PendingConfirmation`, `StaleDevice`, `OutOfScope`,
and `Unknown` remain visible because they have not been proven fixed.

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

Recommendation prioritization uses Defender recommendation
`SeverityScore`, then current things to fix, then recommendation name.
Remediation outcome tables use severity score, current workload, new/reopened
findings, confirmed fixes, and name. Remediation task tables place active tasks
before completed tasks, then order by task priority, overdue state, earliest
task due date, and most recently modified.

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
configuration values until approved as operating policy.

For live data, the SLA starts when this collector first observes the exact
finding:

```text
SlaDueUtc = FirstObservedUtc + SlaDays
```

This is a calculated SLA target, not a manually assigned remediation-task due
date. Existing findings preserve their policy name, policy version, duration,
start, and target across later runs.

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

The collector compares current finding keys with the prior live state.

| Observation | Result |
|---|---|
| Present in both snapshots | Preserve first observation and remain open |
| Previously fixed key appears again | `Reopened`; set `ReopenedUtc` |
| First qualified absence | `PendingConfirmation`; set `FirstAbsentUtc` |
| Second qualified absence | `Fixed`; use first absence as `FixedUtc` and current snapshot as `FixedConfirmedUtc` |
| Device is stale or not fresh | `StaleDevice`, not fixed |
| Device is offboarded or unsupported | `OutOfScope`, not fixed |
| Device is missing from inventory | `Unknown`, not fixed |

An absence is qualified only when the device remains active and its last-seen
time is within the configured 48-hour freshness window. The required number of
qualified absences is configured as two runs.

Therefore, **fixed** means the exact finding key was absent from two consecutive
complete snapshots while the device remained active and fresh. A Defender task
being completed does not by itself mark findings fixed.

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

## 10. Deployment effects

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
