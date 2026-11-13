# Development and maintenance

The [project guide](../PROJECT-GUIDE.md) covers the engineering handoff.
[Application flow](application-flow.md) describes the runtime.
This guide covers local work, tests, release versions, and maintenance tools.

## Local development

The package requires Python 3.12 or later. Both Azure applications run Python
3.12; deployment workstation setup uses Python 3.14.

macOS/Linux:

```bash
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

Windows PowerShell:

```powershell
py -3.14 -m venv .venv-win
.\.venv-win\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Existing local output can be served with:

```bash
./start-app.sh
```

On Windows, with the environment activated:

```powershell
python -m uvicorn vulnerability_view.dashboard_server:app --app-dir src --host 127.0.0.1 --port 8000 --reload
```

The local dashboard reads `dashboard/data` by default. Synthetic data, live
collection, and imported snapshots have different data-handling implications;
the [local evaluation guide](local-evaluation.md) covers those paths.
Local recommendation tracking is off by default. When explicitly enabled,
the local preview is in memory and resets with the process.

Replay avoids repeated Defender downloads while testing normalization,
lifecycle, SLA, or dashboard output:

```bash
vulnerability-view simulate-scheduled-run --from-raw latest --local-only
vulnerability-view validate
```

An authorized local viewer can read Azure data with
`DASHBOARD_DATA_SOURCE=azure ./start-app.sh`. That is real customer data access,
not an isolated fixture. Local live collection without `--local-only` can also
publish to configured Storage.

## Validation

Tests use pytest; browser interaction tests use Node.js without installing
front-end packages. Examples:

```bash
DASHBOARD_AUTH_ENABLED=false python -m pytest -q tests/test_dashboard_exports.py
node --test tests/dashboard_queries.test.cjs
DASHBOARD_AUTH_ENABLED=false python -m pytest -q
git diff --check
```

Terraform and shell checks apply when those files change:

```bash
terraform -chdir=infra/terraform validate
bash -n infra/deploy.sh infra/check-runs.sh infra/check-function-logs.sh start-app.sh
```

Regular pytest excludes `performance` tests. The retained finalization regression
can be selected explicitly:

```bash
python -m pytest -q -m performance tests/test_bounded_processing.py
```

Exercise raw replay, normalization, and full finalization with **three million
current findings** and 3.3 million retained events (6.3 million output events):

```bash
PYTHONPATH=src python tests/benchmark_bounded_finalization.py \
  --findings 3000000 --history-events 3300000 --budget 1800 \
  --enforce-targets --root output/finalization-benchmark
```

These are the benchmark defaults. This is opt-in, not part of ordinary pytest.
The synthetic workload has 2,122 machines, up to 13,604 referenced CVEs,
128 products, four severities, and historical events spanning 90 days. Raw pages
are machine-grouped and bounded to 2,500 rows rather than one giant input file.
Both portable query-index groups are built and the bundle passes the existing
integrity checks. The benchmark enforces exact finding/event counts and a
30-minute processing budget; a timeout fails instead of reporting success.

For a shorter investigation of the customer's `normalize / replay-raw` stage,
stop after normalization with a ten-minute processing budget:

```bash
PYTHONPATH=src python tests/benchmark_bounded_finalization.py \
  --stop-after normalize --budget 600 --enforce-targets \
  --root output/normalization-benchmark
```

For rapid hotspot investigations, profile a smaller workload separately instead
of repeating the three-million-row acceptance run:

```bash
PYTHONPATH=src python tests/benchmark_bounded_finalization.py \
  --findings 100000 --history-events 110000 --stop-after normalize \
  --budget 120 --profile --enforce-targets \
  --root output/normalization-profile
```

This processes 100,000 real synthetic rows; it does not claim to verify
three-million-row throughput, nonlinear costs, or memory use by extrapolation.
Ordinary pytest runs the small benchmark-harness regressions, not either large
workload.

Add `--profile` to capture `profile.pstats` and the top cumulative/self-time
functions in `profile.txt`;
profiling adds overhead, so do not compare profiled timings with unprofiled
release budgets. Each run also writes `report.json` with stage wall/CPU times,
peak RSS, timeout/interrupted-stage details, and exact checkpoint counts.
`progress.jsonl` captures timestamped substep messages, including raw replay and
query-index construction. A normalization-only run reports `targetReached=true`
but `complete=false`: it has not exercised the later stages.

Always select a fresh or empty local root; existing results are not overwritten.
Input generation is timed separately, outside the processing budget. The
benchmark exercises actual application processing with synthetic local files
only, not Azure, network latency, API pacing, or customer records. Passing
locally is not a customer-environment performance guarantee.
The baseline contains retained events but no prior finding snapshot, so all
current findings produce new events; it does not model every reconciliation
mix in an established customer tenant.

### Scratch SQLite optimizations

Disk-backed mapping membership uses key-only existence queries, without loading
or decoding the stored value. Bulk row/mapping loads stream parameters through
SQLite `executemany`; individual appends and assignments remain immediately
visible on the same connection. No Python batch of full findings is retained.
Scratch transactions commit every 10,000 writes, with a final commit on close.
Bulk operations finish inserting before returning, including before checkpoint
serialization; durable recovery still uses verified artifacts, not scratch
commits. Duplicate ordering, last-value-wins behavior, key encoding, output
formats, history retention, and lifecycle/SLA decisions are unchanged.

Tests and benchmarks can create ignored `.test-work/` and `output/` content.
Those are not release files. Dependency manifests define the environment;
installed framework files are not maintained as project source.

## Release versions

Collector version metadata is in `function-version.json`; dashboard metadata
is in `dashboard/config.js`. Shared Python changes may affect both packages.
Versions use `YYYY.MM.DD.N` with the UTC date and an increment for another
release that day. Revision timestamps use UTC.
Every program change updates the affected application's version/revision and
the modified program files' `Last modified` header dates. Dashboard asset
query versions change with edited browser assets so clients request the new files.

Deployment reads those files and stamps the affected application package.
Terraform preserves existing deployed version settings instead of relabeling
old code. Source publication does not deploy either application.

The source workflow uses `main` for development and `latest` for customer
distribution. The matching workflow menus are:

```bash
./infra/github-workflow-menu.sh
```

```powershell
.\infra\github-workflow-menu.ps1
```

The shared CLI tests before publishing/promoting and checks that files and HEAD
did not change during validation. An edit or concurrent commit stops publication
instead of promoting untested content. `GITHUB_WORKFLOW_TEST_COMMAND` can
override its test command. Deployment remains a separate operation.

## Why the reporting implementation changed

Large snapshots made full browser downloads and repeated raw-evidence scans
expensive. The current design addresses those costs in several places:

| Choice in place | Reason |
|---|---|
| Server-side SQLite facts and bounded pages | Keep complete findings/events out of browser memory |
| Published primary/history indexes | Move reusable index construction into publication rather than every viewer restart |
| Compressed evidence blocks and typed identifier dictionary | Preserve exact evidence while reducing index size and repeated decoding |
| Separate shared aggregate model | Reuse counts and relationships without rescanning every finding for each default view |
| Exact filtered rollups and CVE membership | Reuse compatible aggregates without double-counting distinct CVEs |
| Separate persistent viewer-cache container | Restore compatible completed indexes, search, history, and query results after restart |
| Background preparation with explicit readiness | Keep the shell responsive without reporting incomplete data as complete |
| Separate interactive and heavy-work capacity | Keep reports and exports from occupying every navigation worker |
| Shared requests, cancellation, and deadlines | Avoid repeating equivalent work or keeping abandoned requests indefinitely |
| Narrow SQL projections before evidence decoding | Avoid unnecessary decompression; SQLite versions can choose different plans |

The [runtime reference](application-flow.md#7-web-app-startup-indexing-memory-and-caches)
describes their current behavior and limits.

Filter-rollup construction groups findings before hashing bucket keys and only
feeds eligible rows into period histograms. Workload rules on interned fields
are omitted from per-finding expressions only when the shared dictionary proves
they cannot match. These startup optimizations preserve SLA calculations,
evidence ordering, and existing cache formats; they do not require a query-index
or read-model version change.

## Query-index maintenance

Published indexes belong to the immutable run. A format-incompatible index is
built locally; a corrupt index fails verification. Changing persisted query
projections or index definitions requires a `QUERY_INDEX_VERSION` change.
Changing only a report calculation does not necessarily change that format.
Viewer-only models and saved results have their own compatibility identities.

### Rebuilding indexes without recollection

The maintenance tool rebuilds indexes for an exact retained snapshot. It does
not call Defender, change collection timestamps, regenerate findings, or rewrite
original evidence. Without `--publish`, it only downloads and validates locally:

```bash
PYTHONPATH=src python tools/rebuild_dashboard_indexes.py \
  --account "<historyStorageAccountName>" \
  --history-container dvm-history \
  --current-container dvm-current
```

Publication adds `--publish` and requires the exact target confirmation.
A previously validated local build can be reused:

```bash
PYTHONPATH=src python tools/rebuild_dashboard_indexes.py \
  --account "<historyStorageAccountName>" \
  --history-container dvm-history \
  --current-container dvm-current \
  --publish --publish-existing output/index-rebuilds/rebuild-<local-build-id>
```

The tool checks subscription/account identity, evidence hashes, row counts,
index validity, and the original pointer ETag. It appends a revision under
`runs/.../index-rebuilds/<revision>/` and conditionally updates only the current
pointer. The original run ID and evidence remain unchanged. A separate
`queryIndexRevision` records the maintenance operation.

A concurrent publication, invalid evidence, or target mismatch blocks the
switch. Partial immutable uploads remain retained. If the final upload times
out, current-pointer inspection is needed before retrying.
`--source-manifest` can select an older retained manifest for local work;
publication still requires matching current evidence. This is not a historical
data activation tool.

The Web App discovers the new revision through normal metadata refresh; no
application restart or collection is required. Existing browsers stay on their
selected snapshot until reload. Local output contains sensitive curated data
and indexes and can require several GiB of disk.

### Recovering a synthetic load-test population

`tools/populate_load_test_data.py --resume-local <saved-population-directory>`
reuses a failed or validated local synthetic population instead of regenerating
identifiers and raw pages. `--publish` still requires target confirmation.

This is a synthetic test-data tool, not a customer-data repair operation.
It refuses already-published or ambiguous publication attempts. Exact customer
snapshots use the index-rebuild tool above. The two publishers must not overlap.

## Performance checks

### Machine/CVE management reporting

The browser requests `filters.managementReporting=true`. Management summaries
count unique device IDs, unique CVE IDs, and recommendations independently.
Duplicate software/version evidence cannot multiply those totals. Missing
identifiers do not create phantom entities.
Shared startup defaults use the same machine/CVE model and prewarm the
Vulnerabilities view in distinct-CVE mode, rather than preparing unused legacy
finding-instance summaries.

For machines/CVEs, `Improved` requires a confirmed machine/CVE completion during
the selected period with some unresolved risk remaining. Removing one software
instance while the same CVE remains on that machine is not a completed CVE.
Recommendation progress retains confirmed removal of supporting exposure.
`Fully resolved` additionally requires no unresolved
exposure in the entire selected scope at period end. Pending verification is
unresolved even when a qualified-absence timestamp exists. A later confirmed
reopening prevents current resolution but does not erase the earlier resolved
interval. Unknown deadlines are not interpreted as compliant. Assessment is
capped at the pinned collection time.

Management scope ignores activity-window, latest-run-change, and exposure-status
toggles so an unchanged open exposure cannot disappear from the resolution
test. The other workspace filters still apply; resolution is not an unfiltered
tenant-wide claim. Severity uses each entity's highest remaining severity.
Historical status is reconstructed from retained machine `FirstObservedUtc`,
confirmed removals, and reopen timestamps, not a complete replay of every past
cycle. `FirstSeenUtc` can be a CVE catalog detection date and must not backdate
machine exposure when `FirstObservedUtc` is available. Legacy records without
that field retain their existing first-seen fallback. Retained run-history
coverage is explicit: earlier periods are unavailable, not zero; intersecting
periods identify partial history.

Management SLA uses **one outcome per device ID + CVE ID**, not one per software
version. A pair completes only when no evidence remains unresolved and a
confirmed removal falls in the period. After confirmation, its completion time
is the latest first-qualified-absence timestamp across its software evidence
(`EffectiveRemediationUtc`, falling back to `FixedUtc`), and its deadline is the
earliest retained applicable deadline.
Any known lateness wins; otherwise missing deadlines are unknown, not success.
On-time percentage divides completed-on-time pairs by completed pairs with
known outcomes. Open/pending and unknown outcomes never enter that denominator.
The same CVE can be fixed on one machine and remain open on another.
The severity chart exposes each numerator, assessed denominator, late count,
and excluded unknown-deadline completion count. Empty severity buckets say
Waiting for data, not 100%. A 100% on-time completion rate does not mean all risk
has been remediated. The overall completion counts and retained observation
start/snapshot count are visible alongside the chart.

First-day qualified absence is reported separately as **Fix observed — awaiting
confirmation**, not a completed SLA outcome. `AwaitingConfirmation` counts
machine/CVE pairs only if all unresolved software evidence is
`PendingConfirmation`, with a usable `EffectiveRemediationUtc` in the selected
period. Unqualified verification, stale/offline devices, returned detections,
and partial software clearance do not qualify. Confirmation retains the first
absence date; an interrupted qualified sequence restarts that date. Pending
rows keep open SLA status in collection output, and older provisional fixed-SLA
labels are excluded from the technical completed-outcome calculation.
Activity cards, period comparisons, machine/CVE rows, detail, and CSVs expose
the provisional/confirmed distinction without multiplying software evidence.
Viewer read-model, filter-rollup, and prepared-response identities are advanced
when these calculations change; retained collection evidence and published
query indexes are not rewritten.

Summary contains only current machine/CVE headline totals, their severity
breakdowns, observed/confirmed fix activity, a new/fixed/open CVE comparison,
and a compact SLA-by-severity status table. It does not show
compliance percentages, period comparison tables, or detailed
remediation tables. Detailed SLA analysis remains in Executive Snapshot,
Reporting, and Remediate. The compact table separates open-within-deadline,
open-overdue, completed-on-time, completed-late, and unknown-deadline outcomes.
These categories are disjoint; known overdue/late evidence takes precedence
over missing deadlines. Unknown combines open and completed unassessed outcomes;
verification-pending evidence stays open. Completions use the report period,
while open status uses its pinned endpoint.

The detailed SLA, Executive Snapshot, Vulnerabilities, and Reporting panels
retain completion percentages and period movement. The
headline severity panels show machines/workload instances first, then unique
CVEs, each classified once at its highest remaining severity in the selected
scope: Critical, High, Medium, Low. Unknown severity is separate, never silently
classified Low. Machine totals are distinct device IDs, not collapsed workload
groups. SLA outcomes are separate from vulnerability severity; there is no
red/yellow/green rating or `ExecutiveStatus` field. SLA deadlines do not reset
on deployment; new collection evidence updates tracking at each pinned snapshot.

The dedicated SLA page starts with a compact machine/CVE-pair severity summary,
reusing `build_sla` outcomes without recalculating lifecycle or policy decisions.
Its `machineCveSummary` metadata is independent of calendar-history availability:
open status is current; month-to-date fixes explicitly report partial coverage.
Summary drilldowns use the same pair projection and predicates as the counts,
including open deadline counts, confirmed-fix percentages, and explicit unknown deadlines.
Open deadline status is labeled not yet due or overdue, not completed SLA.
With no confirmed fixes with known deadlines, completion is N/A, never 100%.
CSV exports use those identical predicates. The distinct-entity reports remain
separate below it.

Management-card actions select the counted entity/status table, not a broader
list. Activity-window details retain the actual evidence scope rather than
switching to a management report that discards activity dates. Observation
counts include software/version evidence and pending or subsequently reopened
fixes; they do not assert full CVE clearance. The optional between-run activity
window uses an exclusive previous boundary and inclusive latest boundary.
Queries, read-model eligibility, prepared-response identities, and exports
respect that window; unavailable comparisons never fall back to a daily window.
Machine activity detail additionally includes a separate full-scope CVE status
list, so activity filtering never conceals that machine's other unresolved CVEs.
The original activity evidence and exports retain their activity scope.

Summary, SLA, Remediate, Reporting, and Executive Snapshot include an unresolved
CVE breakdown for each stated reporting period. Its three groups are mutually
exclusive: no recorded fix progress, confirmed progress but still unresolved,
and awaiting confirmation. Pending confirmation takes precedence when a CVE
also has confirmed progress, so it is counted only in the pending group.
The three counts must sum exactly to the unresolved total; both backend and UI
reject inconsistent counts. The displayed equation makes that reconciliation
explicit. The unresolved total is a heading, never a competing fourth bar.

Initial inventory, later additions, and full clearances are displayed separately
from those status bars. They are historical context, not additional unresolved
categories and not operands in a simplified baseline-minus-partial-fixes equation. Initial
inventory is shown separately in periods containing the first retained collection.
First seen after baseline excludes CVEs already present in that initial inventory;
it uses the earliest retained collector observation for a CVE in scope, not
publication time or a new software/version row. It does not establish when the
vulnerability was introduced. If retained baseline history is unavailable, both
discovery counts are unavailable, not zero or the whole backlog.

Fully cleared means a distinct CVE has no remaining unresolved evidence anywhere
in the selected scope, with confirmed clearance during the period. Confirmed
progress among unresolved CVEs includes clearance on some machines or partial
supporting-evidence removal, but does not imply full resolution. Partial fixes count distinct CVEs
with confirmed supporting-evidence removal while the same CVE remains unresolved
on that machine; these do not count as completed SLA outcomes. Awaiting
confirmation counts distinct CVEs with pending-confirmation evidence at period
end, even if other software evidence for the CVE remains detected. Open is the
unresolved backlog at that endpoint, including both partial and pending fixes.
The historical context can overlap status counts, but the three displayed open
status groups cannot overlap. Neither is a remediation rate.
Charts label retained-history coverage; missing history is not proof of zero
activity. Existing immutable history and deadlines are unchanged.

A disk-backed scalar clock projection is shared by the entity and pair
aggregations. Each period endpoint is evaluated once per source row. Full
evidence payloads are not materialized. Group all periods before joining the
compact entity tables, so entity lookups do not run once per machine/CVE pair.
Their bounded disposable product cache is shared across summary,
report, paging, and export requests. Cache admission is limited to 30,000 total
entity rows and the existing product-size limits; evidence collections are
never copied into the response or cache. Cold management aggregation uses the
serialized expensive-query worker, not the read model's interactive fast lane.
Mixed recommendation-type scopes materialize catalog membership once, rather
than performing a correlated type lookup for every evidence row. First-catalog
row and missing-identifier semantics are preserved. The scale benchmark includes
an unrelated misconfiguration action to exercise that customer-data path.
The compact SLA cache retains only per-machine/per-CVE rollups and percentage
charts, never the full machine/CVE pair collection. Prepared response version 19
invalidates earlier presentations without changing retained source data.

Machine/CVE detail defaults to `pivotSlaCveTable`: one row per machine/CVE,
including confirmed fixed and remaining CVEs in the selected reporting period.
`managementSourceView` preserves Executive Snapshot/Reporting scope and dates.
Machine exports include `FixedCVEs` and completed on-time/late/unknown outcomes;
CVE exports include `FixedMachines`. Pair detail exports
carry the period, pinned snapshot, and selected identity.
Machine detail prioritizes the CVE status table above recommendations, with
All, All unresolved, CVEs fully cleared in period, Confirmed partial fixes
(excluding pending), and Awaiting confirmation filters. `EvidenceProgress` distinguishes partial
supporting-evidence clearance from full CVE resolution without changing
`ProgressStatus` or the SLA completion calculation.
Paging and CSV exports use the identical filter and preserve workspace scope.
Its current-period unresolved breakdown and reconciliation stay unfiltered so the
full machine context remains visible. SLA-origin detail uses month to date;
Executive Snapshot and Reporting retain their chosen periods, and other machine
details use the explicitly labeled latest 30 days. Optional dated event history
remains independently selectable.

Recommendations is an alphabetical catalog, with independent
`recommendationCatalogStatus` and `recommendationCatalogSort` controls and
access to workspace filters. Its CSV follows those filters and sort.
`recommendationCatalogSort=priority` puts unresolved actions first, then ranks by
severity, Defender score, affected machines and unique CVEs, not duplicate
instance volume. `recommendationCatalogStatus=Unresolved exposure` limits the
catalog to detected or pending actions. There is no separate Prioritize tab;
legacy browser navigation redirects to Recommendations with Priority sorting.
The legacy priority API remains available for compatibility.
Legacy API requests without management mode retain their prior behavior.
No collector changes or new collection are required.

The browser always uses `filters.includeFindingEvidence=false` and distinct-CVE
mode. It has no finding-instance selector or hidden technical report panels.
The backend's explicit evidence/compatibility contracts remain available for
diagnostic callers; they are not dashboard metrics. Entity CSVs use tables such as
`executiveSnapshotManagementMachineTable`, `executiveSnapshotManagementCveTable`,
and `executiveSnapshotManagementRecommendationTable`. Entity CSVs retain the
period, pinned snapshot time, representation, and resolution-scope filters so
a scoped resolution claim is not mistaken for tenant-wide resolution.

The standalone benchmarks generate isolated local data. They do not establish
Azure B2 response times, network behavior, managed-identity latency, or capacity
for a different customer's data shape.

Query-engine scale check:

```bash
PYTHONPATH=src python tests/benchmark_dashboard_queries.py \
  --rows 2000000 --events 2000000 --prepare-defaults --all-views \
  --broad-filters --mixed-lifecycle --enforce-targets
```

Machine/CVE report scale and response-shape check:

```bash
PYTHONPATH=src python tests/benchmark_dashboard_queries.py \
  --rows 1000000 --mixed-lifecycle --management-reporting --enforce-targets
```

This checks exact distinct-entity totals, no finding-instance columns in entity
tables, bounded responses, a cold report within 10 seconds, a cached response
within 5 seconds, and a second entity page within 10 seconds. Index preparation
is measured separately.

Full-server smoke check:

```bash
PYTHONPATH=src python tests/benchmark_dashboard_startup.py \
  --rows 1000 --events 1000 --devices 50 --cves 100 --recommendations 20
```

Bounded collection finalization:

```bash
PYTHONPATH=src python tests/benchmark_bounded_finalization.py \
  --findings 2000000 --budget 900 \
  --root output/benchmarks/bounded-finalization-2m
```

Each tool's `--help` describes scale and output options. Results identify the
run, data shape, timings, resource measurements, and failures. Acceptance
thresholds in a harness are checks, not enforced service quotas.

## Remaining work and limits

- Executive Snapshot concentration charts share one compact, period-end
  aggregation rather than repeatedly scanning finding evidence. The aggregation
  retains device identities for exact distinct-machine counts, including the
  combined Other row. It reads scoped findings in row order instead of forcing
  recommendation-ordered random evidence lookups. Recommendation workload and
  concentration calculations have separate diagnostic stages; the normal query
  execution deadline is unchanged.
- The recommendation-type classifier treats some end-of-support uninstall
  recommendations as misconfiguration. Their linked vulnerability findings can
  therefore be excluded by the default Vulnerability-only scope. This affects
  count interpretation and remains an unresolved classification issue.
- Cold preparation, a new snapshot, changed filters, and historical reporting
  can still require substantial computation. Compatible cache reuse avoids
  repeated work; it does not make every query free or incremental.
- Hosting still has finite CPU, memory, and local disk. The cache budget does
  not cap total process resource use, and not every pair of snapshots will fit.
- Automated in-app application updates are not implemented. Publication,
  deployment, and approval remain separate operator activities.
- Environment-specific alerts, access ownership, state backups, recovery
  arrangements, and approved SLA targets remain part of the operational handoff.

## Cleanup boundary

Local test output and snapshots may contain unredacted security data.
Handling and removal follow the organization's data policy. Local cleanup,
reset, redeployment, or "start over" never authorizes deletion of retained Azure
history, containers, or accounts.
