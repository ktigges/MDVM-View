# Development, demonstration, and source control

> **Last modified:** 2026-11-03
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

## Full-server cold-start benchmark

This local-only harness generates synthetic data in an isolated temporary
directory, starts the actual Uvicorn/FastAPI application with one worker on an
ephemeral loopback port, and waits for real application readiness:

```bash
PYTHONPATH=src .venv/bin/python tests/benchmark_dashboard_startup.py \
  --rows 1800000 --events 1800000 \
  --devices 2075 --cves 13222 --recommendations 100 \
  --runs 2
```

For a quick smoke test:

```bash
PYTHONPATH=src .venv/bin/python tests/benchmark_dashboard_startup.py \
  --rows 1000 --events 1000 --devices 50 --cves 100 --recommendations 20
```

The large scenario is the default except that `--runs` defaults to one. Each
run is a new process with a fresh temporary index; datasets are generated once.
The application still executes its normal startup preparation. The harness
checks health, the exact generated run and index-ready snapshot, and completion of
the Summary and HTTP queries for every default view after index readiness.
Exact finding/event ingestion counts are checked from index diagnostics after
those on-demand queries. Finding counts are checked against the default
exposure filter (which excludes the synthetic Fixed quarter).

Results, startup/heartbeat logs, and per-process resource measurements remain
under a unique directory in ignored `output/dashboard-startup-benchmarks/`.
The command prints the results path before generation begins. `results.json`
records generation time separately from process-launch-to-readiness time, plus
shared-index preparation time, on-demand per-view timings, diagnostics/index bytes,
CPU time, and peak RSS. No view is precomputed before readiness. Resource
measurements cover the server process through application shutdown, including
the post-readiness verification requests; they exclude the data generator.
Peak RSS measurement requires Linux or macOS. If unavailable, the memory
acceptance check fails explicitly rather than reporting a pass.

`--timeout-seconds` defaults to 1800 per startup; `--max-rss-mib` defaults to
512. These are acceptance thresholds, **not enforced CPU/memory quotas**.
Timeouts, startup failures, incorrect results, memory-threshold failures, or
unclean shutdown return a nonzero exit code and retain the evidence. A failed
run stops the remaining attempts. The harness terminates only its own server,
escalating to a kill after ten seconds if necessary, and removes its generated
data and temporary indexes. Abruptly killing the harness itself can leave
temporary local files behind.

The script does not read the repository's `.env`, modify demo data, call
Azure, or change deployed application settings. Inherited Azure hosting,
storage, identity, and dashboard environment settings are removed or overridden
in the child, which runs from the isolated data root. Authentication, branding,
and recommendation tracking are disabled for the benchmark.

**Interpretation:** 1.8 million finding events and 100 recommendations are
explicit synthetic scenario assumptions, not measured customer counts. CVE
cardinality describes references in the findings, not per-CVE detail files.
The fixture mixes Open, Fixed, PendingVerification, and Reopened findings;
other history datasets are empty. It does not simulate managed identity,
Azure downloads/retries, tracking-event blob history, customer-specific data
distribution, App Service disk performance, B2 CPU/memory limits, concurrent
users, or browser rendering. "Cold" means a fresh application process/index,
not a flushed operating-system file cache. A local pass cannot exclude an
Azure-specific startup bottleneck.

## Published dashboard query indexes and staged readiness

Completed run bundles now include `index/dashboard-primary.sqlite3.gz` and
`index/dashboard-history.sqlite3.gz`, published append-only under the immutable
run's `runs/` prefix. They contain the
existing SQLite projections, compressed evidence and indexes, built with the
same query engine and curated datasets as browser queries. Normal CLI collection,
durable/resumable collection, synthetic history and the standalone load-test
populator all retain/upload this artifact before publishing the current manifest.
Resumable processing checkpoints retain the artifact so a fresh worker restores
them without rebuilding. Incomplete runs do not receive published indexes.

The manifest records compressed SHA-256/size, expanded size, query format version
and an identity covering the run, snapshot, normalization version, curated
hashes/counts and query evidence schema/dictionary. The Web App streams the
compressed download, verifies its hash/size, bounds decompression, validates
SQLite and embedded identity/counts, then atomically installs it. Corruption
fails preparation explicitly; it is not silently replaced with partial results.
Older runs and incompatible format versions rebuild locally with a visible
notice. Upgrading the application does not modify an existing immutable run.
Changes to persisted query projections/index definitions must increment
`QUERY_INDEX_VERSION`; changing only report calculations need not rebuild the
stored projections.

Format 10 stores exact JSON and full search text together in compressed blocks
of 256 rows, rather than independently compressing two blobs for every row.
Each connection caches at most four decoded blocks. Device IDs, device names
and recommendation IDs use a shared, typed value dictionary; SQL views expose
the original values, not the internal integer references. Those references
have INTEGER affinity and the dictionary has a value lookup index, so decoded
identifier predicates retain indexed fact lookups rather than nested full scans.
The existing analytical covering indexes, metrics, filters, ordering, evidence
fields, searches and exports are preserved. History materializes only its query
keys; other fields remain available from the exact compressed evidence.

Processing scratch and query-index SQLite pages both use 16 KiB geometry.
Matching page sizes avoids native cache amplification when both databases are
open during finalization. Dataset loading, index construction and dictionary
analysis use a 2 MiB connection cache; ordinary dashboard queries retain their
8 MiB cache, and processing scratch retains its 4 MiB cache. The existing native
RSS regression checks the entire finalization with these databases open together,
without relaxing its 24 MiB growth limit between 1,000 and 100,000 findings.
The maximum page count is calculated from the actual page size.
The **7 GiB per-database/combined published-index limit and 8 GiB
dashboard cache budget are unchanged**. SQLITE_FULL now reports the configured
database limit and filesystem free space explicitly; a large free drive does
not override a database limit.

There are two fixed index groups per run, not one per filter, user or view. Their storage grows
with indexed rows and field sizes rather than filter combinations; it is extra
storage, not a promise of zero overhead. No uncompressed index, SQLite journals
or prepared-report variants are uploaded. Build scratch is removed after
compression; downloaded compressed scratch is removed after installation.
Combined expanded indexes are capped at 7 GiB and the existing per-worker 8 GiB/two-snapshot
cache bounds remain enforced. Existing retained Azure data is never deleted.
Index construction now costs collection/publication time rather than repeating
at every Web App restart. Old snapshots still incur local construction.

ASGI startup now serves the authenticated shell while data preparation runs in
the background. `/api/health` is liveness; `dashboardReady` remains false until
the shared workspace dataset indexes are ready. Summary calculations are not a
global readiness requirement. `/api/dashboard/snapshot` returns
HTTP 202 plus preparation status and `Retry-After` until then, and HTTP 200 with a
pinned snapshot afterward. `/api/dashboard/status` exposes preparation stage,
elapsed/stage seconds, processed rows/bytes and explicit retry/error state.
The UI polls initial readiness every two seconds and replacement preparation
every fifteen seconds. It shows download, restoration, validation, rebuild and
waiting stages without displaying partial totals or fabricated ETAs.
Local index construction also reports every index by name and ordinal, followed
by a separately timed `ANALYZE` stage. Console logs emit each step's start,
completion/failure and elapsed time; heartbeats include completed/total steps.
The status API's `progress.indexPlan` lists the dataset, ordered steps,
`completedSteps` and `totalSteps`. The UI shows the active index and stage
duration, plus an expandable complete/in-progress/waiting checklist. Counts
describe finished operations, not percentage completion inside a SQLite index
build. A failed operation retains its stage and unfinished plan under
`progress.failure`. Already running deployments cannot acquire these diagnostics
without deploying the updated code.

Only the primary index is downloaded/restored before initial readiness. Without
a compatible published index, the required workspace datasets are fully indexed
first; no partial finding totals are exposed. Once those prerequisites are ready,
the snapshot becomes queryable and the selected view runs through the existing
bounded asynchronous query workers. A slow Summary does not gate independent
Recommendations or other views. There is no nine-view startup sequence: all
views, including Summary, are computed on demand.

The internal query name `executive` corresponds to the visible **Summary** tab;
`overview` is **Vulnerabilities**. Per-query progress now names activity/filter
metadata, finding counts, recommendation matching, impact totals, ranking,
evidence enrichment and SLA metrics instead of a misleading `executive:1/9`.
Results and readiness remain pinned to one snapshot and filter scope. Shared
calculation dependencies and available worker capacity can still delay a query;
independent readiness does not promise simultaneous completion on limited CPU.

The recommendation-domain evidence union projects only `RecommendationId` and
`AssetClass`. SQLite 3.40.1 (observed in Azure/Python 3.12) evaluates otherwise
unused payload columns in a wide `UNION ALL` coroutine; decoding those compressed
evidence blocks repeatedly made Summary preparation dramatically slower than
SQLite 3.54 on the local workstation. The narrow projection removes payload
decoder operations without changing matching, search or domain classification.

With the customer's 1,837,575-finding snapshot, a separate read-only diagnostic
process on Azure/SQLite 3.40.1 completed the corrected Summary in 132.892 seconds.
The entire JSON response had the same SHA-256 as the local SQLite 3.54.1 result
(11.398 seconds), including 1,836,170 findings in the default exposure scope,
259 recommendations and 13,121 detected CVEs. The Azure measurement ran alongside
the original application worker; it is not a redeployed startup benchmark or a
guaranteed response time. Aggregate counts and SLA calculations remain significant
work even after unnecessary evidence decoding is removed.

The lifecycle-event index is downloaded/restored on first use and attached read-only;
it is not copied into the primary database. Other views, including history
reports, are prepared only when requested.
Their existing asynchronous queries return HTTP 202 with per-job index progress;
detail/search/filter/pagination/export calculations and bounded result pages are
unchanged. A previous complete snapshot remains served during replacement
preparation or failure. Query/export, evidence-browser and tracking endpoints
cannot read an index that is still being installed. Initial failures remain
visible and retry at the existing dashboard cache interval. First-use report
aggregation may still be expensive even when all row indexes are restored.

The load-test populator still targets exactly the requested upload count,
including the new indexes; it emits two fewer derived raw pages. Previously
published load-test runs are not retroactively changed.

### Rebuilding indexes without recollection

Use the standalone maintenance command for an **existing exact snapshot**, including
customer data. Unlike the synthetic populator, it does not call Defender, clone
identifiers, regenerate summaries, change collection timestamps, or rewrite
history. It uses the signed-in Azure CLI identity, verifies the selected storage
account belongs to the selected subscription, and requires separate existing
history and current-pointer containers.

For the test environment, build and publish indexes for the current snapshot:

```bash
PYTHONPATH=src .venv/bin/python tools/rebuild_dashboard_indexes.py \
  --account sadvmviewerdata \
  --history-container dvm-history \
  --current-container dvm-current \
  --publish
```

Omit `--publish` for **local validation only, with no Azure writes**. Add
`--subscription <subscription-id>` to pin a subscription. Replace the storage
arguments explicitly for a customer environment; do not use the synthetic
populator to index customer data. Review the retained collection identity and type
the exact `account/history-container/current-container` target when prompted.
Automation can supply the same exact value with `--confirm-target`.

The command downloads and hash-verifies curated files and the retained policy,
builds the same primary/history indexes used by normal publication, checks actual
row counts, and validates both compressed databases. Progress uses the existing
startup diagnostics: download byte counts, individual index names/ordinals,
ANALYZE, compression, validation, upload byte counts, timings and heartbeats.
Raw evidence and previous indexes are neither downloaded nor copied.

Each rebuild appends only two indexes, an exact source-manifest copy, and a
revision manifest beneath
`runs/YYYY/MM/DD/<original-run-id>/index-rebuilds/<unique-revision-id>/`.
Existing non-index manifest content and all original evidence paths, hashes,
counts, timestamps and policy references remain unchanged. The collection
`runId` stays the same: an index rebuild is **not a new collection**. A separate
`queryIndexRevision` records the build ID/time, immutable revision-manifest path
and source-manifest provenance. Normal collection file-count metadata continues
to describe the original collection; the rebuild report records five uploads,
including the current pointer.

Before any upload, publication checks the original pointer ETag and requires
the current evidence to match the rebuilt evidence. New immutable uploads use
`overwrite=False`; their size/hash metadata is verified before a conditional
ETag update of **only** the separate `current/manifest.json`. A concurrent
publication, immutable collision or verification failure prevents the pointer
switch. Partial immutable uploads remain retained; there is no rollback deletion.
Avoid overlapping maintenance with other publishers. If a timeout occurs during
the final pointer upload, inspect the current pointer before retrying.

A local build can be published later **without downloading or rebuilding again**:

```bash
PYTHONPATH=src .venv/bin/python tools/rebuild_dashboard_indexes.py \
  --account sadvmviewerdata \
  --history-container dvm-history \
  --current-container dvm-current \
  --publish --publish-existing output/index-rebuilds/rebuild-<local-build-id>
```

The saved target, subscription, revision ID and original pointer ETag are checked
again. If another snapshot has been published, rebuild against that snapshot
instead of changing the saved baseline. `--source-manifest runs/.../manifest.json`
can build a particular retained snapshot locally; publishing it is allowed only
when its evidence still matches current. This is not a historical-data activation
or rollback command.

The command does not deploy or restart either application. The updated Web App
discovers the changed manifest during its normal refresh, prepares the new
revision while retaining the previous ready snapshot, and offers the existing
reload notice. The dashboard snapshot ID changes even though collection `runId`
does not. Verify `/api/dashboard/snapshot` includes the report's
`queryIndexRevision.id` after preparation and reload. An already-open browser
remains pinned until reload. Updated Function code is still needed for indexes
on future normal collections, but is not required to run this maintenance command.
The synthetic populator already builds indexes for its new publication; do not
run this command concurrently just to repeat that work.

Local output contains sensitive curated data, the policy and both compressed
indexes; allow several GiB of free disk and retain/protect it accordingly.
Rebuilds reuse existing Azure evidence, but every revision retains another fixed
pair of compressed indexes. Size depends on record shape and index format; the
older format-8 scale fixture below used about 2.13 GiB compressed. This is
linear additional storage per rebuild, not zero-cost indexing or per-filter
duplication. No Azure data, containers or application resources are deleted.

### Recovering a failed or validated local synthetic population

The populator's `--resume-local` option reuses a saved local population directory:

```bash
PYTHONPATH=src .venv/bin/python tools/populate_load_test_data.py \
  --account sadvmviewerdata \
  --history-container dvm-history \
  --current-container dvm-current \
  --resume-local output/load-test-data/population-REPLACE_WITH_SAVED_ID \
  --publish
```

Replace the final directory name with the failed/validated population directory.
Do not pass `--source-manifest` or regeneration options. This is **synthetic test
data recovery**, not the customer index-only command above.

If compatible indexes and a verified completed bundle already exist, publication
reuses them without another index build or seed download. Otherwise it copies
the exact generated curated files to a new local bundle and rebuilds only the
indexes, retaining the existing raw files and synthetic run identity. It does
not clone identifiers, recollect data, regenerate summaries or rewrite the
original failed directory. A local `manifest.pending.json`, marked incomplete,
retains sizes, hashes and row counts before index construction; it is never
published. Recovery validates those hashes before reusing counts. Older failed
runs without a checkpoint require one streaming count of their retained JSON,
not extrapolation or summary generation.

Target/subscription checks, exact-target confirmation, immutable uploads and
conditional pointer publication still apply. A known changed saved ETag blocks
publication. Already-published runs, or attempts where publication may have
completed, are refused; use index-only maintenance for those retained runs.
Omit `--publish` for local validation only. The command prints a new local report
directory; that report references the reusable bundle and original raw folder.
Publish successfully before deploying the matching updated Web App for the
load test. No Function deployment is required for this standalone workflow.

### Compact format-10 validation with the retained test data

The failed local population was recovered without regenerating findings or raw
pages: **1,837,575 findings, 4,717,980 finding events and 66,439 recommendation
events**. Its longer seed-derived identifiers exposed the old 7 GiB limit; the
earlier generic fixture below was not representative of these record sizes.

The complete format-10 index build and local bundle verification took
**325.666 seconds** on macOS/Python 3.14:

| Index | Expanded bytes | Compressed bytes |
|---|---:|---:|
| Primary | 2,618,769,408 | 554,780,136 |
| History | 1,215,922,176 | 519,446,761 |
| Total | 3,834,691,584 | 1,074,226,897 |

That is approximately **3.57 GiB expanded and 1.00 GiB compressed**, within the
unchanged combined 7 GiB publication limit. The final restored-index check verified
all nine prepared views and every dataset count, with **zero curated downloads**:

| Local operation | Seconds |
|---|---:|
| Primary restore and validation | 2.769 |
| Executive | 7.510 |
| Overview | 3.635 |
| Recommendations | 1.964 |
| Priority | 2.786 |
| Workstations | 0.821 |
| SLA | 7.036 |
| Trend, including first history restore | 35.794 |
| Executive snapshot | 13.256 |
| Help | 0.017 |

These measurements exclude Azure transfer/authentication, Web App startup and
browser rendering. First-use history/report aggregation remains on demand.
Remediation outcomes use one grouped pass per period instead of correlated
device/recommendation scans. The definition is unchanged: a pair must have a
finding fixed during the period and no finding open at its end. Regression tests
compare the grouped result with the original SQL, including nullable and
mixed-type identifiers, fallback recommendation names and timestamp combinations.

The check also pinned the first snapshot while loading a second revision,
restored both primary/history groups exactly once per snapshot, and verified
both snapshots' dataset counts. Their combined local cache was **7,670,022,144
bytes**, below the unchanged **8,589,934,592-byte (8 GiB)** budget.

### Local index scale validation (historical format 8)

A macOS/Python 3.14 synthetic run with 1,837,575 findings, 3,675,150
lifecycle events, 2,075 devices, 13,222 CVE references and 100 recommendations
verified exact index counts and the default executive scope:

| Measurement | Result |
| --- | --- |
| Bundle construction, including both query indexes | 363.031 s |
| Primary index restoration and validation | 4.075 s |
| Executive query after restoration | 6.930 s |
| Deferred history index restoration and validation | 4.291 s |
| Compressed primary index | 1,075,275,302 bytes |
| Compressed history index | 1,209,628,871 bytes |
| Combined expanded indexes | 5,407,633,408 bytes |
| Curated JSON reads during restoration/query checks | 0 |

These are local component timings, **not an Azure start-to-ready prediction**:
they exclude network transfer, managed identity, ASGI startup and browser work.
The history timing excludes report aggregation. The fixture's history count and
entity distribution are assumptions, not measurements of customer data.
The two index artifacts add approximately **2.13 GiB per retained run** in this
fixture, in addition to curated/raw evidence; they are not as compact as gzipped
JSON (the fixture's curated datasets were approximately 129 MiB).
Doubling findings/events from 100,000/100,000 to 200,000/200,000 increased combined
compressed index bytes by 2.005 times. Growth is linear in this test, but the
constant storage overhead is significant and should be included in retention
and transfer planning. The existing cache limits can explicitly reject a
replacement when old/new indexes plus restoration scratch cannot coexist;
the previous complete snapshot remains served rather than exceeding the budget.

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
