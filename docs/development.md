# Development and maintenance

The [README](../README.md) covers the application and handoff.
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
python -m pytest -q tests/test_dashboard_exports.py
node --test tests/dashboard_findings.test.cjs tests/dashboard_queries.test.cjs
python -m pytest -q
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

The standalone benchmarks generate isolated local data. They do not establish
Azure B2 response times, network behavior, managed-identity latency, or capacity
for a different customer's data shape.

Query-engine scale check:

```bash
PYTHONPATH=src python tests/benchmark_dashboard_queries.py \
  --rows 2000000 --events 2000000 --prepare-defaults --all-views \
  --broad-filters --mixed-lifecycle --enforce-targets
```

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
