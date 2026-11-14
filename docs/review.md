# DVM Viewer — review before simplification (2026-11-14)

Scope: working tree on `main` at Function/Web version `2026.11.14.2`, which has uncommitted changes in about 45 files. I changed no code. I took measurements from logs and data already on disk:
- `output/diagnostics/collector-20261105T005158Z`: sanitized Function logs for runs `live-20261103…` and `live-20261104…`.
- `output/snapshots/…/live-20261109T123001Z.zip`: a published run bundle, including raw pages.
- `output/benchmarks/bounded-finalization-2m-complete/report.json`: a local synthetic 2M-finding benchmark.
- Microsoft Learn pages for the Defender export, machines, and advanced hunting APIs, fetched today.

Labels used below: **[code]** = read in source. **[data]** = observed in retained run data/logs. **[docs]** = Microsoft documentation. **[test in tenant]** = not yet verified.

## Things that don't match what you described (read first)

1. **Scale Sets are not excluded today.** Exclusion is a flag, `EXCLUDE_SCALE_SETS` / `exclude_scale_sets`. It defaults to `false` ([config.py:50](../src/vulnerability_view/config.py#L50), [variables.tf:364](../infra/terraform/variables.tf#L364)), and `infra/terraform/main.tfvars.json` does not set it. With the flag off, VMSS devices are collected and stored. The dashboard then *groups* VMSS instances into one "VM scale set" row ([dashboard_queries.py:695](../src/vulnerability_view/dashboard_queries.py#L695)) and still counts them in SLA totals. **[code]**
2. **When the flag is on, the collector does not "pull millions then throw away VMSS".** It builds the VMSS device list from `/api/machines` first and never requests findings for those devices. The cost is elsewhere: it then requests findings **one machine at a time**, paced 2.5 s apart, and it **disables delta mode** ([live_collector.py:861-867](../src/vulnerability_view/live_collector.py#L861-L867), [defender_client.py:372](../src/vulnerability_view/defender_client.py#L372), [dataprep_cli.py:528](../src/vulnerability_view/dataprep_cli.py#L528)). **[code]**
3. **The SLA clock does not start at Defender's first-seen date.** It starts at `FirstObservedUtc`, which is the timestamp of the first *collector snapshot* that contained the row. A field called `FirstSeenUtc` exists, but it holds the CVE catalog's **tenant-wide** `firstDetected`, not a per-device date. Neither field is the date you asked for. **[code][data]**
4. **The fixed date is not Defender's.** It is the snapshot time of the first run in which the row was absent. The delta API's `eventTimestamp` and `status=Fixed` are downloaded and kept in `raw/`, then discarded during normalization. **[code][data]**
5. **The SLA policy is not one number per severity.** There are five policies: Critical 2 days, **Critical-with-known-exploit 4 days**, High 7, Medium 30, Low 60 ([config/sla-policies.json](../config/sla-policies.json)). Exploited Criticals currently get *more* time than other Criticals, which looks inverted. Your brief has `[X]` placeholders, so the real numbers are an open question.
6. **Run volumes (resolved 2026-11-14).** Your own environment has about 127 machines. The customer environment is represented by two local snapshots: `live-20261024T005946Z` (2,075 devices, 1,837,575 findings) and `live-20261110T050000Z` (47,890 inventory machines, **45,817 excluded as Scale Sets**, 2,073 collected, 1,551,066 raw finding rows, 2,199,452 curated findings, 2,954,759 finding events). The 2026-11-04 log replays the customer's 1.84M-row baseline in your environment. See §4.5.

---

## Part 1 — Map of what exists

### 1.1 Architecture

| Layer | What it does | Files |
|---|---|---|
| Scheduler / orchestration | Azure Functions (Durable) timer, every 12 h (`0 30 */12 * * *`). Mode `auto` runs a daily delta and a weekly full run on Sunday (`full_collection_weekday: 6`). Each stage runs in a child process with checkpoints. | [function_app.py](../function_app.py), [collection_workflow.py](../src/vulnerability_view/collection_workflow.py), [collection_worker.py](../src/vulnerability_view/collection_worker.py), [collection_transport.py](../src/vulnerability_view/collection_transport.py) (HTTP request/page checkpoints), [collection_identity.py](../src/vulnerability_view/collection_identity.py), [collection_diagnostics.py](../src/vulnerability_view/collection_diagnostics.py), [collection_timing.py](../src/vulnerability_view/collection_timing.py) |
| Collector (API pull) | Defender + Graph + ARM calls. Every response page is gzip-archived to `raw/`. | [defender_client.py](../src/vulnerability_view/defender_client.py), [live_collector.py](../src/vulnerability_view/live_collector.py) `collect_live`, [secure_score_client.py](../src/vulnerability_view/secure_score_client.py), [azure_subscription_client.py](../src/vulnerability_view/azure_subscription_client.py), [credentials.py](../src/vulnerability_view/credentials.py) |
| Processing | Seven separately checkpointed stages: `normalize → reconcile → finding-events → recommendation-events → summaries → history → bundle`. Each stage streams gzip JSON through a SQLite scratch DB. | [resumable_processing.py](../src/vulnerability_view/resumable_processing.py), [bounded_processing.py](../src/vulnerability_view/bounded_processing.py), [live_collector.py](../src/vulnerability_view/live_collector.py) `normalize_live`/`reconcile_live_findings`, [bounded_summary.py](../src/vulnerability_view/bounded_summary.py), [summary_builder.py](../src/vulnerability_view/summary_builder.py), [normalizer.py](../src/vulnerability_view/normalizer.py), [models.py](../src/vulnerability_view/models.py), [dataprep_cli.py](../src/vulnerability_view/dataprep_cli.py) (older in-process path plus local CLI) |
| ADLS layout | Append-only `raw/YYYY/MM/DD/<runId>/<endpoint>-page-NNNN.json.gz`, `curated/YYYY/MM/DD/<runId>/<dataset>.json.gz` (14 datasets), and `runs/YYYY/MM/DD/<runId>/{manifest.json, sla-policies.json, dashboard-*.sqlite3.gz}`. Replaceable `current/manifest.json` sits in the separate current container. Also `dvm-workflow` (tracking events) and branding blobs. | [storage_writer.py](../src/vulnerability_view/storage_writer.py), [dataset_io.py](../src/vulnerability_view/dataset_io.py) |
| Cache layer (Web App) | At least seven derived, disposable SQLite caches: the portable query index built at publish time, the snapshot cache, the filter cube, read-model aggregates, query products, the search projection, and startup preparation. | [dashboard_index.py](../src/vulnerability_view/dashboard_index.py), [dashboard_cache.py](../src/vulnerability_view/dashboard_cache.py), [dashboard_snapshots.py](../src/vulnerability_view/dashboard_snapshots.py), [dashboard_filter_cube.py](../src/vulnerability_view/dashboard_filter_cube.py), [dashboard_read_model.py](../src/vulnerability_view/dashboard_read_model.py), [dashboard_products.py](../src/vulnerability_view/dashboard_products.py), [dashboard_search.py](../src/vulnerability_view/dashboard_search.py), [dashboard_preparation.py](../src/vulnerability_view/dashboard_preparation.py), [dashboard_publication.py](../src/vulnerability_view/dashboard_publication.py), [dashboard_jobs.py](../src/vulnerability_view/dashboard_jobs.py), [dashboard_control.py](../src/vulnerability_view/dashboard_control.py), [dashboard_startup.py](../src/vulnerability_view/dashboard_startup.py) |
| Backend / API | FastAPI app with routes `/api/health`, `/api/auth`, `/api/status`, `/api/diagnostics`, `/api/dashboard/{snapshot,status,query,query/cancel,export}`, `/api/sla-policy`, `/api/recommendation-tracking`, `/api/data-browser/*`, `/api/data/*`, `/api/branding/logo`. Almost all view logic lives in one 4,216-line query engine. | [dashboard_server.py](../src/vulnerability_view/dashboard_server.py), [dashboard_queries.py](../src/vulnerability_view/dashboard_queries.py), [dashboard_management.py](../src/vulnerability_view/dashboard_management.py), [recommendation_tracking.py](../src/vulnerability_view/recommendation_tracking.py), [dashboard_branding.py](../src/vulnerability_view/dashboard_branding.py) |
| Front end | Single-page vanilla JS plus a diagnostics page. | [dashboard/index.html](../dashboard/index.html), [dashboard/app.js](../dashboard/app.js) (1,807 lines), [dashboard/styles.css](../dashboard/styles.css), [dashboard/config.js](../dashboard/config.js), [dashboard/data-evidence.html](../dashboard/data-evidence.html)/[.js](../dashboard/data-evidence.js) |
| Ops tooling | 2,717-line ops CLI, shell/PowerShell menus, Terraform, a GitHub branch workflow CLI, and a cost calculator. | [operations_cli.py](../src/vulnerability_view/operations_cli.py), [github_workflow_cli.py](../src/vulnerability_view/github_workflow_cli.py), `infra/*`, [tools/](../tools/) |

Size: about 23,000 lines of Python/JS/HTML, plus about 5,400 lines of docs.

### 1.2 UI views (nav order)

| View | What it shows | Maps to requirement |
|---|---|---|
| **Summary** (`executive`) | Exposure cards: active/pending exposure *instances*, affected machines, severity donuts, recommendation severity pie. | Partly #5/#6 |
| **Vulnerabilities** (`overview`) | Distinct-CVE list (paged, CSV export) and a "Known exploit watchlist". | #2, #3 entry |
| **Recommendations** | Defender recommendation catalog, impact ranking, work-tracking statuses. | Not requested |
| **Machines** (`workstations`) | Device inventory with VMSS/"workload" grouping, CVE counts, "Not assessed" discovered-only devices. | #4 entry |
| **SLA** (`slaDashboard`) | Distinct-entity SLA for month-to-date and calendar weeks/months, "Compliance percentage snapshots", and machine/CVE drill-down with seven sub-statuses. | #1, #6 |
| (`sla` story) | "Machine/CVE SLA tracking and remediation outcomes": per-recommendation before/after counts. | Not requested |
| **Reporting** (`trend`) | Period comparison, "Change activity by entity", historical OS breakdown, "Observed change detail". | Partly #5 |
| **Executive View** (`executiveSnapshot`) | A separate management report with its own timeframe, PDF/CSV, and compliance snapshots. | #5/#6 (duplicate) |
| **Job history** | Published runs, entity balances, endpoint results. | Admin |
| Pivot panel / detail dialog | CVE → machines and recommendation → machines. Machine → "CVE inventory and remediation" plus "Machine vulnerability history". | #3, #4 |
| New-activity bar | "Newly observed" and "recorded removals" counts with a limit-workspace toggle. | Not requested |
| Help | Long workflow guide. | — |
| `data-evidence.html` | Raw curated data browser. | Admin |

Global filters: subscription, team (inferred), **exposure status** (Detected and pending / Detected only / Pending evidence only / Confirmed fixed only / All lifecycle states), asset class, OS, hide non-reporting (7/14/30/60/90 days), new-period limit, and an 8-option work-tracking status filter.

### 1.3 Statuses, labels, metrics, calculated fields

The **Disposition** column is relative to your four states (OW = Open–within, OP = Open–past, FW = Fixed–within, FP = Fixed–past).

**Finding lifecycle, `FindingStatus`.** Set in `reconcile_live_findings` ([live_collector.py:640](../src/vulnerability_view/live_collector.py#L640)).

| Value | Logic in plain words | Disposition |
|---|---|---|
| `Open` | Row present in this snapshot and in the previous one. | Open (merge) |
| `Reopened` | Row was `Fixed` before and is present again; `ReopenedUtc` is set. | Open (merge). Starts a new episode; see Q4 |
| `DetectionReturned` | Row was Pending and came back; provisional fix revoked. | Open (merge) |
| `Fixed` | Absent from a complete collection while the device is Active and seen within 48 h. `FixedUtc` is the snapshot time of the first absent run. | Fixed (merge) |
| `PendingConfirmation` | Absent, but fewer than `fixedConfirmationRuns` absences. The config value is 1, so new rows should not get this, but **46 legacy rows still exist [data]**. | Drop; map to Fixed |
| `PendingVerification` | Absent, but the collection was incomplete. | Drop as a status; keep the last known Open |
| `StaleDevice` | Absent, but the device is not `Active` or was not seen in 48 h. | Drop as a status; keep Open (see Q3) |
| `OutOfScope` | Absent and the device is offboarded/unsupported. | Exclude from SLA (see Q3) |
| `Unknown` | Absent and the device is missing from inventory (retired?). | Exclude from SLA (see Q3) |

**Evidence status, `SlaEvidenceStatus`.** Values: `Detected`, `Confirmed`, `PendingConfirmation`, `DetectionReturned`, `InsufficientEvidence`, `OutOfScope`. This is a second label that restates `FindingStatus`. **Remove.**

**SLA status, `SlaStatus`.** Set by `apply_sla` ([normalizer.py:56](../src/vulnerability_view/normalizer.py#L56)) and `update_sla` inside reconcile.
- `OpenWithinSla` / `OpenOutsideSla` / `FixedWithinSla` / `FixedOutsideSla` already **are your four states**, at the software-row grain. **Keep**, but compute them at the device+CVE grain.
- `Unknown` covers no first-seen or no matching severity. 30 rows **[data]** have severity `Unknown` because CVE metadata was missing. Decide a default (Q1).
- Bug **[data]**: 44 rows have `FindingStatus=PendingConfirmation` but `SlaStatus=Fixed*`, so the two fields disagree.

**Dashboard pair-level labels** ([dashboard_management.py:372](../src/vulnerability_view/dashboard_management.py#L372) `build_sla`, [:617](../src/vulnerability_view/dashboard_management.py#L617) `sla_pair_sql`).
- `ProgressStatus`: Open / Fix observed — awaiting confirmation / Confirmed fixed. Merge to Open/Fixed.
- `EvidenceProgress`: Confirmed partial fix…, Fix awaiting confirmation…, Confirmed CVE clearance, No confirmed or pending fix. **Remove.**
- Pair `SlaStatus`: Overdue / Unknown SLA / **Awaiting verification** / Within deadline / Fixed late / Fixed within SLA. Merge to the four states.
- Per-period flags `Open/Resolved/Provisional/Partial/Late/Within/Unknown/Overdue/UnknownOpen/Pending/Blocking/AwaitingEvidence`, plus the `_continuous_evidence_aliases` "same identity reappeared" correction ([:126](../src/vulnerability_view/dashboard_management.py#L126)). This logic exists to paper over the key-format bug in §2.3. Replace it with the simple pair rule.

**SLA cards and graphs** ([dashboard_queries.py:2141](../src/vulnerability_view/dashboard_queries.py#L2141) `_sla_rows`, [:2186](../src/vulnerability_view/dashboard_queries.py#L2186) `_sla_cards`).
- Counts per severity: `OpenWithinSLA`, `OpenOutsideSLA`, `FixedWithinSLA`, `FixedOutsideSLA`, `PendingVerification`.
- `SLACompliance` = FixedWithin ÷ (FixedWithin + FixedOutside).
- Cards: "Finding instances observed", "Findings confirmed fixed", "SLA remediations pending verification", "Remediation observed within/outside policy SLA", "Detected findings overdue".
- These count **software rows**, not device+CVE pairs. Keep the four counts but recompute them per pair. Drop the pending card.

**Remediation outcome** ([dashboard_queries.py:2195](../src/vulnerability_view/dashboard_queries.py#L2195)).
- `BeforeLatestRefresh`, `FixedToday`, `NewToday`, `ReopenedToday`, `CurrentThingsToFix`, `ExposedDevices`, `FixedDevicesToday`, `RemediationResult` ("Remediated N assets…"), and `RecommendationSeverity`.
- **Remove.** These are recommendation-oriented and were not requested.

**Reporting period summary** ([dashboard_queries.py:2449](../src/vulnerability_view/dashboard_queries.py#L2449) `_summarize`).
- `New`, `Fixed`, `EndingOpen`, `EndingRiskMachines`, `NewlyAffectedMachines`, `FixedMachines`, `FixedWithinSLA`, `FixedOutsideSLA`, `OpenOutsideSLA`, `NetChange`, `SLACompliance`.
- **Bug:** `New` and "open at date" use `_first = FirstSeenUtc`, the tenant-wide CVE date ([:106-109](../src/vulnerability_view/dashboard_queries.py#L106-L109), [:2400](../src/vulnerability_view/dashboard_queries.py#L2400)). The SLA uses `FirstObservedUtc`. The two clocks disagree.
- Keep only open-vs-fixed over time for #5.

**Executive View / SLA page entity metrics** (`management.build_entities`, `remediation_progress`).
- "Full clearance" per CVE and per machine, "improved" vs "cleared", unresolved-at-highest-severity, on-time %.
- Overbuilt for #5/#6. Replace with pair counts by severity and an open/fixed time series.

**Other calculated fields**
- `PriorityScore` and `PriorityExplanation` ([normalizer.py](../src/vulnerability_view/normalizer.py) `priority_score`): severity + CVSS + exploit + internet + exposure + asset points. Not requested. **Remove from UI.** The field can stay in data.
- `AssetClass` / `OwnerTeam` ("Cloud Operations / Endpoint Operations / Server Operations / Unassigned") and `ClassificationReason` (`_asset_class`, [live_collector.py:231](../src/vulnerability_view/live_collector.py#L231)). An inferred team. Not requested. Remove from UI.
- `ExploitabilityLevel` and the known-exploit flags: used only for the exploit SLA policy and the watchlist. Keep only if Q1 keeps the exploit rule.
- `AssignedTeam`, `AssignedEngineer`, `AssignmentStatus`, `ExternalTicketId`, `AssetCriticality`: always empty or constant ("Standard"). Dead fields.
- Recommendation work tracking (`Untracked / In progress / Needs reassignment / Marked fixed · awaiting collection / Confirmed fixed / Still detected after validation / Needs attention`) and the 7-day reassignment clock ([recommendation_tracking.py](../src/vulnerability_view/recommendation_tracking.py), LOGIC.md §8). Not requested. Remove.
- Remediation-task fields (`DueOnUtc`, `ProgressPercent`, …): the endpoint is "experimental" and off. Remove.
- Secure Score and Azure subscription inventory: not requested. Subscription is used only as a filter.
- Exposure-status filter values (DetectedAndPending, …) exist only because of the Pending states. Remove.

### 1.4 How SLA is calculated today, vs. your model

1. **Policy pick:** match on severity. If any exploit flag is true and a Critical-exploit policy exists, use it (4 days). Otherwise use the shortest matching policy.
2. **Start:** `SlaStartUtc = FirstObservedUtc` = the first collector snapshot containing that **software row** (`FindingKey`).
3. **Due:** `SlaDueUtc = start + SlaDays`.
4. **Fixed:** `FixedUtc` = the snapshot time of the first run where the row was absent, provided the collection was complete and the device is Active and seen ≤48 h ago.
5. **Status:** fixed ≤ due → FixedWithin; still open and snapshot ≤ due → OpenWithin; otherwise the "outside" variants.
6. **Frozen:** once a row has a policy version, its policy name, days, start and due are copied forward unchanged, even if the policy changes.

| # | Difference from your model | Where |
|---|---|---|
| D1 | The grain is the software row, not device+CVE. One CVE on 3 products on one device gives 3 clocks. The dashboard regroups this per pair with complex SQL. | `normalize_live`, `build_sla` |
| D2 | The clock starts at the collector's first observation, not Defender's first-seen. A history reset (as on 2026-11-06) restarts every clock. | [live_collector.py:537](../src/vulnerability_view/live_collector.py#L537) |
| D3 | The fixed date is the snapshot time, not Defender's event time. Granularity is the 12 h schedule. A device that is offline at the time is never credited. | reconcile |
| D4 | The exploit-specific policy gives more time to exploited Criticals. | [config/sla-policies.json](../config/sla-policies.json) |
| D5 | The key changes between delta and full runs, so the same vuln is marked Fixed (often "within SLA") and restarted. See §2.3. | `_raw_finding`, `normalize_live` |
| D6 | A product-version change closes one key and opens another (LOGIC.md §2). That restarts the SLA clock even though the device+CVE never stopped being vulnerable. | `FindingKey` |
| D7 | Pending/Stale/OutOfScope/Unknown states sit outside the four buckets and are shown separately. | reconcile, dashboard |
| D8 | Reporting "new"/"open at" uses a different start date (tenant-wide CVE `firstDetected`) than the SLA. | [dashboard_queries.py:106](../src/vulnerability_view/dashboard_queries.py#L106) |

### 1.5 Dead code, duplication, unrequested features

**Duplicated pipelines**
- `dataprep_cli.collect-live` (in-memory, `summary_builder`) vs `resumable_processing` (bounded, `bounded_summary`). The Function only uses the bounded path; `_run_dataprep` is called only in debug mode ([function_app.py:212](../function_app.py#L212)).
- `normalize_live` has three code paths (archived / workspace / reverse-pop list) to keep output order identical.

**Duplicated SLA logic**
- `apply_sla`, `update_sla` (reconcile), `_sla_rows`, `_summarize`/`_daily_points` policy bins, and `dashboard_management.build_sla` plus `sla_pair_sql`. That is five places that decide within/outside.

**Cache sprawl**
- About seven cache/derived layers for one dataset that has at most a few hundred thousand rows per run.
- Local `output/` has 8.3 GB under `dashboard-startup-benchmarks` and 8.7 GB under `snapshot-imports`.

**Unrequested features**
- Recommendations and recommendation-machine relationships: 99 extra API calls per run **[data]**.
- Work tracking; remediation tasks; Secure Score; subscriptions; priority score; asset class / operating queue; custom workload grouping rules.
- New-activity bar; known-exploit watchlist; Executive View and Reporting as two overlapping report screens; job history; data-evidence browser; customer branding.
- Synthetic data generator plus "combined" mode; GitHub workflow CLI; cost calculator; long help page.

**Dead fields**
- Assignment fields, `AssetCriticality`, `ConfirmationRuns*` (when the setting is 1), and `VerificationFailedUtc`.

---

## Part 2 — Can the data support the simple model?

### 2.1 Requirement check

| Req | Supported by current data? | Fields |
|---|---|---|
| 1 SLA per device+CVE | **Partly.** Severity, due and fixed exist per software row; you can group to the pair. Start and fixed dates are the wrong source (D2, D3), and the key bug (D5) corrupts some rows. | `DeviceId`, `CveId`, `Severity`, `SlaStartUtc`, `SlaDueUtc`, `FixedUtc`, `FindingStatus` in `curated/…/findings.json.gz` |
| 2 Open / fixed views | **Yes.** Each run's findings file carries both current and all historical fixed rows. | `FindingStatus`, `FixedUtc` |
| 3 CVE → machines with first seen, fixed, SLA | **Yes** after the date fixes. A detail pivot exists today. | same, plus `DeviceName` |
| 4 Machine → CVEs | **Yes.** `_machine_remediation` exists. | same |
| 5 Open vs fixed over time | **Yes.** It can be derived from findings dates alone (open at *t* = start ≤ *t* and not fixed by *t*). `finding-events`, `daily-summary` and `run-history` also exist. | `SlaStartUtc`, `FixedUtc`, `ReopenedUtc` |
| 6 SLA gauges by severity | **Yes**, from #1. | as #1 |
| VMSS excluded | **Supported, but turned off.** `/api/machines` returns `vmMetadata.resourceId` (23 of 126 devices have it **[data]**, though not in Microsoft's doc **[docs]**). `is_scale_set_device` checks for `/virtualmachinescalesets/`. | `AzureResourceId` on devices/findings |

### 2.2 How "first seen" and "fixed date" are captured today, and what is available

| Date | Today | Available but unused |
|---|---|---|
| First seen | `FirstObservedUtc`, the first collector snapshot for the row. `FirstSeenUtc` holds the CVE catalog `firstDetected` (tenant-wide). In the 2026-11-09 data the two fields differ on **all 27,008 rows [data]**. | **Delta export rows include per-device `firstSeenTimestamp` and `lastSeenTimestamp` [data][docs].** They sit in `raw/…/vulnerability_changes-page-*.json.gz` and are dropped by `_raw_finding` ([live_collector.py:266](../src/vulnerability_view/live_collector.py#L266)). The full JSON export `SoftwareVulnerabilitiesByMachine` also has `FirstSeenTimestamp` **[docs]**. `machinesVulnerabilities`, used by today's full runs, does **not**: it returns only id, cveId, machineId, fixingKbId, product*, severity **[docs][data]**. Note the format, `"2026-11-06 21:21:15"`, has no `T` or `Z`, so assume UTC **[test in tenant]**. |
| Fixed date | Snapshot comparison: the first complete run where the key is absent while the device is Active and seen ≤48 h ago. `FixedUtc` = that run's snapshot time. | **Delta rows with `status=Fixed` carry `eventTimestamp`** [data][docs]. Microsoft says fix time ≈ `eventTimestamp`, accurate to 6 h, because the delta generator runs every 6 h. There is no separate Defender "remediation timestamp" per device+CVE. The remediation-task API has task-level dates only. |

**How the snapshot comparison works.**
- Delta mode rebuilds "current" from the previous run's active rows. It applies `New`/`Updated` (upsert) and `Fixed` (delete) events, sorted by `eventTimestamp`.
- `reconcile_live_findings` then compares previous and current `FindingKey`s. Any key that disappears goes through the absence rules.

**Edge cases**

| Case | Today | Note |
|---|---|---|
| Device goes offline | `health≠Active` or `lastSeen>48h` gives `StaleDevice`; no fix credit, ever, until the device comes back. 107 of 126 devices are `Inactive` **[data]**. | Defender itself emits `Fixed` only after a new scan, so an offline device keeps its last state. Recommended: keep Open. |
| Device retired / offboarded | `OutOfScope` (offboarded/unsupported) or `Unknown` (missing from inventory). Never fixed. Stays in the findings file forever. | Need a rule (Q3). Recommended: exclude from SLA views from the retire date; do not count as fixed. `/api/machines` also returns `mergedIntoMachineId`, `isExcluded`, and `isPotentialDuplication` **[data]**, which the code does not use. |
| Vuln goes away and returns | Same key → `Reopened`. The *original* SLA deadline is kept (policy fields copied forward), so a re-introduced vuln may be instantly "past SLA". Different key (version change) → a brand-new clock. | Q4: new episode, new clock? Whether Defender resets `firstSeenTimestamp` after a return is **[test in tenant]**. |
| Same CVE on several software items on one device | One row per software item. The device+CVE is fixed only when all rows are gone (LOGIC.md §6; dashboard `build_sla`). 238 of 14,576 pairs have rows in mixed states **[data]**. | Simple rule: pair open if any row is open. First-seen = earliest row first-seen. Fixed date = the latest row fixed date. Severity = highest row severity. |
| Device moves RBAC group | Delta export emits `Fixed` and `New` with the same timestamp **[docs]**. The code orders Fixed first, so the result is still open (OK). | Identity ignores the RBAC group (OK). |

### 2.3 Data defects found

1. **Key-format split between delta and full runs. [code][data]**
   - Full-mode keys look like `machine-_-CVE-_-vendor-_-product-_-version-_-` (the `machinesVulnerabilities` id).
   - Delta-mode keys look like `machine_vendor_product_version_CVE` (the export id).
   - A delta `Updated` event, or the next weekly full run, swaps the key. The old row is marked **Fixed** (usually "FixedWithinSla") and a new **Open** row starts a fresh clock.
   - The 2026-11-09 bundle has **56 identities with two keys**: 26 Fixed+Open, 24 DetectionReturned+PendingConfirmation, 6 StaleDevice+Open.
   - The dashboard's `_continuous_evidence_aliases` partly hides this in the SLA page only.
2. **Status/SLA disagreement.** 44 rows are `PendingConfirmation` with `SlaStatus=Fixed*`.
3. **Delta reconstruction drops non-active rows. [code, suspected — needs a unit test]** `apply_vulnerability_delta` only carries forward `Open/Reopened/DetectionReturned` ([live_collector.py:282](../src/vulnerability_view/live_collector.py#L282)). A `StaleDevice` or `PendingVerification` row is missing from the next "current" set. When its device becomes fresh it looks absent and is marked **Fixed** at that snapshot, even though Defender never sent a `Fixed` event.
4. **Findings file grows without bound.** Fixed and unresolved rows are carried forward in every run. On 2026-11-04 the baseline was 1.84M rows against 685k current rows **[data]**. This is what drives the reconcile disk-full failure (Part 3).

### 2.4 What's missing, and the smallest change

| Gap | Smallest change | Touches data structure? |
|---|---|---|
| Per-device first seen | Keep `firstSeenTimestamp` through `_raw_finding`/normalization. Write it to the **existing** `FirstSeenUtc` field and use it as `SlaStartUtc`. Fall back to `FirstObservedUtc` when it is missing. Full runs need an endpoint that returns it (Part 3). | No schema change. `FirstSeenUtc` changes meaning from CVE-level to device-level. |
| Defender fixed time | For delta `Fixed` events, use `eventTimestamp` as `FixedUtc`/`EffectiveRemediationUtc`. Otherwise keep the snapshot comparison as the fallback. | No schema change |
| Stable identity | Match previous to current on `(DeviceId, CveId, product, version)`, normalized lowercase, not on the raw id. Keep the existing `FindingKey` value when a match exists. | No schema change. Existing duplicate rows need a one-time read-side merge |
| Pair grain | Compute device+CVE state at query time with a `GROUP BY DeviceId, CveId`. | No |
| VMSS | Turn on exclusion, and let delta mode filter by device ID (see Part 3). | No |
| Unbounded growth | Optional: stop re-emitting Fixed rows older than N days into each run's findings file. Historic runs keep them because they are immutable. | Changes row *content* per run, not layout. Only if needed for performance. |

**Conclusion:** the existing ADLS layout and dataset schemas can support the simple model **without layout or schema changes**. The fixes are in how two existing date fields are filled and how rows are matched between runs.

---

## Part 3 — Collector performance

### 3.1 What we measured (not guessed)

**Run `live-20261104T123001Z`, delta mode, 127 machines (Function logs) [data]**

| Step | Time | Notes |
|---|---|---|
| `machines` | 0.3 s | 127 rows |
| `vulnerabilities` (catalog, `updatedOn ge since`) | **50.6 s** | 30,682 rows. This is a tenant-wide catalog delta, not only referenced CVEs |
| `recommendations` | 2.1 s | 1,141 rows |
| `vulnerability_changes` (delta) | 8.7 s | 10,323 rows |
| delta CVE details | ~2 s | |
| recommendation-machine calls (~99 calls), secure score, subscriptions, raw upload | ~2 min 12 s | Not split in this log |
| **API/collect total** | **4 min 42 s** | |
| `normalize` | **117.6 s** | 685,169 findings. About 46 CPU-s per 60 s, so CPU-bound |
| `reconcile` | **3 × ~485 s, then failed** | `sqlite3.OperationalError: database or disk is full`. Baseline 1,837,575 rows. Orchestration failed at 13:01:46; nothing was published |

So for this tenant, **processing, not the API, is the bottleneck, and it fails outright.**

**Local synthetic benchmark, 2M findings on a Mac** (`output/benchmarks/bounded-finalization-2m-complete/report.json`) [data]

| Stage | Time |
|---|---|
| normalize | 111 s |
| reconcile | 136 s |
| finding-events | 95 s |
| summaries | 38 s |
| history | 28 s |
| bundle | 0.2 s |

Total 408 s wall, 392 s CPU, so it is CPU-bound.

**Full mode with per-machine requests:** I have no Function log in hand. The repo's own note ([troubleshooting.md:200](troubleshooting.md)) says 2,440 pages implies about 100 minutes of pacing alone.

### 3.2 How to get the split you asked for

**What already exists.** `[timing]` markers are emitted per run phase (prepare/collect/process/verify/publish).
- `transport`: `networkSeconds`, `pacingSeconds`, `throttledRequests` (429s).
- `storage`: read/write/list seconds and counts (ADLS).
- `processing_stage`: per stage, with `cpuSeconds`.
- `endpoint`: rows/pages/bytes/rows-per-second.

Pull them with the KQL in [troubleshooting.md:250](troubleshooting.md). For the newest run's diagnostics ZIP, use menu **7 → 12** or `python -m vulnerability_view.operations_cli download-collection-diagnostics --id <id>`.

**What's missing.** Inside a stage there is no timer for **parse vs. VMSS filter vs. joins/lookups vs. SLA vs. gzip write vs. SHA-256 vs. upload**. Only progress lines with `elapsedSeconds` exist, and I diffed those above.

**Plan step 0** (below) adds `timed_operation` markers around each sub-step, plus a local replay of a *real* raw run folder through the benchmark harness with `--profile`. The harness today only generates synthetic rows; see [development.md:85](development.md).

**Local profiling now, no code change:**
```bash
PYTHONPATH=src python tests/benchmark_bounded_finalization.py \
  --findings 700000 --history-events 1800000 --profile --enforce-targets \
  --budget 1800 --root output/profile-$(date +%s)
```
This writes `report.json` (per-stage wall/CPU/RSS) and `profile.txt` (top functions). It is shaped like the 2026-11-04 tenant, but the data is synthetic.

### 3.3 Slow patterns found in processing [code]

| Pattern | Where | Effect |
|---|---|---|
| **Small lookup tables kept in SQLite.** Every finding row does about 4 SQLite queries plus JSON decode: `machines.get`, `vulnerabilities.get`, `recommendations_by_product.get`, `in excluded_ids`. Each row is also JSON-encoded into SQLite on append. | `normalize_live` with `workspace` ([live_collector.py:374-540](../src/vulnerability_view/live_collector.py#L374-L540)); `DiskMap` ([bounded_processing.py:270](../src/vulnerability_view/bounded_processing.py#L270)) | 127 machines and ~10k CVEs would fit in a few MB of dicts. This is millions of needless round trips. |
| **Whole-dataset keyed maps in SQLite** with a 4 MB page cache (`cache_size=-4096`). Previous (1.84M) and current (685k) rows are written as full JSON values into `DiskMap`, then iterated and looked up row by row. | `reconcile_live_findings` ([live_collector.py:659-666](../src/vulnerability_view/live_collector.py#L659-L666)) | Disk-full failure, about 5 min CPU. Only ~10 fields are needed for matching. |
| **Unbounded carry-forward** of Fixed/stale rows. | reconcile | Input grows every run. |
| **Same data parsed many times.** Each of the 7 stages re-downloads, re-SHA-256-hashes and re-parses the baseline and current findings. `Artifacts.get` re-hashes the whole file on *every* access ([resumable_processing.py:113](../src/vulnerability_view/resumable_processing.py#L113)), and `history` calls `rows("findings")` several times. | resumable_processing | Repeated full scans of a 55 MB gzip. |
| Pure-Python streaming JSON parser (`raw_decode` on 64 KB chunks). | `iter_json_rows` | Correct and memory-safe, but slower than `json.load` per page for 2,500-row raw pages that already fit in memory. |
| Raw files are canonical-recompressed and re-hashed after collection. | [collection_worker.py:323-334](../src/vulnerability_view/collection_worker.py#L323-L334) | Small. |
| Cache build: the query index is built in `bundle`, then rebuilt or prepared again on Web App startup. | dashboard_index / dashboard_preparation | Not measured here. Startup benchmarks are in `output/`. |
| Many small ADLS writes: one blob per raw page, per request checkpoint, per processing artifact, per state. | collection_transport, resumable_processing | `storage` timing markers will quantify this. In the 2026-11-04 run, uploads were seconds, not minutes. |

### 3.4 Scale Set exclusion

- **Today:** off. When on, it builds `excluded_ids` from `/api/machines` (`vmMetadata.resourceId` contains `/virtualMachineScaleSets/`) and skips per-machine findings requests for those IDs. It also re-filters during normalize, reconcile, and relationships.
- **The catch:** turning it on forces **full mode every run** with per-machine requests (2.5 s each). The code's reason is "tenant-wide delta feed disabled", but delta rows include `deviceId` **[data]**, so the same ID set can filter delta rows while streaming.
- **Can we build the VMSS list once and drop while streaming?** Yes. `/api/machines` is one cheap call (0.3 s for 127 devices; max 10,000 per page; 100 calls/min **[docs]**). Pass the ID `set` into the page reader and drop matching rows before anything else. This works for delta, full JSON export, and file export alike, since all carry `DeviceId` **[docs]**.
- **Risk to verify [test in tenant]:**
  - `vmMetadata` is not in Microsoft's documented schema.
  - Flexible-orchestration VMSS instances may show `virtualMachines/` resource IDs, not `virtualMachineScaleSets/`.
  - Devices without Azure metadata (Arc, or no MDE VM metadata) can't be detected this way.
  - Check the counts in your tenant.

### 3.5 Defender API options

| API | Returns | Limits | Fit |
|---|---|---|---|
| `GET /api/vulnerabilities/machinesVulnerabilities` (**used today for full runs**, one `$filter=machineId eq` per device) | id, cveId, machineId, fixingKbId, productName/Vendor/Version, severity. **No first-seen, no timestamps.** | `$top` ≤10,000; rate limit not stated **[docs]**; code paces at 2.5 s per request | Poor: slow per device, and lacks the dates you need |
| `GET /api/machines/SoftwareVulnerabilitiesByMachine` (full export, JSON paging) | One row per device+software+CVE with DeviceId, DeviceName, OSPlatform, RbacGroupName, CveId, VulnerabilitySeverityLevel, CvssScore, ExploitabilityLevel, **FirstSeenTimestamp, LastSeenTimestamp**, SoftwareName/Vendor/Version, RecommendedSecurityUpdate(Id), SecurityUpdateAvailable, DiskPaths, RegistryPaths, RecommendationReference | pageSize default 50k, **max 200k**; 30 calls/min, 1,000/h; "best for <100K devices"; refreshed every 6 h **[docs]** | **Recommended for full runs.** About 4 pages for 700k rows instead of one request per device. Records are ~1 KB each uncompressed, so stream pages. |
| `GET /api/machines/SoftwareVulnerabilitiesExport` (full export, files) | `exportFiles` (SAS URLs to gzip JSON-lines) and `generatedTime`. Field list not documented; presumably the same as above **[test in tenant]** | 5 calls/min, 20/h; SAS valid 1 h (max 6 h with `sasValidHours`); "recommended for >100K devices" **[docs]** | Good if the tenant is very large. Gzip download, few calls. |
| `GET /api/machines/SoftwareVulnerabilityChangesByMachine` (delta, **used today**) | The full-export fields plus **`Status` (New/Fixed/Updated)**, **`EventTimestamp`** and IsOnboarded. Version upgrade = `Fixed` on the old version plus `New` on the new one. An RBAC move appears twice. | `sinceTime` required, **max 14 days back**; 6-hour generation buckets; pageSize ≤200k; 30/min, 1,000/h **[docs]** | **Yes:** gives fixed dates directly, and only changes are pulled. Microsoft recommends a weekly full baseline plus delta, which is what `auto` mode does already. |
| Advanced Hunting (`DeviceTvmSoftwareVulnerabilities` ⋈ `DeviceInfo`) | 13 columns, **no first-seen or any timestamp column** **[docs]** | 100,000 rows/result, 50 MB, 200 s per query, 10 min/h and 3 h/day CPU, 45 calls/min. **The MDE advanced-hunting API is being retired (began Jan 2026)**; the replacement is Graph `runHuntingQuery` **[docs]** | Not suitable for SLA dates; would need chunking past 100k rows. Useful only to get the VMSS device list from DeviceInfo if `vmMetadata` proves unreliable. |

To confirm in the tenant before building on them:
- Call `SoftwareVulnerabilitiesByMachine?pageSize=200000` and record row count and duration.
- Check that `firstSeenTimestamp` is stable across days and what happens to it after a fix-and-return.
- Confirm that delta `Fixed` rows arrive for offline/retired devices (or don't).
- Confirm the timestamp time zone.
- Check how VMSS instances appear in `vmMetadata`.

### 3.6 Incremental updates without changing stored structure

**Yes.** `auto` mode already does daily delta plus weekly full, and writes the same curated datasets. Changes needed:
- Allow delta mode with VMSS exclusion.
- Carry delta dates through.
- Fix identity matching.
- Keep the 14-day guard: a gap over 14 days forces a full run, as it does today.

Delta runs then pull only thousands of rows; the 2026-11-09 delta had 44 rows **[data]**. The full findings file is still rewritten each run, because each run is immutable and complete. That is fine once reconcile is fixed.

---

## Part 4 — Recommendations

### 4.1 Current state

**Good**
- Immutable, append-only ADLS history with a verified manifest and a pointer swap.
- Raw API pages retained, so the data can be re-derived.
- Resumable collection with request checkpoints.
- Tenant-identity guard.
- Delta mode already wired.
- Timing and diagnostic markers exist.
- Lots of tests.

**Broken**
- SLA start and fixed dates come from the collector, not Defender (D2/D3).
- Delta/full key mismatch silently closes and restarts SLA clocks (§2.3-1).
- Reconcile fails with disk full on a 1.8M-row baseline (Part 3).
- VMSS exclusion is off, and when turned on it forces slow per-device full runs.
- Reporting uses a different start date than SLA (D8).
- Status and SLA fields disagree on some rows.
- The exploit SLA policy is inverted.

**Overbuilt**
- 9 lifecycle statuses, 6 evidence statuses, and 3 extra layers of pair/entity sub-statuses.
- Recommendation tracking, remediation outcomes, priority scoring, asset classes/teams, two report screens, about 7 cache layers, a 4,200-line query engine, a 2,700-line ops CLI, and synthetic/combined mode.

### 4.2 Proposed status model on the existing data

Grain: **one row per (DeviceId, CveId)**, computed by grouping existing `findings` rows. No new dataset.

**Per-pair fields**
- `FirstSeen` = min over software rows in the current episode of `SlaStartUtc`. After the fix, `SlaStartUtc` = Defender `firstSeenTimestamp`, falling back to `FirstObservedUtc`.
- `Fixed` = the pair has no open software row. `FixedDate` = max `FixedUtc` over its rows. After the fix, `FixedUtc` = the delta `eventTimestamp`, falling back to the first absent snapshot.
- `Severity` = highest across the pair's rows.
- `Due` = `FirstSeen` + SLA days for that severity.

**State**
- Open, now ≤ Due → **Open – within SLA**
- Open, now > Due → **Open – past SLA**
- Fixed, FixedDate ≤ Due → **Fixed – within SLA**
- Fixed, FixedDate > Due → **Fixed – past SLA**

**Old → new**

| Old | New |
|---|---|
| Open, Reopened, DetectionReturned | Open |
| Fixed | Fixed |
| PendingConfirmation (legacy) | Fixed, using its `EffectiveRemediationUtc` |
| PendingVerification | Open (last known) |
| StaleDevice | Open (recommended; Q3) |
| OutOfScope / Unknown (retired, offboarded, gone from inventory) | Removed from all views (recommended; Q3) |
| `SlaEvidenceStatus`, `EvidenceProgress`, ProgressStatus, Awaiting/Provisional/Partial | Dropped |

### 4.3 Dashboard: keep the current flow and look (decision 2026-11-14)

The navigation, screen order, layout, styling, pivots (CVE → machines, machine → CVEs) and detail panels **stay as they are**. What changes is the status model and the numbers underneath, so every screen speaks the same four states.

| Screen | Stays | Changes |
|---|---|---|
| Summary | Layout, cards, donuts | Cards and donuts count device+CVE pairs in the four states. Adds the **four SLA gauges by severity** and an **Open vs Fixed over time** chart in the existing panel style. |
| Vulnerabilities | CVE list, paging, CSV, watchlist | Each CVE shows open/fixed machine counts and its SLA state mix. |
| CVE pivot / detail | As today | Machine rows show First seen (Defender), Fixed date, State, Inactive badge. |
| Machines and machine detail | As today | CVE rows show First seen, Fixed date, State. The device shows an Inactive badge after 7 days unseen. |
| SLA | Page, periods, compliance snapshots, drill-down | The seven pair sub-statuses (Awaiting verification, partial fix, …) become the four states. |
| Reporting / Executive View | Pages, PDF/CSV | Same four-state counts and the same start/fixed dates as SLA, which fixes D8. |
| Recommendations, Job history, Help | As today | Wording updated to the four states. |
| Filters | Kept | "Exposure status" (Detected/Pending/…) becomes **State** (the four states plus All). The "Pending only" shortcut is replaced by an **Include inactive devices** toggle. |

Nothing is removed from the navigation unless you ask.

### 4.4 Collector performance fixes, ranked (time saved ÷ effort)

| # | Fix | Expected gain | Effort |
|---|---|---|---|
| 1 | **Reconcile on a compact in-memory index** (key → ~10 fields) or a single SQL join, instead of row-by-row DiskMap on full JSON | Fixes the **disk-full failure**. Reconcile goes from >8 min (failing) to likely ~1 min. Measure with step 0. | Small |
| 2 | **Plain dicts for small lookups in `normalize_live`** (machines, CVEs, recommendations, VMSS ID set) | Removes ~4 SQLite queries per row. Likely halves normalize (118 s); to be measured. | Small |
| 3 | **Full runs via `SoftwareVulnerabilitiesByMachine` (pageSize 200k)** instead of per-machine `machinesVulnerabilities` | Per-device pacing (N × 2.5 s, ~100 min at 2,440 pages per the repo notes) drops to a handful of calls. Also provides `FirstSeenTimestamp`. | Medium, needs a tenant test |
| 4 | **Allow delta with VMSS exclusion** by filtering rows by device ID while streaming | Keeps daily runs incremental when exclusion is on. | Small |
| 5 | **Drop unrequested API calls**: per-recommendation `machineReferences` (~99 calls), Secure Score, subscriptions, and the tenant-wide catalog delta (50 s; fetch only referenced CVEs instead) | About 2–3 min per run. | Small |
| 6 | **Stop re-hashing and re-parsing between stages**: cache digests in `Artifacts`, and merge the 7 processing activities into 2–3 | Tens of seconds to minutes on large baselines. | Medium |
| 7 | **Bound the findings carry-forward** (drop long-fixed rows from new runs' files; history stays in older runs) | Keeps reconcile input from growing forever. | Small, but a data *content* decision (Q6) |
| 8 | Remove `finding-events`, `recommendation-events`, `summaries` and `history` stages if the new UI doesn't read them | Removes ~160 s per 2M rows (benchmark). | Small, after the UI change |


Note: §4.5 below changes item 3 of this table. Because 96% of the customer's machines are Scale Sets, the tenant-wide export would download mostly rows we throw away. Weekly full runs therefore stay per-machine until a tenant test proves otherwise.

### 4.5 Decisions (2026-11-14)

| Topic | Decision | How it is applied |
|---|---|---|
| SLA days | Taken from [config/sla-policies.json](../config/sla-policies.json), unchanged. | All SLA logic reads that file. The current file gives Critical 2 days and Critical-with-known-exploit 4 days; edit the file if that isn't intended. |
| Offline devices | A device is **inactive** when it hasn't been seen for **7 days**. | `lifecycle.deviceFreshnessHours` goes from 48 to **168** in the policy file. Inactive is a **device flag**, not a fifth status. Its pairs keep their last state (an open vuln stays open). An absence on an inactive device never counts as a fix. Offboarded devices and devices missing from inventory are also flagged inactive. |
| Vuln comes back | **Reset.** A return starts a new episode with a new SLA clock. | The earlier episode stays as a Fixed row. The new episode gets its own row and a clock starting at the reappearance (or at Defender's new `firstSeenTimestamp` if Defender resets it; to test). |
| Environments | Your own tenant for live tests. The customer's two snapshots for load and size. | Your tenant: `output/raw`, live runs, ~127 machines. Customer: `output/customer-snapshots/92cb…` (10-24) and `output/snapshot-imports/live-20261110T050000Z-…` (11-10, curated and indexes extracted). The 11-10 raw pages are listed in its manifest but not extracted; the original ZIP is `~/Downloads/live-20261110T050000Z.zip`. |
| Infrastructure | Keep the Azure infrastructure as it is. | No step requires an infrastructure change. Optional settings are listed in §4.7. |

**What the customer snapshot adds (11-10 manifest) [data]**

| Item | Value | Effect on the plan |
|---|---|---|
| Machine inventory | **47,890 machines; 45,817 (96%) excluded as Scale Sets** | Exclusion is on, which forces **full per-machine mode every run** (§3.4). This is the customer's slowness. |
| Machines with findings collected | 2,073 machines, 2,212 pages, 1,551,066 raw finding rows | At 2.5 s pacing, about 90+ minutes of request spacing per run. |
| CVE metadata | 12,410 referenced CVEs missing metadata (only 1,700 returned) | Exploit flags and CVSS are mostly unknown, so severity comes from the finding row. Fix the referenced-CVE lookup in Step 3. |
| Data size | 2,199,452 curated findings; 2,954,759 finding events; 108,177 recommendation-machine rows | These are the load figures for Step 1 (processing) and Step 4 (dashboard). |

### 4.6 Revised plan: Step 0 plus 5 steps

Each step ships as one release, bumps its version with `./bump-version.sh`, and is deployed with the existing commands: `tfdeploy function` for collector steps, `tfdeploy webapp` for dashboard steps. None needs `tfapply`.

**Step 0 — Freeze today's state in a branch, then work on a new branch (git only)**
- Today's working tree on `main` has 45 uncommitted modified files (version `2026.11.14.2`).
- Create `archive/pre-sla-simplification` from the current state, commit all current changes plus `docs/review.md` there, and push it to `origin`. This branch is reference only; nobody builds or deploys from it.
- Create `refactor/sla-simplification` from that archive commit. All Steps 1–5 are committed there, one commit (or PR) per step.
- `main` is left exactly as it is (`033d569`) until the refactor branch is reviewed and merged.
- *Test:* `git status` is clean on the archive branch, both branches exist on `origin`, and `main` is unchanged.
- *Infrastructure/data change:* none. A deploy from the refactor branch replaces only Function/Web App code, as today.

**Step 1 — Make processing fast and stop the disk-full failure (collector code only)**
- Add sub-step `[timing]` markers inside normalize and reconcile: parse, VMSS filter, lookups, SLA, write, hash, upload.
- Use in-memory dicts for the small lookups in `normalize_live`: machines, CVEs, recommendations, and the VMSS ID set.
- Reconcile on a compact key index (about 10 fields per row) instead of full-JSON SQLite maps.
- Cache SHA-256 digests in `Artifacts` so files aren't re-hashed on every access.
- *Test:* replay the customer data locally, with the 10-24 curated findings as baseline and the 11-10 data as current. The curated output must be **byte-identical** to today's code. Record per-stage time and peak disk. Then run one collection in your tenant and compare its `[timing]` markers with §3.1.
- *Data change:* none.

**Step 2 — Fix lifecycle correctness for the simple model (collector code plus the policy-file lifecycle value)**
- Match rows between runs on (device, CVE, product, version), not the API id. Keep the existing `FindingKey` when a match exists. This fixes the delta/full duplicates.
- Carry inactive or pending rows forward in delta mode, which fixes §2.3-3.
- Take Defender `firstSeenTimestamp` into `FirstSeenUtc`/`SlaStartUtc`, and the delta `eventTimestamp` into `FixedUtc` for Fixed events. Fall back to the snapshot times when they're missing.
- Set `deviceFreshnessHours: 168` (7 days), and give no fix credit while a device is inactive.
- Reopen = new episode row and new clock (§4.5).
- Write only `Open` or `Fixed` to `FindingStatus` for new rows. The read side maps the legacy values per §4.2.
- *Test:*
  - Unit tests built from the recorded delta pages in the 11-09 bundle.
  - A replay of your tenant's 11-08 → 11-09 runs must produce **0** identities with two keys (56 today).
  - Reopen and inactive fixtures.
  - Then **one full collection in your tenant** to re-key cleanly before daily deltas resume.
- *Data change:* values only. See §4.7.

**Step 3 — Speed up collection with Scale Set exclusion on (collector code; tenant tests first)**
- Allow **delta mode with exclusion on**. Build the Scale Set ID set from `/api/machines` once, and drop matching delta rows while streaming. Daily customer runs then become one delta pull instead of 2,073 per-machine requests.
- Weekly full runs stay per-machine, with the 2.5 s pacing re-measured against real 429 counts.
- Probe the file-export size in each tenant. Switch the full run to the export only if the download (including the 96% Scale Set rows) is cheaper than per-machine requests.
- Keep the per-recommendation `machineReferences` calls, because the Recommendations screen stays and uses them; the step-0 timing markers will show whether they cost enough to batch. Fetch CVE metadata only for referenced CVEs, and fix the 12,410-missing lookup.
- *Test:* in your tenant, set exclusion on and compare the device+CVE pair set from a delta run with a full run taken the same day. They must match. In the customer environment, compare run duration before and after from the `[timing]` markers.
- *Data change:* none to layout. Raw pages for the dropped endpoint stop appearing in new runs.

**Step 4 — Four-state model in the existing dashboard (Web App code only)**
- One shared backend rule computes device+CVE state from `findings` rows: the four states plus the inactive flag (last seen more than 7 days before the snapshot). Summary, SLA, Reporting, Executive View and the detail pivots all use it, replacing the five separate within/outside calculations.
- Add the severity gauges and the Open vs Fixed chart to Summary. Rename labels and filters per §4.3.
- Same screens, navigation and styling (§4.3).
- *Test:* load the customer 11-10 snapshot locally (`DASHBOARD_DATA_SOURCE=local ./start-app.sh` with the imported snapshot). Record startup time and per-view query latency against today's dashboard on the same snapshot. Check that every screen's four-state totals agree. Then deploy to your environment.
- *Data change:* none. The dashboard reads existing fields.

**Step 5 — Remove internals that are no longer used (both apps; no visible change)**
- The old status vocabulary paths, the legacy alias workaround (`_continuous_evidence_aliases`), duplicated SLA code, the unused in-memory processing pipeline, and cache layers the new queries no longer read.
- Screens and their data stay. Anything visible is removed only if you ask.
- *Test:* the full test suite, the customer-snapshot dashboard benchmark (no slower than Step 4), and one full plus one delta collection in your tenant.
- *Data change:* none. All 14 datasets keep being written.

Step 0 comes first. Steps 1 and 2 are the urgent ones: Step 1 fixes the failing runs and Step 2 fixes the wrong SLA dates. Steps 1 and 3 together address customer collection time.

### 4.7 Infrastructure, schema and data callouts

**Infrastructure:** no changes required.
- The storage account, containers, immutability policy, Function App, Web App and Terraform stay as they are.
- *Optional, an app setting only:* set `"exclude_scale_sets": true` in your environment's `infra/terraform/main.tfvars.json` so it mirrors the customer. Run `tfplan`, then `tfapply function`. This changes one Function app setting and nothing else. The customer environment already has it on.
- *Only if Step 1's measurement still shows local disk exhaustion in Azure* would a larger Function instance be considered. That would be an infrastructure change, and I'd raise it with numbers first.

**Schema:** no dataset, field or ADLS path changes. The 14 curated datasets, `raw/`/`curated/`/`runs/` layout, and `current/manifest.json` pointer are unchanged.

**Data values in new runs (existing history is never rewritten)**

| Field | Today | After |
|---|---|---|
| `FirstSeenUtc` | CVE catalog `firstDetected` (tenant-wide) | Defender per-device `firstSeenTimestamp`, falling back to first observed |
| `SlaStartUtc` / `SlaDueUtc` | First collector snapshot | Same as `FirstSeenUtc`; due = start + days from the policy file |
| `FixedUtc` / `EffectiveRemediationUtc` | First absent snapshot | Delta `eventTimestamp` when Defender reports Fixed, otherwise first absent snapshot |
| `FindingKey` | API id, which differs between delta and full | Stable per (device, CVE, product, version). A reopened episode gets a suffixed key (for example `…#2`) |
| `FindingStatus` | 9 values | `Open` / `Fixed` for new rows; legacy values mapped on read |
| `config/sla-policies.json` → `lifecycle.deviceFreshnessHours` | 48 | 168 |

### 4.8 Questions still open (defaults I'll use unless you say otherwise)

1. **Gauge definition.** Default: per severity, the % of device+CVE pairs that are within SLA, meaning (Open-within + Fixed-within) ÷ all pairs. Fixed pairs count if they were fixed in the selected period.
2. **Inactive devices in the numbers.** Default: show them with an "Inactive" badge, exclude them from gauges and headline counts, and provide one "Include inactive devices" toggle.
3. **Datasets.** Settled: the screens stay, so all 14 datasets keep being written with their current content.
4. **Existing open clocks.** When Step 2 first sees Defender's `firstSeenTimestamp` for a pair that is already open, should the start move to Defender's date? Default: **yes**. It's the date you asked for, though some pairs will jump to "past SLA" on the first run after the change.
5. **Known-exploit rule.** It stays because it's in the policy file (Critical 2 days vs known-exploit 4 days). Edit the file if the 4 days isn't intended.
