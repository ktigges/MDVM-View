# Local evaluation and local datasets

> **Last modified:** 2026-09-28
> **Purpose:** Keep a complete run in the local file store and review the entire dashboard before deploying Azure infrastructure.

This is a separate local-only development and demonstration path. It is not
required when installing the Azure collector and running the Web App locally
against the collector's published Azure data. You can collect or replay source
data, retain the raw and normalized run, inspect every dashboard dataset, and
validate the application locally. It calls no Terraform command, creates no
Azure resource, and does not upload to Azure Storage.

## 1. Workstation requirements

- Python 3.12 or newer
- Azure CLI for live interactive authentication
- Bash and `curl`
- Defender Vulnerability Management access for a live snapshot
- Git only when obtaining or changing the source

Terraform, `zip`, and `jq` are not required until Azure deployment.

## 2. Install the application

From the repository root:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
```

The `.env` file is optional for a basic Azure CLI collection. Keep environment
values out of source control. Environment variables already set in the shell
take precedence.

## 3. Choose local data

### Option A: collect one live snapshot

Sign into the tenant that contains Defender:

```bash
az login --tenant "<tenant-id>"
az account show --query "{name:name,id:id,tenantId:tenantId}" --output table
```

The signed-in identity needs access to the Defender data and device groups being
evaluated. Preflight reports the exact missing required permission:

```bash
.venv/bin/vulnerability-view preflight
```

Collect one point-in-time snapshot:

```bash
APP_MODE=live STORAGE_ACCOUNT_NAME= \
  .venv/bin/vulnerability-view collect-live \
  --local-only \
  --enrichment targeted

.venv/bin/vulnerability-view validate
```

`--local-only` writes only under the local repository:

- `output/raw/<run-id>/` contains compressed source response pages.
- `output/history/<run-id>/` contains the verified local run bundle.
- `output/curated/` contains CSV output.
- `dashboard/data/` contains the JSON read by the local dashboard.

It does not create an Azure resource, upload a blob, update Defender, or invoke
a remediation API.

Use `--enrichment full` only when complete API-level recommendation-machine
reconciliation is required. It makes substantially more Defender requests.

### Option B: replay a sample

Follow [Collect and replay a sample](sample-replay.md) to validate and import a
checksum-protected package. Replay the raw response pages through the same
normalization, SLA, lifecycle, export, and dashboard-data pipeline used by live
collection:

```bash
APP_MODE=live STORAGE_ACCOUNT_NAME= \
  .venv/bin/vulnerability-view collect-live \
  --from-raw output/raw/live-YYYYMMDDTHHMMSSZ \
  --local-only

.venv/bin/vulnerability-view validate
```

Use a clean checkout or workspace so older local findings and synthetic output
cannot affect the validation.

Replay does not call Defender or load the package into Azure Storage.
`--local-only` keeps the raw pages, verified history bundle, curated exports,
and complete dashboard data in the local file store.

Use replay to evaluate the same snapshot in another isolated environment,
reproduce an issue without repeated API calls, test application changes against
stable data, compare performance, or demonstrate and validate the full
dashboard before deploying any Azure infrastructure.

### Option C: build synthetic history

Synthetic generation requires retained live CVE references from a prior live
collection or imported raw sample. It never invents a vulnerability catalog.

```bash
.venv/bin/vulnerability-view build-sample --mode synthetic
.venv/bin/vulnerability-view validate
```

For a combined local presentation:

```bash
.venv/bin/vulnerability-view build-sample --mode combined --from-raw latest
.venv/bin/vulnerability-view validate
```

Every record is labeled with `DataOrigin`, `ScenarioId`, `SnapshotTimeUtc`, and
`CollectionRunId`. Synthetic rows must not be interpreted as Defender evidence.

## 4. Start the local dashboard

```bash
DASHBOARD_DATA_SOURCE=local ./start-app.sh
```

Open <http://127.0.0.1:8000>. Use a different port when needed:

```bash
DASHBOARD_DATA_SOURCE=local ./start-app.sh 8080
```

The explicit local mode:

- reads `dashboard/data`;
- exposes the same dashboard data APIs used by the hosted application;
- disables App Service Authentication;
- reloads source changes during development;
- uses in-memory recommendation tracking;
- never writes shared Azure workflow state.

Stop it with `Ctrl+C`.

## 5. What can be reviewed locally

The local file store contains the complete collected run:

- compressed source API pages;
- the verified history bundle, manifest, checksums, and retained SLA policy;
- normalized CSV exports;
- all dashboard JSON datasets and per-CVE detail files;
- endpoint status, row counts, durations, lifecycle events, reconciliation,
  Secure Score, subscription metadata, recommendations, and device data.

You can review every dashboard page, filter, recommendation, workload, SLA
calculation, lifecycle state, source-data health result, and read-only API
locally. No storage account, Function, Web App, managed identity, Terraform
deployment, or App Service Authentication is required.

Hosted scheduling, managed identity, App Service Authentication, Azure RBAC,
shared recommendation tracking, and immutable Azure retention can only be
validated after deployment. Local recommendation tracking is an in-memory UI
preview and resets when the local process stops.

## 6. Validate before deciding to deploy

Confirm:

1. Required preflight routes pass.
2. `vulnerability-view validate` reports no errors.
3. The dashboard identifies the expected subscriptions, recommendations,
   devices, severities, and source-data health.
4. The SLA values are treated as examples until adopted as operating policy.
5. Scale-out device naming and workload-grouping rules match the source environment.
6. Collection duration, peak memory, compressed run size, and telemetry volume
   are recorded for Azure sizing and cost estimates.

Only after this review proceed to
[Azure deployment guide](../DEPLOY.md).

## 7. Local data safety and cleanup

Local generated files can be rebuilt, but they may contain sensitive security
data. Protect and remove them according to the organization’s defined handling
process.

Local cleanup never authorizes deletion of Azure Storage data. Retained Azure
paths under `raw/`, `curated/`, and `runs/` are separate immutable evidence.
Only `current/manifest.json` is replaced during successful publication.

## Next documents

- [Azure deployment guide](../DEPLOY.md)
- [Operations and monitoring](operations-and-configuration.md)
- [Troubleshooting](troubleshooting.md)
- [Command reference](command-reference.md)
- [SLA and lifecycle logic](../LOGIC.md)
