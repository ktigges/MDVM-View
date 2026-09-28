# Collect and replay a sample

Use this workflow to create a one-time, read-only sample of full Defender
Vulnerability Management API responses and replay it in a separate local test
environment.

Replay means importing the checksum-protected raw response pages and running
them through the same normalization, SLA, lifecycle, export, and dashboard-data
pipeline used by live collection. Replay does not call Defender and does not
upload anything to Azure Storage.

Common replay use cases are:

- evaluate the complete dashboard in another isolated environment;
- reproduce a data or normalization issue without repeated source API calls;
- test application changes against a stable, representative snapshot;
- compare performance across workstations or application versions;
- validate filters, grouping, SLA behavior, and exports before deploying any
  Azure infrastructure;
- demonstrate the application when direct source-system access is unavailable.

## Data classification

The package contains sensitive security data. Raw responses can include
device names and identifiers, Azure resource and subscription identifiers,
machine tags, software inventory, vulnerabilities, recommendations, Secure
Score information, and other tenant metadata.

The generated ZIP has SHA-256 integrity protection but is not encrypted.
Transfer it only through an encrypted channel defined by organizational policy. Do not use
ordinary email, source control, public file sharing, or a location with broad
access.

No credential, token, or client-secret file is added intentionally. The source
organization must inspect the package and authorize its release under its own
data-handling policy.

## Collection prerequisites

- Windows PowerShell 5.1 or PowerShell 7
- Python 3.12 or newer
- Azure CLI
- A trusted copy of this repository
- Azure CLI signed into the source tenant
- Read permissions required by `vulnerability-view preflight`
- Internet access to install the pinned Python dependencies and call Microsoft APIs
- A destination directory outside the repository on a secured encrypted drive

Sign in before collection:

```powershell
az login --tenant <source-tenant-guid>
```

## Collect one sample

From the repository root:

```powershell
.\tools\collect-sample-data.ps1 `
  -TenantId "<source-tenant-guid>" `
  -OutputDirectory "E:\SecureTransfer"
```

The default `targeted` enrichment provides the recommendation relationships
needed by the dashboard without requesting every optional recommendation-machine
endpoint. Use `-Enrichment full` only when complete API-level recommendation
relationship reconciliation is required.

The script:

1. Refuses to place sensitive output inside the source repository.
2. Verifies the Azure CLI tenant.
3. Creates an isolated temporary Python environment.
4. Runs the read-only API preflight.
5. Runs one `collect-live --local-only` snapshot.
6. Validates the normalized output and durable local history bundle.
7. Packages only that run's unmodified raw response pages.
8. Adds a manifest with the size and SHA-256 hash of every raw page.
9. Deletes the temporary working directory.

It never uploads the sample to Azure Storage and never calls a remediation write
API.

## Validate and import in another local environment

The replay environment needs Python 3.12 or newer, this repository, and the
transferred ZIP. It does not need Azure CLI sign-in, source API permissions,
Terraform, an Azure subscription, or deployed Azure resources.

First validate the package without extracting it:

```bash
.venv/bin/python tools/import_sample_data.py \
  /secure-transfer/dvm-sample-data-live-YYYYMMDDTHHMMSSZ.zip \
  --validate-only
```

After validation, import it:

```bash
.venv/bin/python tools/import_sample_data.py \
  /secure-transfer/dvm-sample-data-live-YYYYMMDDTHHMMSSZ.zip
```

The importer verifies paths, file types, declared contents, sizes, and SHA-256
hashes before creating `output/raw/<run-id>`. It refuses to overwrite an existing
run.

## Replay the sample

Replay creates a complete local copy of the collected run without deploying
Azure infrastructure or uploading anything to Azure Storage:

```bash
APP_MODE=live STORAGE_ACCOUNT_NAME= .venv/bin/vulnerability-view collect-live \
  --from-raw output/raw/live-YYYYMMDDTHHMMSSZ \
  --local-only
.venv/bin/vulnerability-view validate
DASHBOARD_DATA_SOURCE=local ./start-app.sh
```

The replay writes:

- the imported compressed API pages under `output/raw/<run-id>/`;
- a verified durable run bundle under `output/history/<run-id>/`;
- normalized CSV exports under `output/curated/`;
- all dashboard JSON and CVE detail files under `dashboard/data/`;
- the SLA policy, collection status, checksums, and manifest retained with the
  local history bundle.

`--local-only` is the control that keeps the complete run in the local file
store. Use a clean checkout or workspace so prior live findings and synthetic
output cannot affect validation. The local dashboard reads only
`dashboard/data` and requires no Function, Web App, storage account, Terraform
deployment, managed identity, or App Service Authentication.
