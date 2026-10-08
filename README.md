# Vulnerability View

Vulnerability View is a read-only collection and dashboard application for
Microsoft Defender Vulnerability Management. It correlates findings,
recommendations, devices, Secure Score, remediation activity, lifecycle state,
and example SLA calculations while retaining point-in-time evidence in
application-owned Azure Storage.

It does not change Defender data, perform remediation, or send dashboard state
back to Defender. Optional recommendation work status coordinates users in this
dashboard only.

## Repository structure

```text
Elite-MockUp/
├── README.md                    Main introduction, navigation, and repository map
├── DEPLOY.md                    Canonical Azure deployment procedure
├── LOGIC.md                     Finding lifecycle, SLA, and dashboard calculation rules
├── function_app.py              Azure Functions timer entry point
├── host.json                    Azure Functions host configuration
├── pyproject.toml               Python package, CLI, tooling, and test configuration
├── requirements.txt             Azure deployment dependency list
├── start-app.sh                 Local Web App startup helper
├── config/
│   ├── sla-policies.json        Versioned example SLA calculation thresholds
│   └── vulnerability-view.example.json
│                                Example application configuration
├── dashboard/
│   ├── index.html               Dashboard page structure
│   ├── app.js                   Filtering, reporting, evidence, and interaction logic
│   ├── styles.css               Dashboard presentation and responsive layout
│   └── config.js                Browser-safe presentation defaults
├── docs/                        Installation, operations, data, and troubleshooting guides
├── infra/
│   ├── deploy.sh                Reviewed Terraform and package deployment workflow
│   ├── check-runs.sh            Durable collection-run status checks
│   ├── check-function-logs.sh   Function and Application Insights log checks
│   └── terraform/
│       ├── main.tf              Azure resources, identities, settings, and monitoring
│       ├── variables.tf         Terraform input contract
│       ├── outputs.tf           Deployment outputs consumed by scripts
│       └── main.tfvars.example.json
│                                Environment values template
├── src/vulnerability_view/
│   ├── dataprep_cli.py          Collection, replay, backfill, validation, and orchestration
│   ├── live_collector.py        Defender and Graph collection and finding reconciliation
│   ├── normalizer.py            API payload normalization
│   ├── summary_builder.py       Lifecycle events, run history, summaries, and reconciliation
│   ├── storage_writer.py        Immutable run bundles and current manifest publication
│   ├── export_writer.py         Dashboard JSON and curated CSV exports
│   ├── operations_cli.py        Cross-platform Azure, Terraform, deployment, and status commands
│   ├── dashboard_server.py      Authenticated FastAPI dashboard and evidence API
│   ├── recommendation_tracking.py
│   │                            Shared recommendation workflow state
│   ├── synthetic_generator.py  Labeled demonstration data generation
│   ├── credentials.py          Local and managed-identity authentication selection
│   ├── config.py               Configuration loading and validation
│   └── models.py               Normalized data models
├── tests/                       Unit, integration, contract, and portability tests
└── tools/                       Local sample import, collection, and cost-estimation tools
```

## Installation paths

### Deploy the collector and run the Web App locally

This is the current customer installation path. Azure hosts the protected
history storage and scheduled collection Function. The Web App runs on the
developer workstation and reads the latest successfully published live dataset
from Azure Storage.

The local Web App does not call Defender directly. The deployed Function calls
Defender and Graph using its managed identity, publishes an immutable run, and
updates `current/manifest.json`. The local Web App reads that manifest and the
curated files it references.

The workstation requires:

- Terraform 1.10 or newer;
- Azure CLI authenticated to the target tenant and subscription;
- Python 3.12 and a separate virtual environment on each workstation;
- Git;
- globally unique Azure resource names;
- an organization-defined Terraform state backend for production;
- Azure and Microsoft Entra permissions described in
  [Required operator permissions](DEPLOY.md#required-operator-permissions).

Create the environment-specific Terraform values file on macOS or Linux:

```bash
cp infra/terraform/main.tfvars.example.json \
  infra/terraform/main.tfvars.json
```

On Windows PowerShell:

```powershell
Copy-Item infra/terraform/main.tfvars.example.json infra/terraform/main.tfvars.json
```

Create and activate the virtual environment on macOS or Linux:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Then run the same commands on either platform:

```bash
python -m pip install -e '.[dev]'
az login --tenant "<tenant-id>"
az account set --subscription "<subscription-id>"
az account show --query "{name:name,id:id,tenantId:tenantId}" --output table
```

Deploy only the foundation and Function stages:

```bash
vulnerability-view-ops plan foundation
terraform -chdir=infra/terraform show foundation.tfplan
vulnerability-view-ops apply foundation
vulnerability-view-ops verify foundation

vulnerability-view-ops plan function
terraform -chdir=infra/terraform show function.tfplan
vulnerability-view-ops apply function
vulnerability-view-ops deploy function
vulnerability-view-ops verify function
```

Review each Terraform plan before applying it. Leave
`grant_deployer_history_access` set to `true` when the signed-in Terraform
operator also needs to run the Web App locally. Terraform then grants that
identity Storage Blob Data Contributor on the history account. A different
developer needs a separate Blob data-role assignment; subscription access by
itself is not enough.

Copy `.env.example` to `.env` and set these environment variables:

```dotenv
AUTH_MODE=auto
DASHBOARD_DATA_SOURCE=azure
STORAGE_ACCOUNT_NAME=<history-storage-account>
STORAGE_CONTAINER_NAME=dvm-history
STORAGE_CURRENT_CONTAINER_NAME=dvm-current
DASHBOARD_AUTH_ENABLED=false
```

Start the local Web App with the same command on Windows, macOS, or Linux:

```bash
python -m uvicorn vulnerability_view.dashboard_server:app \
  --app-dir src \
  --host 127.0.0.1 \
  --port 8000 \
  --reload \
  --reload-dir src \
  --reload-dir dashboard
```

PowerShell accepts the command on one line:

```powershell
python -m uvicorn vulnerability_view.dashboard_server:app --app-dir src --host 127.0.0.1 --port 8000 --reload --reload-dir src --reload-dir dashboard
```

Open <http://127.0.0.1:8000>. With `AUTH_MODE=auto`, the local application uses
the current Azure CLI credential. The deployed Function does not use that
developer login; it uses its own managed identity for Defender and Storage.

The local Web App displays data after the Function publishes its first
successful run. You can wait for the configured schedule or explicitly create
a run:

```bash
vulnerability-view-ops invoke function --confirm
vulnerability-view-ops check-runs --limit 5 --progress
```

The confirmation is required because the invocation creates a new immutable
run and advances `current/manifest.json` after validation.

Web App and server changes reload locally and do not require an Azure
deployment. Redeploy the Function only when collector code or its Azure runtime
configuration changes.

Use the [collector and local Web App customer quick start](DEPLOY.md#collector-and-local-web-app-customer-quick-start)
for the consolidated installation commands and
[Required operator permissions](DEPLOY.md#required-operator-permissions) for the
deployment account requirements.

### Complete hosted deployment

The optional third deployment stage hosts the Web App in Azure with Microsoft
Entra authentication. Deploy it later when users need shared hosted access:

1. Protected history foundation
2. Collector Function and managed identity
3. Authenticated dashboard Web App

Use [Azure deployment guide](DEPLOY.md) for the full procedure or
[Greenfield Azure deployment](docs/greenfield-deployment.md) for the shorter
operator checklist.

## What gets deployed

The complete Azure design contains:

- one protected ADLS Gen2 history account;
- immutable `raw/`, `curated/`, and `runs/` paths;
- a separate mutable current-pointer container;
- a separate replaceable Function runtime storage account;
- a Python Flex Consumption collector Function;
- collector managed identity and least-scope RBAC/API permissions;
- Log Analytics and Application Insights;
- an optional Linux B1 dashboard Web App;
- a dashboard read identity;
- an assignment-required Microsoft Entra Enterprise Application;
- an optional private append-only recommendation-workflow container.

The history account is protected data and must survive replacement of the
Function or Web App.

## Day-to-day operations

Common read-only checks:

```bash
./infra/check-function-logs.sh 1 3 --status-only
./infra/check-runs.sh 5 --progress
.venv/bin/vulnerability-view status
```

Do not manually invoke the collector while the status check reports `ACTIVE` or
`INDETERMINATE`.

For schedules, manual invocation, deployment updates, monitoring, current-run
verification, history restore, and dashboard user assignments, use:

- [Operations and monitoring](docs/operations-and-configuration.md)
- [Command reference](docs/command-reference.md)
- [Troubleshooting](docs/troubleshooting.md)

## Local evaluation and local datasets

Local-only evaluation is a separate development and demonstration option. It is
not the collector installation path above and does not require Azure
infrastructure.

Use it to collect with a developer identity, replay retained raw responses, or
generate labeled synthetic history. Local commands write their presentation
datasets to `dashboard/data/`, curated CSV files to `output/curated/`, and
verified local run bundles under `output/history/`.

Start the Web App against those local datasets with:

```bash
DASHBOARD_DATA_SOURCE=local ./start-app.sh
```

The local dataset does not automatically follow the Azure collector. To display
the collector's current live Azure data, use `DASHBOARD_DATA_SOURCE=azure` and
the Storage environment variables documented under
[Deploy the collector and run the Web App locally](#deploy-the-collector-and-run-the-web-app-locally).

See [Local evaluation and datasets](docs/local-evaluation.md) for collection,
replay, synthetic history, validation, and local file details.

## Data and retention boundaries

Every successful collection creates a new immutable run. Raw response pages,
curated datasets, manifests, checksums, collection status, and the versioned SLA
policy are retained together. The current pointer advances only after a run is
complete and verified.

Paths under `raw/`, `curated/`, and `runs/` are append-only. Application code
does not delete them. `history_immutability_days` is a minimum no-change period,
not an automatic expiration or purge policy.

Local `output/` cleanup never authorizes deletion of Azure history. Starting
over means creating a new immutable run and advancing only
`current/manifest.json` after successful validation.

The dashboard distinguishes:

- live Defender evidence;
- labeled synthetic demonstration history;
- combined views only when the visible data-origin label/filter distinguishes
  both sources.

See [Data structure and retention](docs/data.md) for the full schema and storage
contract.

## SLA notice

The checked-in SLA thresholds demonstrate aging, lifecycle, and reporting
behavior. They are not an adopted organizational policy. Replace them with
organization-defined remediation targets before using SLA results for
operational or compliance decisions.

The finding SLA clock is separate from Defender remediation-task due dates.
See [Dashboard and collection logic](LOGIC.md) for the exact implemented rules.

## Documentation

The ordered documentation index is [docs/README.md](docs/README.md).

### Installation

1. [Azure deployment guide](DEPLOY.md)
2. [Greenfield Azure deployment checklist](docs/greenfield-deployment.md)
3. [Local evaluation and datasets](docs/local-evaluation.md)
4. [Environment and deployment design](docs/environment-and-deployment.md)
5. [Publishing and Azure cost options](docs/web-app-deployment-recommendations.md)

### Operations

1. [Operations and monitoring](docs/operations-and-configuration.md)
2. [Command reference](docs/command-reference.md)
3. [Collect and replay a sample](docs/sample-replay.md)
4. [Complete configuration reference](docs/configuration-reference.md)

### Troubleshooting

1. [Troubleshooting](docs/troubleshooting.md)
2. [Command reference: diagnostics](docs/command-reference.md#6-collection-progress-runs-failures-and-memory)

### Logic and data

1. [Dashboard and collection logic](LOGIC.md)
2. [Data collection and dashboard workflow](docs/data-collection-and-workflow.md)
3. [Data structure and retention](docs/data.md)

### Development

1. [Development, demonstration, and source control](docs/development.md)
2. [Infrastructure helper summary](infra/README.md)

## Independent project, trademarks, and disclaimer

Vulnerability View is an independent project. It is not a Microsoft product and
is not affiliated with, sponsored, endorsed, supported, or warranted
by Microsoft. References to Microsoft, Microsoft Azure, Microsoft Defender, and
other Microsoft products or services are used only to identify the products and
services with which this software interoperates. Microsoft and the names of its
products and services are trademarks of the Microsoft group of companies.

THE SOFTWARE AND DOCUMENTATION ARE PROVIDED "AS IS" AND "AS AVAILABLE," WITHOUT
WARRANTY OF ANY KIND, EXPRESS, IMPLIED, OR STATUTORY, INCLUDING WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, NON-INFRINGEMENT,
ACCURACY, AVAILABILITY, SECURITY, OR RELIABILITY. TO THE MAXIMUM EXTENT
PERMITTED BY APPLICABLE LAW, THE PROJECT CONTRIBUTORS DISCLAIM LIABILITY FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, EXEMPLARY, OR OTHER
DAMAGES, INCLUDING LOSS OF DATA, LOSS OF PROFITS, SERVICE INTERRUPTION,
SECURITY INCIDENTS, OR COSTS ARISING FROM USE OF, INABILITY TO USE, DEPLOYMENT
OF, OR RELIANCE ON THE SOFTWARE OR DOCUMENTATION.

Users are solely responsible for evaluating suitability, validating the design,
securing the deployment, reviewing permissions, protecting data, testing backup
and recovery, complying with applicable laws and organizational requirements,
and monitoring availability and cost. The documentation does not constitute
legal, compliance, security, or professional advice.

Every deployed Azure resource can incur charges. Review current Azure pricing,
budgets, alerts, consumption, and retained-history growth. Protected DVM history
must not be deleted as part of ordinary cost reduction or application cleanup.
