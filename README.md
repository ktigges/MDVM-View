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

Choose one of these three installation paths:

1. **Azure collector with local Web App** — deploy the Function and protected
   storage, then run the Web App on a workstation against the live Azure data.
2. **Fully hosted Azure deployment** — deploy the Function, protected storage,
   and authenticated Web App in Azure.
3. **Everything local** — run the collector processing and Web App locally to
   evaluate the application without deploying Azure infrastructure.

Options 1 and 2 use the same protected foundation and the same collector
Function deployment. Option 2 does not install a different collector; it adds
the hosted Web App stage to the resources already created for option 1.

### 1. Deploy the Azure collector and run the Web App locally

This is the current customer installation path. Azure hosts the protected
history storage and scheduled collection Function. The Web App runs on the
developer workstation and reads the latest successfully published live dataset
from Azure Storage.

Option 1 deploys the same protected foundation and the same collector Function
used by option 2. These are not temporary or separate resources. Moving from
option 1 to option 2 later only adds the hosted Web App stage.

The local Web App does not call Defender directly. The deployed Function calls
Defender and Graph using its managed identity, publishes an immutable run, and
updates `current/manifest.json`. The local Web App reads that manifest and the
curated files it references.

Azure deployments create a Network Security Perimeter and associate both the
history and Function runtime Storage accounts with its shared Storage profile
by default. The deployment subscription is allowed so the Function, hosted Web
App, and Azure deployment service can reach Storage. The initial
`network_security_perimeter_allowed_ip_cidrs` value is `0.0.0.0/0`, so the
perimeter does not restrict IPv4 source addresses yet; private containers,
Microsoft Entra authentication, managed identities, and Storage RBAC still
control data access. Replace that CIDR with approved operator ranges when the
customer is ready to enforce IP restrictions.

Customer policy must allow Storage
`publicNetworkAccess=SecuredByPerimeter`. A policy that always changes public
network access to `Disabled` will prevent Function package deployment and
application Storage access even when the NSP is configured. See the
[Network Security Perimeter option](DEPLOY.md#network-security-perimeter-option)
for benefits, settings, policy requirements, and existing-environment update
steps.

Set `collector_management_group_id` to the management group ID. Terraform
grants the collector Reader once at that scope, and the collector inventories
subscriptions under that group and its nested groups. Subscriptions added below
the management group are included by later collections without updating a
subscription list. The separate `subscription_id` value still identifies the
subscription where the Vulnerability View Azure resources are deployed.

When the scope is **Tenant Root Group**, use the Microsoft Entra tenant GUID as
`collector_management_group_id`. Azure uses the tenant GUID as the root
management-group ID. Do not use the display name `Tenant Root Group`.

The workstation requires:

- Terraform 1.10 or newer, either on `PATH` or as `terraform.exe` in the
  repository root on Windows;
- Azure CLI authenticated to the target tenant and subscription;
- Python 3.12 or the tested Python 3.14.7 local runtime, with a separate
  virtual environment on each workstation;
- Git;
- globally unique Azure resource names;
- the management group ID containing the subscriptions to inventory;
- Azure and Microsoft Entra permissions described in
  [Required operator permissions](DEPLOY.md#required-operator-permissions).

Windows customers who do not want to change `PATH` can extract the official
Terraform Windows ZIP and place `terraform.exe` beside this `README.md`. The
operations CLI checks that exact local file before checking `PATH`. The binary
is excluded by `.gitignore` and must not be committed.

This deployment uses local Terraform state at
`infra/terraform/terraform.tfstate` on the deployment workstation. Protect and
retain that file. A shared remote state backend can be used when multiple
operators or workstations manage the environment, but it requires separate
Terraform backend configuration and is not included in this deployment
documentation.

Python 3.14.7 has been tested successfully for local installation, deployment
operations, and the project test suite. The test run produces FastAPI/Starlette
deprecation warnings but no failures. The Azure Function and hosted Web App
runtimes remain configured for Python 3.12; the workstation's Python version
does not change the deployed Azure runtime.

Create the environment-specific Terraform values file on macOS or Linux:

```bash
cp infra/terraform/main.tfvars.example.json \
  infra/terraform/main.tfvars.json
```

On Windows PowerShell:

```powershell
Copy-Item infra/terraform/main.tfvars.example.json infra/terraform/main.tfvars.json
```

Create, activate, install, and verify the project on macOS or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -c "import sys, vulnerability_view; print(sys.executable)"
```

On Windows PowerShell, create and activate a separate `.venv-win` environment:

```powershell
python3 --version
python3 -m venv .venv-win
.\.venv-win\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -c "import sys, vulnerability_view; print(sys.executable)"
```

If `python3` is not available on Windows, try `py -3.14` in its place.
The verification output must end in `.venv-win\Scripts\python.exe`.

Run deployment operations as
`python -m vulnerability_view.operations_cli <command>`. This form works on
Windows, macOS, and Linux and does not depend on the shell finding a generated
`vulnerability-view-ops.exe` launcher.

After `.venv-win` is activated, Windows uses the same `python -m ...` commands.
If PowerShell cannot activate the environment, use
`.\.venv-win\Scripts\python.exe -m ...` as a fallback.

Before signing in, planning, or deploying, copy `.env.example` to `.env` and
set:

```dotenv
AUTH_MODE=auto
DASHBOARD_DATA_SOURCE=azure
STORAGE_ACCOUNT_NAME=<history-storage-account>
STORAGE_CONTAINER_NAME=dvm-history
STORAGE_CURRENT_CONTAINER_NAME=dvm-current
APP_MODE=live
DASHBOARD_AUTH_ENABLED=false
DASHBOARD_RECOMMENDATION_TRACKING_ENABLED=false
```

Leave `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` empty for this normal path.
Microsoft Entra uses “client ID” and “application ID” for the same application
identifier, but neither value is needed here. Terraform configures the deployed
managed identities, and the local Web App uses the current `az login` identity.

Use these values and sources:

| `.env` setting | Value to use |
|---|---|
| `AUTH_MODE` | Literal value `auto` |
| `AZURE_TENANT_ID` | Leave empty; the local Web App uses the tenant from `az login` |
| `AZURE_CLIENT_ID` | Leave empty |
| `AZURE_CLIENT_SECRET` | Leave empty |
| `AZURE_SUBSCRIPTION_ID` | Leave empty for the local Web App; Terraform reads `subscription_id` from `main.tfvars.json` |
| `AZURE_MANAGEMENT_GROUP_ID` | Leave empty for the local Web App; Terraform sets it on the deployed collector from `collector_management_group_id` |
| `AZURE_RESOURCE_GROUP` | Leave empty for the local Web App; deployment commands read `resource_group_name` from Terraform |
| `STORAGE_ACCOUNT_NAME` | Copy `history_storage_account_name` from `main.tfvars.json` |
| `STORAGE_CONTAINER_NAME` | Copy `history_container_name`; normally `dvm-history` |
| `STORAGE_CURRENT_CONTAINER_NAME` | Copy `current_container_name`; normally `dvm-current` |
| `APP_MODE` | Literal value `live` |
| `DASHBOARD_DATA_SOURCE` | Literal value `azure` |
| `DASHBOARD_AUTH_ENABLED` | Literal value `false` for local hosting |
| `DASHBOARD_RECOMMENDATION_TRACKING_ENABLED` | Literal value `false` unless the optional feature is specifically required |

Recommendation tracking records dashboard-local work status; it does not create
or update remediation tasks in Defender. Leave it off unless shared tracking is
specifically required.

See the [complete runtime setting reference](docs/configuration-reference.md#4-collector-and-dashboard-runtime-settings)
for every optional `.env` value.

After the Terraform values and `.env` are complete, sign in:

```bash
az login --tenant "<tenant-id>"
az account set --subscription "<subscription-id>"
az account show --query "{name:name,id:id,tenantId:tenantId}" --output table
```

Deploy only the foundation and Function stages:

```bash
python -m vulnerability_view.operations_cli plan foundation
python -m vulnerability_view.operations_cli show foundation
python -m vulnerability_view.operations_cli apply foundation
python -m vulnerability_view.operations_cli verify foundation

python -m vulnerability_view.operations_cli plan function
python -m vulnerability_view.operations_cli show function
python -m vulnerability_view.operations_cli apply function
python -m vulnerability_view.operations_cli deploy function
python -m vulnerability_view.operations_cli verify function
```

Review each Terraform plan before applying it. Leave
`grant_deployer_history_access` set to `true` when the signed-in Terraform
operator also needs to run the Web App locally. Terraform then grants that
identity Storage Blob Data Contributor on the history account. A different
developer needs a separate Blob data-role assignment; subscription access by
itself is not enough.

After Terraform apply, the three Storage values can also be confirmed with:

```bash
python -m vulnerability_view.operations_cli output history_storage_account_name
python -m vulnerability_view.operations_cli output history_container_name
python -m vulnerability_view.operations_cli output current_container_name
```

Publish the first live dataset by waiting for the configured schedule or
invoking the collector:

```bash
python -m vulnerability_view.operations_cli invoke function --confirm
python -m vulnerability_view.operations_cli check-runs --limit 5 --progress
```

The confirmation is required because the invocation creates a new immutable
run and advances `current/manifest.json` after validation.

At this point, the shared foundation and collector Function used by both
options 1 and 2 are complete:

- To run the Web App locally, continue with the local startup command below.
- To host the Web App in Azure instead, skip the local startup and continue to
  [option 2](#2-deploy-the-collector-and-web-app-in-azure).

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

Web App and server changes reload locally and do not require an Azure
deployment. Redeploy the Function only when collector code or its Azure runtime
configuration changes.

Use the [collector and local Web App customer quick start](DEPLOY.md#collector-and-local-web-app-customer-quick-start)
for the consolidated installation commands and
[Required operator permissions](DEPLOY.md#required-operator-permissions) for the
deployment account requirements.

### 2. Deploy the collector and Web App in Azure

This path uses the exact same foundation and collector Function from option 1.
The only additional infrastructure is the authenticated Linux Web App, its
managed identity, and its Microsoft Entra application. The hosted Web App reads
the same current Azure dataset that the local Web App reads in option 1.

After completing the foundation and Function steps from option 1, add the Web
App stage:

```bash
python -m vulnerability_view.operations_cli plan webapp
python -m vulnerability_view.operations_cli show webapp
python -m vulnerability_view.operations_cli apply webapp
python -m vulnerability_view.operations_cli deploy webapp
python -m vulnerability_view.operations_cli verify webapp
```

**Required after deployment:** Terraform creates the assignment-required
`DVM Viewer` Enterprise Application, but it does not choose or assign customer
users. In the Microsoft Entra admin center, open **Enterprise applications >
DVM Viewer > Users and groups**, then assign:

- **Dashboard Viewer** to every user or group allowed to open the Web App.
- **Data Evidence Reader** only to users or groups allowed to use the optional
  Data Evidence browser.
- **Dashboard Administrator** only to users or groups allowed to upload and
  replace customer branding.

Until **Dashboard Viewer** is assigned, users cannot sign in to the hosted Web
App. Group assignment requires the applicable Microsoft Entra licensing; assign
individual users when group assignment is unavailable.

Dashboard Administrators can select the header logo and upload a PNG up to 2
MB and 4096 pixels per dimension. The dashboard automatically fits it within
the header while preserving its aspect ratio. Each upload is retained as a new
immutable version in the workflow container; the application never overwrites
or deletes earlier logo versions.

The `webapp` Terraform stage is cumulative: it preserves the existing
foundation and Function while adding the hosted Web App. Microsoft Entra
authentication controls user access to it.

Use [Azure deployment guide](DEPLOY.md) for the full procedure or
[Greenfield Azure deployment](docs/greenfield-deployment.md) for the shorter
operator checklist.

### 3. Run everything locally

This path is for evaluation, demonstrations, replay, synthetic history, and
development without deploying Azure infrastructure. Collection processing and
the Web App both run on the workstation, and the Web App reads datasets under
`dashboard/data/`.

Continue with [Local evaluation and local datasets](#local-evaluation-and-local-datasets).

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
[Deploy the Azure collector and run the Web App locally](#1-deploy-the-azure-collector-and-run-the-web-app-locally).

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

1. [Daily vulnerability remediation workflow](docs/daily-vulnerability-remediation-workflow.md)
2. [Operations and monitoring](docs/operations-and-configuration.md)
3. [Command reference](docs/command-reference.md)
4. [Collect and replay a sample](docs/sample-replay.md)
5. [Complete configuration reference](docs/configuration-reference.md)

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

### Estimated Azure cost

The current single-region deployment is estimated at approximately **$31.43
USD per month by the end of the first 12 months** and **$364.39 USD for the
first year**, including a 10% planning contingency. This estimate uses public
Central US retail assumptions retrieved on **2026-10-09** and models:

- one always-on Linux App Service **B2** instance at $25.55 per 730-hour month;
- one 4 GB Flex Consumption collector running twice per day for eight minutes;
- two StorageV2 accounts, with hot LRS immutable history starting at 1 GiB and
  growing by 0.160 GiB per successful collection;
- 30-day Log Analytics retention with modeled ingestion below the included
  monthly allowance; and
- 1 GiB of monthly internet egress, no private networking, no Front Door, no
  standby region, and no Always Ready Function instances.

This is a planning estimate, not a quote. Actual charges vary with collection
duration, retained-history growth, telemetry volume, region, currency, taxes,
offers, reservations, negotiated discounts, support, networking, and usage.
Defender, Entra, and other prerequisite licensing is excluded. Adjust the
assumptions in the local [DVM Viewer Azure Cost Calculator](tools/calculator.html)
and confirm the final design in the official
[Azure Pricing Calculator](https://azure.microsoft.com/pricing/calculator/)
before deployment and after material workload changes.
