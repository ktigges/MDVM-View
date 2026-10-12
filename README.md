# Vulnerability View

Vulnerability View augments Microsoft Defender Vulnerability Management with
retained history, remediation lifecycle tracking, SLA reporting, and simpler
week-to-week operational views.

It helps answer:

- What is currently open?
- What was fixed between runs or reporting periods?
- Which machines, CVEs, and recommendations are involved?
- Which remediation was observed within or outside SLA?
- Which findings are pending confirmation or returned after remediation?
- What does management need to know about SLA exposure, workload movement, and
  where risk is concentrated?

The application reads Defender data. It does not change Defender findings or
perform remediation. Optional recommendation work status exists only inside
Vulnerability View.

## Deploy or update

Use the interactive deployment menu for every normal customer deployment,
update, verification, collection, and diagnostic operation.

Before the first deployment, complete the one-time
[workstation, permissions, and configuration preparation](DEPLOY.md#before-using-the-menu).
This establishes the required tools, customer-specific Terraform values, and
Azure CLI sign-in.

Then start the menu from the repository root.

macOS or Linux:

```bash
./infra/deployment-menu.sh
```

Windows:

```powershell
.\infra\deployment-menu.ps1
```

On a clean Windows clone, install the system prerequisites before starting the
menu. Use Python 3.14 x64 for the customer workstation:

```powershell
winget install --exact --id Python.Python.3.14
winget install --exact --id Microsoft.AzureCLI
winget install --exact --id Hashicorp.Terraform
winget install --exact --id Git.Git
```

Close and reopen PowerShell after installation, run `az login`, and then start
the menu. Confirm that Python reports `AMD64`, not `ARM64`, with
`python -c "import platform; print(platform.python_version(), platform.machine())"`.
The menu does not install Python, Azure CLI, Terraform, or Git. It does create
`.venv-win`, install Vulnerability View and its Python deployment dependencies,
and run the selected infrastructure, application deployment, or verification
workflow.

Before the first deployment, create both environment-specific configuration
files from their tracked examples:

```powershell
Copy-Item .\infra\terraform\main.tfvars.example.json .\infra\terraform\main.tfvars.json
Copy-Item .\.env.example .\.env
```

Some values intentionally appear in both files. `main.tfvars.json` is
authoritative for Azure infrastructure and the hosted Function and Web App;
`.env` controls only local commands and local application processes. When a
local process targets the deployed customer environment, copy the same tenant,
subscription, management-group, resource-group, location, history Storage, and
collection-policy values into the corresponding `.env` settings. Do not put
the Function runtime storage account in `.env`. Neither environment-specific
file is committed. See the
[configuration overlap table](DEPLOY.md#terraform-and-env-overlap) before
running the menu.

At minimum, replace or confirm these customer-specific values in
`infra/terraform/main.tfvars.json` before selecting option 1:

| Terraform setting | Required value |
|---|---|
| `subscription_id` | Subscription GUID where the application resources will be deployed |
| `tenant_id` | Customer Microsoft Entra tenant GUID |
| `collector_management_group_id` | Actual management-group ID; use the tenant GUID for Tenant Root Group, never `customer-management-group-id` |
| `resource_group_name` | Customer deployment resource-group name |
| `location` | Approved Azure region |
| `history_storage_account_name` | Globally unique protected-history Storage account name |
| `function_runtime_storage_account_name` | Globally unique replaceable Function runtime Storage account name |
| `function_app_name` | Globally unique Function App name |
| `web_app_name` | Globally unique Web App name |
| `web_app_service_plan_name` | App Service plan name |
| `web_app_identity_name` | Dashboard managed-identity name |
| `network_security_perimeter_allowed_ip_cidrs` | Approved source CIDRs, or the documented initial `0.0.0.0/0` value while perimeter behavior is validated |

The deployment identity must also be able to create role assignments at the
configured management group. Microsoft Entra Global Administrator alone is not
enough; use Owner, Role Based Access Control Administrator, or User Access
Administrator at that management-group scope.

The deployment menu reads `main.tfvars.json` directly and does not require
`.env` merely to run Terraform. For local live collection, local dashboard
testing, or local diagnostics against the same deployed customer environment,
set at least these values in `.env`:

| `.env` setting | Required value |
|---|---|
| `AUTH_MODE` | `auto` |
| `AZURE_TENANT_ID` | Same value as `tenant_id` |
| `AZURE_SUBSCRIPTION_ID` | Same value as `subscription_id` |
| `AZURE_MANAGEMENT_GROUP_ID` | Same value as `collector_management_group_id` |
| `AZURE_RESOURCE_GROUP` | Same value as `resource_group_name` |
| `AZURE_LOCATION` | Same value as `location` |
| `STORAGE_ACCOUNT_NAME` | Same value as `history_storage_account_name`, never the Function runtime account |
| `STORAGE_CONTAINER_NAME` | Same value as `history_container_name`, normally `dvm-history` |
| `STORAGE_CURRENT_CONTAINER_NAME` | Same value as `current_container_name`, normally `dvm-current` |
| `APP_MODE` | `live` |
| `DASHBOARD_DATA_SOURCE` | `azure` |
| `DASHBOARD_AUTH_ENABLED` | `false` for local hosting |

Leave `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` empty for the normal
`AUTH_MODE=auto` workflow. Local processes use the current `az login`; hosted
applications use Terraform-configured managed identities.

Choose the menu entry that describes the work being performed. For a first
installation or complete update, use **Complete initial deployment or update**.
Review every Terraform plan and approve it only when it contains the expected
changes and preserves retained history.

After deployment, assign approved users or groups the **Dashboard Viewer** role
under **Enterprise applications > DVM Viewer > Users and groups**. Assign
specialized roles separately when required.

See the [Azure deployment guide](DEPLOY.md) for prerequisites, permissions,
configuration, identities, networking, and protected-history boundaries.

## Normal operations

Start the same deployment menu and choose the task shown there. Use the
smallest deployment option that matches the change:

- Dashboard-only changes require only Web App deployment.
- Collector changes require Function deployment.
- Infrastructure or identity changes require a reviewed Terraform plan.
- A collection is needed only when source data or collector output must be
  refreshed.

Direct CLI, Terraform, and Azure commands are not the normal operating path.
Use the [command reference](docs/command-reference.md) only for troubleshooting,
automation, or an individually required operation.

## Dashboard flow

The navigation follows the way the work is normally reviewed:

1. **Summary** shows current exposure, SLA results, Secure Score, and the
   highest-impact recommendations.
2. **Recommendations** and **Prioritize** group finding instances into work
   that can be assigned and completed.
3. **Vulnerabilities** and **Endpoint assets** provide the detailed CVE,
   finding, and machine evidence.
4. **Remediate** shows SLA and remediation outcomes.
5. **Reporting** compares lifecycle changes by finding, machine, CVE, or
   recommendation and exports the filtered detail.
6. **Executive Snapshot** produces a separate management view for a selected
   timeframe, subscription, and operating team. It can be printed or saved as
   PDF and exported to CSV.
7. **How to use** keeps the daily workflow available inside the application.

Executive Snapshot can show either finding instances or recommendation
workload. Recommendation workload is a rollup of linked finding evidence. It
does not create a separate recommendation SLA clock; the displayed SLA result
still comes from finding deadlines.

## How the application works

At a high level:

1. The Azure Function authenticates with its managed identity.
2. It collects machines, vulnerability findings, recommendations, vulnerability
   details, recommendation-machine relationships, Secure Score, and Azure
   subscription context.
3. The collector retains original source pages and normalizes the data into
   machine/CVE finding instances.
4. The current run is compared with retained prior evidence to identify new,
   pending, fixed, returned, and reopened findings.
5. SLA state is calculated from first observation, severity policy, and the
   first qualified remediation absence.
6. Raw evidence, curated datasets, policies, checksums, and run manifests are
   written to immutable Azure history.
7. Only after successful validation does `current/manifest.json` advance to the
   completed run.
8. The Web App reads the current manifest and curated evidence using its
   separate managed identity.

Routine collections use Defender vulnerability deltas. An initial collection,
the configured weekly reconciliation, or a stale/missing baseline uses a full
vulnerability snapshot. A manual full operation also refreshes complete
recommendation-machine relationships.

Detailed implementation is intentionally kept in the following authoritative
documents:

- [Dashboard and collection logic](LOGIC.md) — finding identity, priority,
  lifecycle, remediation, reopening, SLA, filtering, and reporting rules.
- [Data collection and dashboard workflow](docs/data-collection-and-workflow/)
  — APIs, pagination, retries, full/delta behavior, normalization, scaling, and
  end-to-end processing.
- [Data structure and retention](docs/data/) — raw and curated schemas,
  manifests, replay, storage paths, published datasets, and lineage.
- [Daily remediation workflow](docs/daily-vulnerability-remediation-workflow.md)
  — how operators use pending, fixed, SLA, machine, CVE, and recommendation
  reporting.

## Data protection boundary

Every successful collection creates a new retained run.

- `raw/`, `curated/`, and `runs/` are append-only.
- Application code does not delete retained history.
- Only `current/manifest.json` is replaceable.
- The current pointer advances only after a complete run is validated.
- Local `output/` cleanup never authorizes Azure history deletion.
- Replacing application infrastructure must preserve the history Storage
  account.

See [Data structure and retention](docs/data/) for the complete storage
contract.

## Authentication and authorization

- The Function uses a user-assigned managed identity for Defender, Graph,
  Storage, and Azure inventory access.
- The Web App uses a separate managed identity to read protected history.
- Dashboard users authenticate through App Service Easy Auth and Microsoft
  Entra.
- General access requires `Dashboard Viewer`.
- Optional evidence, tracking, and administration capabilities use additional
  application roles.
- Operator passwords and Azure CLI tokens are not stored in the application.

## Documentation

Start with the document that matches the task:

| Need | Document |
|---|---|
| Deploy or update Azure | [Azure deployment guide](DEPLOY.md) |
| Understand calculations and lifecycle | [Dashboard and collection logic](LOGIC.md) |
| Understand data collection and processing | [Data collection and workflow](docs/data-collection-and-workflow/) |
| Understand schemas and retained Storage | [Data structure and retention](docs/data/) |
| Operate the dashboard | [Daily remediation workflow](docs/daily-vulnerability-remediation-workflow.md) |
| Troubleshoot or run an individual command | [Command reference](docs/command-reference.md) |
| Configure a setting | [Configuration reference](docs/configuration-reference.md) |
| Diagnose a problem | [Troubleshooting](docs/troubleshooting.md) |
| Browse all documents | [Documentation index](docs/README.md) |

## Repository map

```text
dashboard/                  Browser application
src/vulnerability_view/     Collection, processing, Storage, and Web App code
infra/                      Terraform and deployment menus
config/                     Versioned policy and configuration examples
docs/                       Detailed installation, operations, logic, and data guides
tests/                      Automated tests
function_app.py             Azure Function entry point
LOGIC.md                    Calculation and lifecycle specification
DEPLOY.md                   Complete Azure deployment reference
```

## Important notices

The checked-in SLA thresholds are examples, not an adopted organizational
policy. Replace them with approved targets before using SLA results for
operational or compliance decisions.

Vulnerability View is an independent project and is not a Microsoft product.
The software and documentation are provided as-is without warranty. Users are
responsible for validating suitability, security, permissions, recovery,
compliance, availability, and Azure cost.

Every deployed Azure resource can incur charges. Review the assumptions with
the local [Azure cost calculator](tools/calculator.html) and the official
[Azure Pricing Calculator](https://azure.microsoft.com/pricing/calculator/).

Local dashboard use, sample replay, development, testing, and source-control
procedures are intentionally separated from the customer deployment path. See
the [Local development README](docs/local/README.md) only when performing local
or development work.
