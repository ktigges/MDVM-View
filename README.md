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

Use the interactive deployment menu for every normal deployment,
update, verification, collection, and diagnostic operation.

### 1. Install workstation prerequisites

Complete this step before cloning, configuring, or running the deployment
menu. The menu does not install Python, Azure CLI, Terraform, or Git.

Windows PowerShell uses Python 3.14 x64:

```powershell
winget install --exact --id Python.Python.3.14
winget install --exact --id Microsoft.AzureCLI
winget install --exact --id Hashicorp.Terraform
winget install --exact --id Git.Git
```

If `winget` does not install Azure CLI, use Microsoft's
[Azure CLI x64 MSI](https://aka.ms/installazurecliwindowsx64). Close and reopen
PowerShell after installation, then verify every prerequisite:

```powershell
py -3.14 -c "import platform; print(platform.python_version(), platform.machine())"
az version
terraform version
git --version
```

Python must report `AMD64`, not `ARM64`.

macOS uses Homebrew:

```bash
brew update
brew install python@3.14 azure-cli git
brew tap hashicorp/tap
brew install hashicorp/tap/terraform
python3.14 --version
az version
terraform version
git --version
```

See the complete
[workstation prerequisites](DEPLOY.md#workstation-prerequisites) for version,
network, local-state, and alternative-installation requirements.

### 2. Clone or update the repository

For a new deployment workstation:

```bash
git clone https://github.com/ktigges/MDVM-View.git
cd MDVM-View
git branch --show-current
```

The release branch should be `latest`. On an existing deployment clone:

```bash
git switch latest
git pull --ff-only
```

On macOS, create the project environment before running the menu:

```bash
python3.14 -m venv .venv
./.venv/bin/python -m pip install -e '.[dev]'
```

On Windows, the PowerShell menu creates `.venv-win`, installs Vulnerability
View and its Python deployment dependencies, and verifies the operations CLI
before showing the menu.

### 3. Configure the target environment

Before the first deployment, create both environment-specific configuration
files from their tracked examples:

```powershell
Copy-Item .\infra\terraform\main.tfvars.example.json .\infra\terraform\main.tfvars.json
Copy-Item .\.env.example .\.env
```

Some values intentionally appear in both files. `main.tfvars.json` is
authoritative for Azure infrastructure and the hosted Function and Web App;
`.env` controls only local commands and local application processes. When a
local process targets the deployed environment, copy the same tenant,
subscription, management-group, resource-group, location, history Storage, and
collection-policy values into the corresponding `.env` settings. Do not put
the Function runtime storage account in `.env`. Neither environment-specific
file is committed. See the
[configuration overlap table](DEPLOY.md#terraform-and-env-overlap) before
running the menu.

At minimum, replace or confirm these environment-specific values in
`infra/terraform/main.tfvars.json` before selecting option 1:

| Terraform setting | Required value |
|---|---|
| `subscription_id` | Subscription GUID where the application resources will be deployed |
| `tenant_id` | Target Microsoft Entra tenant GUID |
| `collector_management_group_id` | Actual management-group ID; use the tenant GUID for Tenant Root Group and replace the template placeholder |
| `resource_group_name` | Deployment resource-group name |
| `location` | Approved Azure region |
| `history_storage_account_name` | Globally unique protected-history Storage account name |
| `function_runtime_storage_account_name` | Globally unique replaceable Function runtime Storage account name |
| `function_app_name` | Globally unique Function App name |
| `web_app_name` | Globally unique Web App name |
| `web_app_service_plan_name` | App Service plan name |
| `web_app_identity_name` | Dashboard managed-identity name |
| `network_security_perimeter_allowed_ip_cidrs` | Approved source CIDRs, or the documented initial `0.0.0.0/0` value while perimeter behavior is validated |

#### Choose unique deployment names

Before running option 1, replace `replace123` everywhere in
`main.tfvars.json` with one short, consistent suffix for this deployment, such
as `a1b2c3`. Use lowercase letters and numbers so the same suffix is valid in
Storage account names. Do not use an email address, tenant name, organization
name, or other sensitive identifier. The deployment preflight rejects the
unchanged template naming placeholders.

| Setting | Required uniqueness |
|---|---|
| `resource_group_name` | Unique within the selected subscription. Use a new name for a parallel environment; reusing a name targets that existing resource group. |
| `project_name` plus `environment` | Must not collide with generated Function plan, identity, Log Analytics, or Application Insights names in the resource group. |
| `history_storage_account_name` | Globally unique across Azure. Never point a new environment at an existing protected-history account. |
| `function_runtime_storage_account_name` | Globally unique across Azure. |
| `function_app_name` | Globally unique across Azure because it forms an `azurewebsites.net` hostname. |
| `web_app_name` | Globally unique across Azure because it forms an `azurewebsites.net` hostname. |
| `web_app_service_plan_name` | Unique within the resource group. |
| `web_app_identity_name` | Unique within the resource group. |
| `dashboard_entra_application_name` | Microsoft Entra permits duplicate display names, but use a distinct name so operators can identify the correct App Registration and Enterprise Application. |
| `history_container_name`, `current_container_name`, `dashboard_recommendation_tracking_container` | Each must be distinct within the history Storage account. These names can be reused in a different Storage account. |

The `.env` file does not create another set of Azure resources. Copy the exact
resource-group, history Storage account, and container names from
`main.tfvars.json`; do not add a different prefix or suffix only in `.env`.

The deployment identity must also be able to create role assignments at the
configured management group. Microsoft Entra Global Administrator alone is not
enough; use Owner, Role Based Access Control Administrator, or User Access
Administrator at that management-group scope.

For a production environment, have an existing Azure RBAC administrator grant the
deployment identity **Role Based Access Control Administrator** or **User
Access Administrator** at only the required management-group scope. For a
net-new test tenant where the signed-in Global Administrator cannot create the
collector Reader assignment:

1. In the Azure portal, open **Microsoft Entra ID > Properties**.
2. Set **Access management for Azure resources** to **Yes** and save.
3. Refresh the Azure CLI token and restore the intended subscription:

   ```powershell
   az logout
   az login --tenant "<tenant-guid>"
   az account set --subscription "<subscription-guid>"
   az account show --output table
   ```

4. Rerun deployment-menu option 1. Terraform will retain successfully created
   resources and retry the failed role assignment; do not delete or reset the
   partial deployment.
5. After deployment succeeds, set **Access management for Azure resources**
   back to **No** when the temporary root-scope elevation is no longer needed.

If the required Azure role is assigned through Privileged Identity Management,
activate it before deployment and refresh the Azure CLI token afterward.

The deployment menu reads `main.tfvars.json` directly and does not require
`.env` merely to run Terraform. For local live collection, local dashboard
testing, or local diagnostics against the same deployed environment,
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

### 4. Authenticate and start the menu

Sign in and confirm the intended tenant and subscription:

```bash
az login --tenant "<tenant-guid>"
az account set --subscription "<subscription-guid>"
az account show --output table
```

Then start the menu from the repository root.

macOS:

```bash
./infra/deployment-menu.sh
```

Windows:

```powershell
.\infra\deployment-menu.ps1
```

Choose the menu entry that describes the work being performed. For a first
installation or complete update, use **Complete initial deployment or update**.
Before Terraform planning begins, options 1 and 2 run a deployment permission
preflight. It verifies the active Azure CLI tenant and subscription, access to
the configured management group, effective resource and role-assignment write
permissions, and an active Global Administrator or Privileged Role
Administrator directory role. The menu stops with the missing scope or action
when a requirement is not met.
Review every Terraform plan and approve it only when it contains the expected
changes and preserves retained history.

After deployment, assign approved users or groups the **Dashboard Viewer** role
under **Enterprise applications > DVM Viewer > Users and groups**. Assign
specialized roles separately when required.

See the [Azure deployment guide](DEPLOY.md) for prerequisites, permissions,
configuration, identities, networking, and protected-history boundaries.

### Repeat a first-time deployment safely

If a collection has run, do not delete the existing resource group to start
over. It contains the protected history Storage account, and deleting the group
would delete retained evidence. Create a parallel environment instead.

If this is an intentionally disposable test installation, no collection has
ever run, the history containers contain no retained run data, and deletion of
the exact resource group has been explicitly approved, a manual clean reinstall
is possible. Do not delete the local clone first. Its Terraform state identifies
objects that live outside the resource group:

- The dashboard Microsoft Entra application and Enterprise Application.
- The collector Reader role assignment at management-group or subscription
  scope.
- Defender and Microsoft Graph app-role assignments associated with the
  collector identity.

Record and remove the approved test objects at their actual scopes, then remove
the resource group, and only then discard the local clone. Pull `latest` into a
new folder, recreate the two environment-specific configuration files, sign in,
and run option 1. Deleting only the resource group and local clone can leave
orphaned directory objects and duplicate application registrations.

To preserve an existing environment while testing a completely new first-time
deployment:

1. Clone `latest` into a new local folder so it has separate Terraform state.
2. Create new `.env` and `infra/terraform/main.tfvars.json` files from the
   examples.
3. Use a new resource-group name and new globally unique history Storage,
   Function runtime Storage, Function App, and Web App names.
4. Keep the original protected-history resource group and Storage account
   unchanged.
5. Run menu option 1 from the new clone and validate the parallel environment.

If the goal is only to retest application publishing, keep the existing
environment and use option 3 or 4. Decommissioning any old test environment is
a separate reviewed operation; never delete a resource group that contains
retained DVM history without explicit approval of that exact target and a
history-preservation plan.

### Safely remove and rebuild the application

The application teardown scripts remove the replaceable Function, Web App,
Function runtime Storage, identities, monitoring resources, dashboard directory
application, and related assignments. They preserve the resource group,
protected history Storage and containers, protected workflow container,
network-perimeter foundation, and local Terraform state.

Windows:

```powershell
.\infra\destroy-application.ps1
```

macOS:

```bash
./infra/destroy-application.sh
```

The scripts run the deployment permission preflight, create and machine-validate
a Terraform teardown plan, display the complete plan, and require four exact
confirmations:

1. `REVIEWED PLAN`
2. The exact resource-group name
3. The exact Web App name
4. `REMOVE REPLACEABLE APPLICATION`

The plan is rejected if it creates, updates, replaces, or deletes anything
outside the explicit replaceable-application allowlist. After teardown, run
deployment-menu option 1 to recreate and publish the Function and Web App on
the preserved foundation.

### Permanently delete a disposable test environment

Do not use this workflow for an environment containing history that must be
retained. After a human has approved deletion of the exact resource group and
all history inside it, the separate test-only scripts remove Terraform-managed
application and directory resources and then delete the configured resource
group:

Windows:

```powershell
.\infra\destroy-test-environment.ps1
```

macOS:

```bash
./infra/destroy-test-environment.sh
```

The script verifies that Azure CLI is using the subscription configured in
`main.tfvars.json`, displays the application teardown plan and every resource
currently in the resource group, and requires four exact confirmations:

1. `DELETE TEST ENVIRONMENT`
2. The exact subscription ID
3. The exact resource-group name
4. `PERMANENTLY DELETE <resource-group-name>`

It then removes any remaining Terraform-managed Function, Web App, identities,
Microsoft Entra objects, and cross-scope assignments before running an exact
resource-group deletion. This permanently deletes the protected history
Storage account, every container, all immutable and current history, and every
other resource in that group. The script verifies that Azure reports the
resource group absent. Local configuration and Terraform state files remain;
the script does not recursively delete the local repository.

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
procedures are intentionally separated from the hosted deployment path. See
the [Local development README](docs/local/README.md) only when performing local
or development work.
