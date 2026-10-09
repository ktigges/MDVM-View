# Azure deployment guide

> **Last modified:** 2026-10-08
> **Purpose:** Deploy and validate protected storage, the collector Function, and the authenticated dashboard Web App, with explicit operator and runtime identity boundaries.

The deployment is staged so retained DVM history stays independent of
replaceable application infrastructure.

The protected foundation and collector Function are identical whether the Web
App runs locally or in Azure. A hosted deployment simply adds the cumulative
`webapp` stage; it does not create a second foundation or a different
collector.

For the complete inventory of Terraform inputs, runtime environment variables,
JSON keys, generated Azure App Settings, SLA controls, presentation settings,
and script overrides, see
[Complete configuration reference](docs/configuration-reference.md).
For all supported local, collection, deployment, validation, and diagnostic
commands, including when each is safe to use, see
[Command reference](docs/command-reference.md).
For the command-by-command internals, tool dependencies, Azure CLI identity
behavior, Terraform boundaries, and package contents of `infra/deploy.sh`, see
[Infrastructure and deploy.sh reference](infra/README.md).

## Collector and local Web App customer quick start

This installs protected history storage and the collection Function. It does
not deploy the dashboard Web App to Azure. The Web App runs locally and reads
the collector's current live dataset from Azure Storage.

1. Clone the repository and enter its directory:

   ```bash
   git clone "<repository-url>"
   cd MDVM-View
   ```

2. Install the [workstation requirements](#workstation-requirements), create a
   virtual environment, and install the project. On Windows, create and
   activate `.venv-win`:

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
   Windows, macOS, and Linux and does not depend on the shell finding a
   generated `vulnerability-view-ops.exe` launcher.

   After activation, Windows uses the same
   `python -m vulnerability_view.operations_cli <command>` form. If PowerShell
   cannot activate the environment, use the exact `.venv-win` interpreter path
   as a fallback.

3. Copy `infra/terraform/main.tfvars.example.json` to the environment-specific
   `infra/terraform/main.tfvars.json` and replace every example value. Set
   `collector_management_group_id` to the management group ID, not its display
   name or full resource path. `subscription_id` still identifies the
   subscription where Terraform creates the application resources.

   For **Tenant Root Group**, the management-group ID is the Microsoft Entra
   tenant GUID. In that case, `tenant_id` and
   `collector_management_group_id` contain the same GUID. Do not enter the
   display name `Tenant Root Group`.

   Keep `network_security_perimeter_enabled=true` for the default customer
   deployment. The initial `network_security_perimeter_allowed_ip_cidrs` value
   is `["0.0.0.0/0"]`, which does not restrict IPv4 source addresses yet.
   Microsoft Entra authentication and Storage RBAC still protect every data
   request. Replace that value with approved operator CIDRs when the customer
   is ready to restrict source networks.

   The customer's Azure Policy must allow
   `publicNetworkAccess=SecuredByPerimeter`. A policy that unconditionally
   changes Storage public network access to `Disabled` must be updated or
   exempt the NSP-associated Storage accounts.

4. Before signing in, planning, or deploying, copy `.env.example` to `.env`
   and set these environment variables:

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

   Leave `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` empty. “Client ID” and
   “Application ID” refer to the same Entra application identifier, and neither
   is required for the normal deployment/local Web App path. Terraform
   configures the Azure managed identities, while the local Web App uses the
   current `az login` identity.

   `AUTH_MODE=auto` is the normal Azure authentication setting: it uses the
   current Azure CLI login locally and managed identity when hosted. Keep
   `APP_MODE=live`. Local hosting requires `DASHBOARD_AUTH_ENABLED=false`;
   Terraform enables App Service Authentication for the hosted Web App.
   Recommendation tracking is optional dashboard-only collaboration state and
   should remain false unless explicitly required.

   Use these value sources:

   | `.env` setting | Value to use |
   |---|---|
   | `AUTH_MODE` | `auto` |
   | `AZURE_TENANT_ID` | Leave empty; use the tenant from `az login` |
   | `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` | Leave both empty |
   | `AZURE_SUBSCRIPTION_ID` | Leave empty; Terraform reads `subscription_id` from `main.tfvars.json` |
   | `AZURE_MANAGEMENT_GROUP_ID` | Leave empty; Terraform sets it on the collector from `collector_management_group_id` |
   | `AZURE_RESOURCE_GROUP` | Leave empty; deployment commands use the Terraform value |
   | `STORAGE_ACCOUNT_NAME` | `history_storage_account_name` from `main.tfvars.json` |
   | `STORAGE_CONTAINER_NAME` | `history_container_name`, normally `dvm-history` |
   | `STORAGE_CURRENT_CONTAINER_NAME` | `current_container_name`, normally `dvm-current` |
   | `APP_MODE` | `live` |
   | `DASHBOARD_DATA_SOURCE` | `azure` |
   | `DASHBOARD_AUTH_ENABLED` | `false` locally |
   | `DASHBOARD_RECOMMENDATION_TRACKING_ENABLED` | `false` unless explicitly required |

   After Terraform apply, confirm the Storage values with:

   ```bash
   python -m vulnerability_view.operations_cli output history_storage_account_name
   python -m vulnerability_view.operations_cli output history_container_name
   python -m vulnerability_view.operations_cli output current_container_name
   ```

   See the [complete runtime setting reference](docs/configuration-reference.md#4-collector-and-dashboard-runtime-settings)
   for all optional `.env` values.

5. Confirm that the deployment identity has the
   [required operator permissions](#required-operator-permissions), then sign
   in:

   ```bash
   az login --tenant "<tenant-id>"
   az account set --subscription "<subscription-id>"
   az account show --query "{name:name,id:id,tenantId:tenantId}" --output table
   ```

6. Create the protected storage foundation:

   ```bash
   python -m vulnerability_view.operations_cli plan foundation
   python -m vulnerability_view.operations_cli show foundation
   python -m vulnerability_view.operations_cli apply foundation
   python -m vulnerability_view.operations_cli verify foundation
   ```

7. Create and publish the collector:

   ```bash
   python -m vulnerability_view.operations_cli plan function
   python -m vulnerability_view.operations_cli show function
   python -m vulnerability_view.operations_cli apply function
   python -m vulnerability_view.operations_cli deploy function
   python -m vulnerability_view.operations_cli verify function
   ```

   The shared foundation and collector are now complete. Step 8 publishes the
   first dataset for either Web App path.

8. Wait for the configured schedule, or create the first immutable run now:

   ```bash
   python -m vulnerability_view.operations_cli invoke function --confirm
   python -m vulnerability_view.operations_cli check-runs --limit 5 --progress
   ```

   To use the local Web App, continue with step 9. To host the Web App in Azure,
   skip step 9 and continue with the
   [Web App stage](#deploy-the-authenticated-dashboard-web-app).

9. Run the Web App locally:

   ```bash
   python -m uvicorn vulnerability_view.dashboard_server:app --app-dir src --host 127.0.0.1 --port 8000 --reload --reload-dir src --reload-dir dashboard
   ```

   Open <http://127.0.0.1:8000>. The local Web App uses the current Azure CLI
   credential to read the current manifest and curated data from Azure Storage.
   The deployed collector continues to use its own managed identity.

Stop here for a collector-only installation. Do not run the `webapp` stage.
The operator supplies the Terraform values and an authorized Azure CLI login;
the deployment commands create the Azure resources, collector managed identity,
RBAC assignments, Defender/Graph application permissions, monitoring, Function
settings, and collector package.

## Deployment path

Follow this order:

1. Confirm [workstation requirements](#workstation-requirements).
2. Confirm [required operator permissions](#required-operator-permissions).
3. Create and review `infra/terraform/main.tfvars.json`.
4. Sign in and confirm the target tenant/subscription.
5. Deploy the protected foundation.
6. Deploy the collector Function.
7. Run and validate one collection.
8. Deploy the authenticated dashboard Web App.
9. Assign authorized dashboard users/groups.
10. Use the [operations guide](docs/operations-and-configuration.md) and
    [troubleshooting guide](docs/troubleshooting.md).

The stages are cumulative. After the Web App exists, later Terraform plans
should use the `webapp` stage so the plan preserves the foundation, Function,
and Web App together.

## Workstation requirements

The deployment workstation needs:

- Terraform 1.10 or newer, either on `PATH` or as `terraform.exe` in the
  repository root on Windows;
- Azure CLI authenticated to the target tenant and subscription;
- Python 3.12 or the tested Python 3.14.7 local runtime, with the project
  virtual environment;
- Git;
- outbound access required by Terraform providers, Azure CLI, package restore,
  and code deployment.

For Windows without a `PATH` change, download the official Terraform Windows
ZIP, verify it according to the customer's software-installation policy, and
extract `terraform.exe` into the repository root beside `README.md`. Do not put
it in `infra/terraform/`. The operations CLI checks the repository-local
executable before checking `PATH`, and `.gitignore` prevents the binary from
being committed.

Terraform stores state locally at `infra/terraform/terraform.tfstate` on the
deployment workstation. Protect and retain that file because it records the
managed resources and may contain sensitive deployment values. A shared remote
state backend can be used, but it requires separate Terraform backend
configuration and is not part of this deployment documentation.

Install the application dependencies:

macOS or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

Windows PowerShell:

```powershell
python3 --version
python3 -m venv .venv-win
.\.venv-win\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -c "import sys, vulnerability_view; print(sys.executable)"
```

If `python3` is not available on Windows, use `py -3.14` for the first two
commands.

The last command must print a path ending in
`.venv-win\Scripts\python.exe`. If the import fails or it prints a global
Python path, stop before deployment and reactivate `.venv-win`. Once activated,
Windows, macOS, and Linux all use
`python -m vulnerability_view.operations_cli`. If activation is blocked, use
`.\.venv-win\Scripts\python.exe -m vulnerability_view.operations_cli` as a
fallback. Both forms are documented in
[Infrastructure operations](infra/README.md).

Python 3.14.7 has been tested successfully for local installation, deployment
operations, and the full project test suite. The test run produces dependency
deprecation warnings but no failures. Terraform continues to configure the
Azure Function and Linux Web App runtimes for Python 3.12. Using Python 3.14.7
on the workstation does not change those deployed runtimes.

## What the deployment commands do

`python -m vulnerability_view.operations_cli` runs the Terraform, Azure CLI, packaging, and
verification steps for you. The deployment remains separated into operations
so you can review infrastructure changes before applying them:

```text
plan infrastructure -> review saved Terraform plan -> apply reviewed plan
                    -> publish application code -> verify deployed resource
```

You do **not** need to run `terraform init` manually before a `plan` command.
Every `python -m vulnerability_view.operations_cli plan <stage>` invocation automatically runs:

1. `terraform init -input=false`
2. `terraform validate`
3. `terraform plan`, saved as `infra/terraform/<stage>.tfplan`

Planning and applying remain deliberately separate. `plan` never applies
infrastructure, and `apply` never creates or refreshes a plan. Review and
apply the exact saved plan:

```bash
python -m vulnerability_view.operations_cli plan webapp
python -m vulnerability_view.operations_cli show webapp
python -m vulnerability_view.operations_cli apply webapp
```

`deploy` is a code-package operation. It does not run Terraform `init`, `plan`,
or `apply`. It expects the selected Function or Web App infrastructure and
Terraform outputs to already exist. For a dashboard code-only update to an
existing Web App, use:

```bash
python -m vulnerability_view.operations_cli deploy webapp
python -m vulnerability_view.operations_cli verify webapp
```

Use `deploy function` and `deploy webapp` independently. Updating one application
does not publish, restart, or invoke the other. Publishing Function code also
does not start a collection.

## Consolidated deployment runbook

Use this table to choose the smallest operation that matches the change:

| Situation | Commands | Run a collection? |
|---|---|---|
| First deployment | Run `plan`, review, `apply`, and `verify` for `foundation`; repeat with `deploy` added for `function` and `webapp` | Run `invoke function --confirm` only if data is needed immediately |
| Collector infrastructure or permissions changed | `plan function`, review, `apply function`, `deploy function`, `verify function` | Only when an immediate fresh snapshot is needed |
| Collector Python changed, infrastructure did not | `deploy function`, then `verify function` | No; wait for the schedule unless fresh data is needed |
| Web App infrastructure, Easy Auth, roles, or settings changed | `plan webapp`, review, `apply webapp`, `deploy webapp`, `verify webapp` | No |
| Dashboard or dashboard-server code changed | `deploy webapp`, then `verify webapp` | No |
| Recommendation tracking enabled persistently | Set `dashboard_recommendation_tracking_enabled=true`; `plan webapp`, review, `apply webapp`, `deploy webapp`, `verify webapp` | No |
| A fresh Defender snapshot is needed immediately | `invoke function --confirm`, then `verify function` | This is the collection |

All abbreviated commands in this table are subcommands of
`python -m vulnerability_view.operations_cli`.

All Terraform stages are cumulative. Once the Web App exists, use the `webapp`
stage for later infrastructure plans so Terraform preserves the foundation,
Function, and Web App together. Never apply a plan that deletes the protected
history account, its retained containers, or their data.

After Terraform creates the Enterprise Application, assign authorized users or
groups manually at **Microsoft Entra admin center > Enterprise applications >
DVM Viewer > Users and groups**:

- Assign **Dashboard Viewer** to everyone who may open the application.
- Assign **Data Evidence Reader** only to users or groups that may use the
  hidden Data evidence browser.

Terraform does not create an access group and does not manage these
assignments.

## Storage-account separation

The two storage-account variables serve different security and lifecycle
purposes:

| Terraform variable | Example | Purpose | Application setting |
|---|---|---|---|
| `history_storage_account_name` | `sadvmviewerdata` | Retains immutable raw responses, curated datasets, run manifests, and the current manifest pointer. This is application data and must survive Function replacement. | `STORAGE_ACCOUNT_NAME` |
| `function_runtime_storage_account_name` | `sadvmviewerfunc001` | Stores Azure Functions host state and deployment packages. It is operational infrastructure, not vulnerability history. | Managed by Terraform through `AzureWebJobsStorage__*`; do not put this account in `.env`. |

For the supplied example values, local application configuration is:

```dotenv
STORAGE_ACCOUNT_NAME=sadvmviewerdata
STORAGE_CONTAINER_NAME=dvm-history
STORAGE_CURRENT_CONTAINER_NAME=dvm-current
```

The dashboard, local CLI, replay, migration, and collector data pipeline all use
the history account. The runtime account is used only by the Azure Functions
platform. Local Functions host testing uses
`AzureWebJobsStorage=UseDevelopmentStorage=true` with Azurite instead.

Never configure `STORAGE_ACCOUNT_NAME` with the Function runtime account.

## Inputs and local files

Copy the example Terraform values file and replace every sample value:

```bash
cp infra/terraform/main.tfvars.example.json infra/terraform/main.tfvars.json
```

The deployment helper requires
`infra/terraform/main.tfvars.json`. Keep environment values, plans, and state
files out of source control. The supplied configuration writes local state to
`infra/terraform/terraform.tfstate`. Keep that file on the authoritative
deployment workstation and include it in the organization's protected backup
process. Do not store it in the protected DVM history account.

Organizations that require shared state can configure a separate remote
Terraform backend. Backend provisioning, access control, migration, and
recovery are not included in this deployment documentation.

The wrapper supplies the cumulative deployment-stage values:

- `plan foundation` disables the Function and Web App.
- `plan function` enables the Function and keeps the Web App disabled.
- `plan webapp` enables both the Function and Web App as the cumulative stage.

`grant_deployer_history_access=true` grants the identity executing Terraform
Storage Blob Data Contributor on the new history account. With interactive
Azure CLI authentication, this is the currently signed-in local operator. Keep
it enabled when that operator will run status, restore, backfill, or synthetic
seeding commands.

`config/vulnerability-view.example.json` is an optional local CLI configuration
template. It is not read by Terraform and is not packaged into the Function.
Azure Function runtime settings are created by Terraform as Function App
application settings.

## Network Security Perimeter option

Azure deployments enable a Network Security Perimeter (NSP) by default. The
foundation stage creates one perimeter and one Storage profile, then associates
the protected history account. The Function stage associates the separate
Function runtime account with the same profile. After each association exists,
Terraform uses the Azure API provider to set that Storage account's public
network access to `SecuredByPerimeter`; creating the association alone does not
change an account that customer policy previously set to `Disabled`.

The NSP provides these benefits without requiring a VNet or private endpoints:

- Centralizes the network boundary for both Storage accounts.
- Allows customer policy to use
  `publicNetworkAccess=SecuredByPerimeter` instead of unrestricted `Enabled`.
- Explicitly permits the deployment subscription so the Function, hosted Web
  App, and Azure deployment service can reach Storage.
- Preserves Microsoft Entra authentication, managed identities, private
  containers, and Storage data-plane RBAC as the authorization controls.
- Provides a controlled path to restrict operator access to approved public
  CIDRs later without redesigning the application.

Configure the option in `infra/terraform/main.tfvars.json`:

```json
{
  "network_security_perimeter_enabled": true,
  "network_security_perimeter_access_mode": "Enforced",
  "network_security_perimeter_allowed_ip_cidrs": [
    "0.0.0.0/0"
  ]
}
```

`0.0.0.0/0` intentionally leaves IPv4 source addresses unrestricted during the
initial deployment. It does not make containers or blobs anonymous. Replace it
with approved corporate or operator egress CIDRs when the customer is ready to
enforce source-IP restrictions.

The customer Azure Policy must permit
`publicNetworkAccess=SecuredByPerimeter`. A policy that always changes Storage
public network access to `Disabled` must be updated or exempt the two
NSP-associated Storage accounts. Otherwise, Function ZIP deployment and
application Storage access remain blocked.

To add the NSP to an environment where the Function infrastructure already
exists, create a new cumulative Function plan:

```bash
python -m vulnerability_view.operations_cli plan function
python -m vulnerability_view.operations_cli show function
python -m vulnerability_view.operations_cli apply function
```

Review the plan before applying it. It should add the perimeter, profile,
rules, two Storage associations, and two in-place
`SecuredByPerimeter` updates without replacing either Storage account. After
apply, both accounts should report `SecuredByPerimeter`. Then publish and verify
the Function:

```bash
python -m vulnerability_view.operations_cli deploy function
python -m vulnerability_view.operations_cli verify function
```

Set `network_security_perimeter_enabled=false` only when customer policy allows
ordinary public Storage access and the customer explicitly chooses not to use
the perimeter.

## Required operator permissions

For a collector-only installation, the identity running Terraform needs:

- **Azure RBAC:** Owner on the target subscription. The supported split is
  Contributor plus Role Based Access Control Administrator or User Access
  Administrator.
- **Management group scope:** Owner, Role Based Access Control Administrator,
  or User Access Administrator on the management group configured in
  `collector_management_group_id`, because Terraform grants the collector
  Reader once at that scope.
- **Microsoft Entra:** an active **Privileged Role Administrator** assignment
  when applying the Function stage. Microsoft requires this role when granting
  Microsoft Graph or other Microsoft first-party application permissions to a
  managed identity.
- Permission to read the Microsoft Defender for Endpoint and Microsoft Graph
  enterprise applications.

The same signed-in identity is used by the AzureRM and AzureAD Terraform
providers, so it must have both the Azure RBAC and Microsoft Entra permissions
while `apply function` runs. If Privileged Identity Management is used,
activate the required role before planning and applying the Function stage.

Terraform then grants the collector managed identity:

- Microsoft Defender for Endpoint `Machine.Read.All`;
- Microsoft Defender for Endpoint `Vulnerability.Read.All`;
- Microsoft Defender for Endpoint `SecurityRecommendation.Read.All`;
- Microsoft Graph `SecurityEvents.Read.All`;
- Reader on the configured management group, inherited by all nested
  subscriptions;
- the Storage and monitoring roles listed under
  [Runtime identities and permissions](#runtime-identities-and-permissions).

No collector client secret, customer username, or password is created or stored.

Uploading existing local history requires Storage Blob Data Contributor on the
history account. The foundation assigns this automatically to the Terraform
execution identity when `grant_deployer_history_access=true`. Azure subscription
Owner or Contributor alone does not automatically provide Blob data-plane
access.

The hosted collector uses its user-assigned managed identity and has no client
secret.

The later Web App stage additionally requires permission to create an Entra
application and Enterprise Application. App Service Easy Auth requires a
dashboard application credential; Terraform creates it and stores the sensitive
value in the secured Terraform state and Web App application settings.
Whoever assigns dashboard users or groups needs permission to manage the
Enterprise Application. Global Administrator is sufficient; use narrower
authorized roles when organizational policy requires them.

## Runtime identities and permissions

Terraform uses the signed-in operator only for deployment and explicitly
requested local storage operations. Hosted workloads use separate user-assigned
managed identities:

| Identity | Permission | Scope and purpose |
|---|---|---|
| Collector | Reader | Management group in `collector_management_group_id`; inventories all nested subscriptions, including subscriptions added later |
| Collector | `Machine.Read.All`, `Vulnerability.Read.All`, `SecurityRecommendation.Read.All` | Microsoft Defender for Endpoint application access |
| Collector | `SecurityEvents.Read.All` | Microsoft Graph Secure Score application access |
| Collector | Storage Blob Data Contributor | Protected history account; appends runs and advances only the current manifest pointer |
| Collector | Storage Blob Data Owner, Storage Blob Data Contributor, Storage Queue Data Contributor, Storage Table Data Contributor | Dedicated Function runtime account |
| Collector | Monitoring Metrics Publisher | Application Insights |
| Dashboard | Storage Blob Data Reader | Protected history account; reads the current manifest and referenced curated datasets |
| Dashboard | Storage Blob Data Contributor | Private `dvm-workflow` container only; appends and reads shared workflow events when the application setting enables tracking |
| Dashboard users | Roles assigned manually in the Enterprise Application | `Dashboard.Viewer` is required; `Data.Evidence.Reader` authorizes the optional evidence browser; local recommendation workflow needs no additional role |

The dashboard identity receives no Defender or Microsoft Graph permission and
cannot write to retained history or the current manifest. Its only storage
write scope is the separate workflow container; the application does not access
that container while recommendation tracking is disabled.

## Deployment packages

Terraform creates infrastructure but does not publish application source.

`python -m vulnerability_view.operations_cli deploy function` builds `function-source.zip`, uploads
it to the existing Function App with Azure CLI remote build, stamps the
configured collector version, and synchronizes the Function triggers.

`python -m vulnerability_view.operations_cli deploy webapp` builds `webapp-source.zip`, stamps the
operator-managed `dashboard_version` and deployment time, uploads the package,
and waits for Azure to report the final deployment result. The dashboard header
shows both the release version and deployment time.

Both ZIP files are local build artifacts and must not be committed.

## Resource inventory

### Stage 1: protected foundation

`plan foundation` and `apply foundation` create:

1. One resource group.
2. One ADLS Gen2 history storage account:
   - StorageV2 with hierarchical namespace enabled.
   - HTTPS-only and TLS 1.2 minimum.
   - Shared-key access disabled.
   - Public blob access disabled.
   - Associated with the default Storage Network Security Perimeter profile.
   - Every request still requires Microsoft Entra authentication and Storage
     data-plane RBAC.
   - Configurable LRS, ZRS, GRS, or GZRS replication.
   - Blob and container soft delete, 30 days by default.
   - Terraform `prevent_destroy`.
3. One Network Security Perimeter and shared Storage profile:
   - Enabled by default through `network_security_perimeter_enabled`.
   - The deployment subscription is allowed for Function, hosted Web App, and
     Azure deployment-service Storage traffic.
   - IPv4 source addresses are initially unrestricted through `0.0.0.0/0`.
   - Association mode defaults to `Enforced`.
4. One private history container, `dvm-history` by default:
   - Holds append-only `raw/`, `curated/`, and `runs/` paths.
   - An unlocked 365-day time-based immutability policy protects existing and
     newly written blobs from modification or deletion during their retention period.
   - Terraform `prevent_destroy`.
5. One private current-pointer container, `dvm-current` by default:
   - Holds only `current/manifest.json`.
   - Has no immutability policy because the pointer must be replaceable.
   - Terraform `prevent_destroy`.
6. Storage Blob Data Contributor on the history account for the identity running
   Terraform when `grant_deployer_history_access=true`.

Soft delete and WORM serve different purposes. The 30-day soft-delete window
allows recovery after an eligible blob or container is deleted; it never
deletes an active blob, but Azure permanently expires the already-deleted copy
after that recovery window. The 365-day WORM policy prevents history blobs from
being modified or deleted in the first place. WORM expiration does not delete
history, and no lifecycle deletion policy is configured.

Keep `lock_history_immutability_policy=false` while validating collection and
recovery. Locking the policy is a separate irreversible decision: after it is
locked, the policy cannot be removed and its retention period cannot be
shortened.

The foundation stage does not create the Function, managed identity, monitoring,
or Function runtime account.

### Stage 2: collector Function

`plan function` and `apply function` retain the foundation and add:

1. One Flex Consumption service plan using SKU `FC1`.
2. One Linux Flex Consumption Function App:
   - Python 3.12.
   - 2,048 MB instance memory.
   - Maximum one instance.
   - No always-ready instance configured.
   - HTTPS-only with TLS 1.2 minimum.
   - Public network access enabled.
3. One separate StorageV2 Function runtime account:
   - Used for host state and deployment packages only.
   - Shared-key access disabled.
   - Public blob access disabled.
   - Associated with the same Storage Network Security Perimeter profile for
     Function hosting and code deployment.
   - Anonymous blob access remains disabled.
   - Seven-day blob and container soft delete.
4. One private `function-releases` container in the runtime account.
5. One user-assigned collector managed identity attached to the Function App.
6. Runtime-account role assignments for the collector identity:
   - Storage Blob Data Owner.
   - Storage Blob Data Contributor.
   - Storage Queue Data Contributor.
   - Storage Table Data Contributor.
7. Storage Blob Data Contributor for the collector identity on the protected
   history account.
8. Microsoft Defender for Endpoint application-role assignments:
   - `Machine.Read.All`.
   - `Vulnerability.Read.All`.
   - `SecurityRecommendation.Read.All`.
9. Microsoft Graph application-role assignment:
   - `SecurityEvents.Read.All`.
10. One Log Analytics workspace with 30-day retention.
11. One workspace-based Application Insights resource.
12. Monitoring Metrics Publisher for the collector identity on Application
    Insights.
13. One Function diagnostic setting that sends all logs and metrics to the Log
    Analytics workspace.

Terraform configures these Function application settings:

| Setting | Source |
|---|---|
| `AUTH_MODE` | Fixed to `managed_identity` |
| `AZURE_CLIENT_ID` | Collector managed-identity client ID |
| `AzureWebJobsStorage__accountName` | Function runtime account |
| `AzureWebJobsStorage__clientId` | Collector managed-identity client ID |
| `AzureWebJobsStorage__credential` | Fixed to `managedidentity` |
| `COLLECTION_SCHEDULE` | `collection_schedule` |
| `DEFENDER_API_BASE_URL` | `https://api.security.microsoft.com` |
| `FULL_ENRICHMENT_WEEKDAY` | `full_enrichment_weekday` |
| `RECOMMENDATION_ENRICHMENT_MODE` | `recommendation_enrichment_mode` |
| `ENABLE_EXPERIMENTAL_ENDPOINTS` | `enable_experimental_endpoints`; keep `false` unless explicitly testing undocumented compatibility routes |
| `APP_MODE` | `app_mode`; deployed values are `live` or `combined`. `live` publishes only collected Defender data; `combined` carries retained synthetic rows into new live runs. Local build commands also support `synthetic` |
| `STORAGE_ACCOUNT_NAME` | History storage account |
| `STORAGE_CONTAINER_NAME` | History container |
| `STORAGE_CURRENT_CONTAINER_NAME` | Current-pointer container |

The application code contains no Azure Storage delete operation. Historical
paths are append-only. Only `current/manifest.json` is replaceable.

### Stage 3: authenticated dashboard Web App

`plan webapp` and `apply webapp` retain the foundation and Function and add:

1. One Linux B1 App Service plan and Web App.
2. One dedicated user-assigned managed identity.
3. Storage Blob Data Reader on the history account for that identity.
4. A private recommendation-workflow container and Storage Blob Data
   Contributor for the dashboard identity on that container only.
5. One single-tenant Entra app registration and Enterprise Application named
   `DVM Viewer`.
6. `Dashboard.Viewer` and `Data.Evidence.Reader` app roles for manual
   assignment. `Recommendation.Tracker` remains defined for existing
   assignments, but the current workflow does not require it.
7. Assignment-required Enterprise Application access.
8. App Service Easy Auth with unauthenticated requests redirected to Entra.
9. Azure-backed FastAPI settings, a 300-second current-manifest refresh interval,
   and per-dataset caching for the active immutable run.

The Enterprise Application display name is `DVM Viewer`; the app registration
uses the same name. After apply, Terraform outputs
`dashboard_enterprise_application_object_id` and
`dashboard_entra_client_id` identify it. Manage assignments at **Microsoft
Entra ID > Enterprise applications > DVM Viewer > Users and groups**.

The configured Web App name must be globally available when the Web App stage
is applied.
Group-based Enterprise Application assignment requires the applicable
Microsoft Entra ID licensing. If it is unavailable, assign individual users
at the same **Users and groups** page. Terraform intentionally leaves all
assignments to the tenant administrator. The Easy Auth application credential
has a two-year lifetime and an annual Terraform rotation trigger. Apply a
reviewed Web App plan at least annually so Terraform rotates it before
expiration.

Plan, review, apply, publish, and verify:

```bash
python -m vulnerability_view.operations_cli plan webapp
python -m vulnerability_view.operations_cli show webapp
python -m vulnerability_view.operations_cli apply webapp
python -m vulnerability_view.operations_cli deploy webapp
python -m vulnerability_view.operations_cli verify webapp
```

The reviewed plan must show no deletion of the protected history account,
history container, or current-pointer container.

## Resources not created

The current Terraform does not create:

- Key Vault integration; the Easy Auth application credential remains in
  sensitive Terraform state and the Web App's protected application settings.
- Azure App Configuration.
- Private endpoints or VNet integration.
- Power BI resources.
- Storage lifecycle deletion policies.
- A managed Durable Task Scheduler.

The current collector is a synchronous timer-triggered pilot. Durable Functions
or another bounded orchestration should be considered if production runs
approach the configured execution timeout.

## Sign in and confirm the target

```bash
az login --tenant "<tenant-id>"
az account set --subscription "<subscription-id>"
az account show --query "{name:name,id:id,tenantId:tenantId}" --output table
```

Confirm that the displayed subscription and tenant match
`main.tfvars.json` before planning.

## Deploy the protected foundation

```bash
python -m vulnerability_view.operations_cli plan foundation
python -m vulnerability_view.operations_cli show foundation
python -m vulnerability_view.operations_cli apply foundation
python -m vulnerability_view.operations_cli verify foundation
```

Review the saved plan before applying. It should create the resource group,
history account, two protected containers, and the deployer data-role
assignment. It must not delete or import an existing populated storage account.

Azure RBAC can take several minutes to propagate. If `verify foundation`
returns authorization failure immediately after apply, wait and rerun it before
seeding or backfilling data.

## Upload retained local history

After the foundation exists, configure the local application to use the history
account:

```dotenv
STORAGE_ACCOUNT_NAME=<history_storage_account_name>
STORAGE_CONTAINER_NAME=<history_container_name>
STORAGE_CURRENT_CONTAINER_NAME=<current_container_name>
```

Authenticate with an identity that has Storage Blob Data Contributor on the
history account, then upload all completed local history:

```bash
.venv/bin/vulnerability-view backfill-history
.venv/bin/vulnerability-view status --azure
```

Backfill uploads immutable runs first and updates
`dvm-current/current/manifest.json` only after the newest completed run is
available. It does not delete remote history.

## Seed six months of synthetic test history

Synthetic seeding is an explicit local operator action. The Azure Function does
not generate synthetic data.

The `vulnerability-view` executable is the project's complete data-preparation
and operator CLI. `seed-synthetic-history` is one command within it; the same
CLI also performs live collection, replay, validation, status, restoration, and
history backfill.

### APP_MODE reference

| Value | Where supported | Result |
|---|---|---|
| `live` | Local collection and deployed Function | Collects and publishes Defender data only. Use this to remove synthetic rows from the dashboard's current dataset |
| `combined` | Local collection and deployed Function | Collects live Defender data and carries forward previously seeded rows labeled `DataOrigin=Synthetic` |
| `synthetic` | Local build/test commands only | Generates deterministic sample data without calling Defender. Terraform intentionally rejects this value for the deployed Function |

Changing from `combined` to `live` does not delete any Azure Storage history.
The next **successful** live collection creates a new immutable live-only run
and updates only `current/manifest.json` to reference it. Older synthetic and
combined runs remain retained and can still be audited.

To switch the deployed collector to live-only mode, set:

```json
"app_mode": "live"
```

Then apply only the Function configuration and run or await a collection:

```bash
python -m vulnerability_view.operations_cli plan function
python -m vulnerability_view.operations_cli show function
python -m vulnerability_view.operations_cli apply function
python -m vulnerability_view.operations_cli invoke function --confirm
./infra/check-runs.sh
```

The dashboard remains on the prior current bundle if that collection fails.
Synthetic rows disappear from the current dashboard only after the live-only
run publishes successfully.

For a test environment that should display synthetic history beside current
Defender data, set this Terraform value before planning the Function:

```json
"app_mode": "combined"
```

After the foundation exists, point the local `.env` at the new history account
and authenticate with an identity that has Storage Blob Data Contributor. Then
run:

```bash
.venv/bin/vulnerability-view seed-synthetic-history --confirm-azure-write
.venv/bin/vulnerability-view status --azure
```

The command:

1. Reads a deterministic sample of real CVE identifiers from the latest
   retained local `live-*` history bundle.
2. Generates the configured six months of fictional device exposure, lifecycle,
   ownership, SLA, and remediation data around those references.
3. Labels every generated row with `DataOrigin=Synthetic`.
4. Creates and verifies a checksummed durable bundle under
   `output/history/synthetic-<timestamp>-<seed>/`.
5. Uploads immutable curated files and a run manifest to dated paths in
   `dvm-history`.
6. Replaces only `dvm-current/current/manifest.json` after all immutable files
   upload successfully.

There are no fake Defender raw response pages because synthetic data does not
come from Defender. To test bundle generation without writing Azure:

```bash
.venv/bin/vulnerability-view seed-synthetic-history --local-only
```

If no retained live CVE references are available, the command stops rather than
inventing identifiers. Collect or restore a live snapshot first.

A real CVE reference does not mean that a synthetic device was actually
exposed. Synthetic CVE detail records explicitly state that device exposure,
dates, SLA, ownership, and remediation are synthetic.

When the deployed collector later runs with `app_mode=combined`, it calls only
the live Defender collection path. It carries forward rows already labeled
`Synthetic` from the current durable bundle and appends the newly collected
`Live` rows. Live lifecycle reconciliation considers only prior `Live` rows.
The Function never calls the synthetic generator.

For production, set `"app_mode": "live"`. The next successful live collection
publishes a live-only current bundle; the older immutable synthetic run remains
retained but is no longer referenced by the current manifest.

## Deploy the collector Function

```bash
python -m vulnerability_view.operations_cli plan function
python -m vulnerability_view.operations_cli show function
python -m vulnerability_view.operations_cli apply function
python -m vulnerability_view.operations_cli deploy function
python -m vulnerability_view.operations_cli verify function
```

The code deployment packages `function_app.py`, `host.json`,
`requirements.txt`, `pyproject.toml`, `src/`, and the versioned SLA policy. It
removes the legacy connection-string form of `AzureWebJobsStorage`, restarts the
app, publishes the package with a remote build, and synchronizes Function
triggers. Each invocation uses a temporary writable directory under `/tmp` to
stage and verify the run before upload; that directory is removed afterward and
is not durable history.

## Run the deployed collector

The timer runs automatically at the UTC `collection_schedule`. To start one
intentional run immediately:

```bash
python -m vulnerability_view.operations_cli invoke function --confirm
python -m vulnerability_view.operations_cli verify function
```

Each scheduled or manual invocation calls `collect-live`, creates a new
immutable run, and advances the current manifest only after successful
publication. In `combined` test mode it retains previously seeded synthetic rows
but does not generate them. Do not start a manual run while another invocation
is active.

### Temporary two-hour lab schedule

The collector normally uses 2 GB and runs daily. If telemetry shows the Python
worker exiting after its working set approaches or exceeds 2 GB, temporarily
set these Terraform values for a lab-day test:

```json
"function_instance_memory_in_mb": 4096,
"app_mode": "live",
"collection_schedule": "0 30 */2 * * *"
```

This runs at minute 30 of every even UTC hour. Apply the Function
infrastructure/settings, then launch one current run:

```bash
python -m vulnerability_view.operations_cli plan function
python -m vulnerability_view.operations_cli show function
python -m vulnerability_view.operations_cli apply function
python -m vulnerability_view.operations_cli invoke function --confirm
```

Do not invoke manually if a scheduled invocation is already running or is due
before the manual collection can finish. Monitor invocation and memory
telemetry, then verify immutable publication:

```bash
./infra/check-function-logs.sh 6 10
./infra/check-runs.sh 5
```

After the lab, restore the normal daily schedule:

```json
"collection_schedule": "0 0 5 * * *"
```

If repeated live-only runs remain comfortably below 2 GB, also restore:

```json
"function_instance_memory_in_mb": 2048
```

Run `plan function`, review it, and run `apply function` again after
restoring those values. Changing the schedule or instance memory does not
delete or overwrite immutable run history.

List the latest ten durable Azure runs and their manifest status:

```bash
./infra/check-runs.sh
```

Pass a different positive count when needed, for example
`./infra/check-runs.sh 20`. The script performs read-only Azure operations and
uses a temporary local download directory that it removes on exit.

This lists only runs that reached immutable manifest publication. To see timer
invocations that failed before a run was published, query the Function's
workspace-based Application Insights data:

```bash
./infra/check-function-logs.sh
```

The optional arguments are the lookback in hours and maximum invocation count:

```bash
./infra/check-function-logs.sh 48 20
```

The script displays recent invocations, automatically investigates the newest
failure, prints its warning/error traces and correlated exceptions, and reports
the Function's minute-by-minute memory working set. It is read-only.

The equivalent query can be run after resolving the workspace GUID from the
Log Analytics workspace:

```bash
az monitor log-analytics query \
  --subscription "<subscription-id>" \
  --workspace "<workspace-guid>" \
  --analytics-query "AppRequests
    | where Name == 'dataprep_snapshot'
    | top 10 by TimeGenerated desc
    | project TimeGenerated, Success, DurationMs, OperationId" \
  --output table
```

`TimeGenerated` is UTC. A failed invocation may not appear in
`check-runs.sh` because the current manifest advances only after successful
publication.

## Deploy the authenticated dashboard Web App

Deploy stage 3 only after the foundation, Function, and at least one verified
current run exist:

```bash
python -m vulnerability_view.operations_cli plan webapp
python -m vulnerability_view.operations_cli show webapp
python -m vulnerability_view.operations_cli apply webapp
python -m vulnerability_view.operations_cli deploy webapp
python -m vulnerability_view.operations_cli verify webapp
```

Review the cumulative plan before applying it. It must preserve:

- the protected history account and containers;
- the Function runtime account;
- the collector Function and managed identity;
- existing immutable runs;
- the current manifest pointer.

`apply webapp` creates or updates Web App infrastructure, managed identity,
Microsoft Entra application objects, App Service Authentication, settings, and
role assignments. It does not publish the Python/dashboard source.
`deploy webapp` publishes the code package and stamps a UTC UI revision.

After apply, assign authorized users or groups at:

**Microsoft Entra admin center > Enterprise applications > DVM Viewer > Users
and groups**

Assign:

- **Dashboard Viewer** to everyone allowed to open the dashboard;
- **Data Evidence Reader** only to users allowed to use the optional evidence
  browser.

Shared recommendation status is available to authenticated Dashboard Viewers
when tracking is enabled.

Terraform does not create an access group or decide organization membership.
Group-based assignment requires applicable Microsoft Entra licensing; assign
individual users when group assignment is unavailable.

Verify:

1. `verify webapp` reports the expected running app and authentication
   redirect.
2. An assigned user can sign in.
3. An unassigned user cannot access the app.
4. The header shows the packaged UI revision.
5. The data timestamp matches the current immutable run, not the Web App
   deployment time.
6. `/api/status` identifies the expected run and Azure data source.

Publishing Web App code never starts a collection. If the data timestamp is
old, inspect Function status and run history separately.

## Useful Terraform outputs

```bash
python -m vulnerability_view.operations_cli output
python -m vulnerability_view.operations_cli output history_storage_account_name
python -m vulnerability_view.operations_cli output function_runtime_storage_account_name
python -m vulnerability_view.operations_cli output function_app_name
python -m vulnerability_view.operations_cli output collector_identity_client_id
python -m vulnerability_view.operations_cli output collector_identity_principal_id
python -m vulnerability_view.operations_cli output dashboard_enterprise_application_object_id
python -m vulnerability_view.operations_cli output dashboard_entra_client_id
```

## Safe replacement and teardown boundary

The Function stage is replaceable. The helper permits removal only when the
operator explicitly confirms it:

```bash
python -m vulnerability_view.operations_cli destroy function --confirm
```

This removes only resources controlled by `deploy_function`. It must not remove
the protected history account, its containers, or retained data. Never use a
general reset, cleanup, rebuild, or redeploy request as authorization to delete
DVM history.
