# Azure deployment guide

> **Last modified:** 2026-09-27  
> **Purpose:** Deploy and validate protected storage, the collector Function, and the authenticated dashboard Web App.

The deployment is staged so retained DVM history stays independent of
replaceable application infrastructure.

For the complete inventory of Terraform inputs, runtime environment variables,
JSON keys, generated Azure App Settings, SLA controls, presentation settings,
and script overrides, see
[Complete configuration reference](docs/configuration-reference.md).
For all supported local, collection, deployment, validation, and diagnostic
commands, including when each is safe to use, see
[Command reference](docs/command-reference.md).

## What `infra/deploy.sh` automates

You do **not** need to run `terraform init` manually before a `tfplan` command.
Every `./infra/deploy.sh tfplan <stage>` invocation automatically runs:

1. `terraform init -input=false`
2. `terraform validate`
3. `terraform plan`, saved as `infra/terraform/<stage>.tfplan`

Planning and applying remain deliberately separate. `tfplan` never applies
infrastructure, and `tfapply` never creates or refreshes a plan. Review and
apply the exact saved plan:

```bash
./infra/deploy.sh tfplan webapp
terraform -chdir=infra/terraform show webapp.tfplan
./infra/deploy.sh tfapply webapp
```

`tfdeploy` is a code-package operation. It does not run Terraform `init`,
`plan`, or `apply`; it expects the selected Function or Web App infrastructure
and Terraform outputs to already exist. For a dashboard code-only update to an
existing Web App, use:

```bash
./infra/deploy.sh tfdeploy webapp
./infra/deploy.sh tfverify webapp
```

Linux ZipDeploy can return HTTP 504 while Kudu continues an Oryx build. The
deployment helper treats a nonzero client result as provisional and polls for
a new Kudu deployment record. Kudu status `4` is successful and status `3` is
failed. Before manually retrying an interrupted deployment, inspect its final
state:

```bash
az webapp log deployment list \
  --resource-group RG-DVMVIEWER \
  --name app-dvmviewer-test \
  --query 'sort_by(@,&start_time)[-1].{id:id,status:status,active:active,start:start_time,end:end_time}' \
  --output table
```

## Consolidated deployment runbook

Use this table to choose the smallest operation that matches the change:

| Situation | Commands | Run a collection? |
|---|---|---|
| First deployment | `tfplan foundation`, review, `tfapply foundation`, `tfverify foundation`; then repeat for `function`; then repeat for `webapp` | Run `tfinvoke function` only if data is needed immediately |
| Collector infrastructure or permissions changed | `tfplan function`, review, `tfapply function`, `tfdeploy function`, `tfverify function` | Only when an immediate fresh snapshot is needed |
| Collector Python changed, infrastructure did not | `tfdeploy function`, then `tfverify function` | No; wait for the schedule unless fresh data is needed |
| Web App infrastructure, Easy Auth, roles, or settings changed | `tfplan webapp`, review, `tfapply webapp`, `tfdeploy webapp`, `tfverify webapp` | No |
| Dashboard or dashboard-server code changed | `tfdeploy webapp`, then `tfverify webapp` | No |
| Recommendation tracking enabled persistently | Set `dashboard_recommendation_tracking_enabled=true` in `main.tfvars.json`; `tfplan webapp`, review, `tfapply webapp`, `tfdeploy webapp`, `tfverify webapp` | No |
| A fresh Defender snapshot is needed immediately | `CONFIRM_LIVE_COLLECTION=yes ./infra/deploy.sh tfinvoke function`, then `tfverify function` | This is the collection |

All Terraform stages are cumulative. Once the Web App exists, use the `webapp`
stage for later infrastructure plans so Terraform preserves the foundation,
Function, and Web App together. Never apply a plan that deletes the protected
history account, its retained containers, or their data.

After Terraform creates the Enterprise Application, assign approved users or
groups manually at **Microsoft Entra admin center > Enterprise applications >
DVM Viewer > Users and groups**:

- Assign **Dashboard Viewer** to everyone who may open the application.
- Assign **Data Evidence Reader** only to users or groups that may use the
  hidden Data evidence browser.
- Assign **Recommendation Tracker** to users or groups that may update shared
  recommendation status.

Terraform does not create an access group and does not manage these
assignments.

### Remove a group created by an earlier release

An earlier Terraform configuration created `DVM Viewer Users` and assigned all
three application roles to it. Before applying the cleanup plan:

1. Assign the intended existing user or group to **Dashboard Viewer** in the
   `DVM Viewer` Enterprise Application.
2. Assign **Data Evidence Reader** and **Recommendation Tracker** only where
   those capabilities are required.
3. Run `./infra/deploy.sh tfplan webapp` and review the saved plan.
4. Confirm that the plan removes only the generated group, its membership, and
   its three app-role assignments. It must retain the Enterprise Application,
   Web App, identities, storage accounts, containers, and stored data.
5. Run `./infra/deploy.sh tfapply webapp`.
6. Run `./infra/deploy.sh tfverify webapp`.

Assigning the intended access first avoids a period where the
assignment-required Enterprise Application has no authorized users.

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
`infra/terraform/main.tfvars.json`. Terraform variable files, plans, and state
files are ignored by Git. Store Terraform state in a secured backend that is
separate from the protected DVM history account before production deployment.

The deployment workstation needs:

- Terraform 1.10 or later.
- Azure CLI authenticated to the target tenant and subscription.
- Python 3.12 and the project virtual environment.
- Bash, `zip`, `jq`, and `curl`.

The deployment-stage values in the file are informational when using the helper:

- `tfplan foundation` disables the Function and Web App.
- `tfplan function` enables the Function and keeps the Web App disabled.
- `tfplan webapp` enables both the Function and Web App as the cumulative stage.

`grant_deployer_history_access=true` grants the identity executing Terraform
Storage Blob Data Contributor on the new history account. With interactive
Azure CLI authentication, this is the currently signed-in local operator. Keep
it enabled when that operator will run status, restore, backfill, or synthetic
seeding commands.

`config/vulnerability-view.example.json` is an optional local CLI configuration
template. It is not read by Terraform and is not packaged into the Function.
Azure Function runtime settings are created by Terraform as Function App
application settings.

## Required operator permissions

The person running Terraform needs permission to:

- Create resources in the target subscription or resource group.
- Create Azure role assignments.
- Create a user-assigned managed identity.
- Read the Microsoft Defender for Endpoint and Microsoft Graph enterprise
  applications.
- Create application-role assignments for the collector identity.
- Create an Entra application and Enterprise Application for the dashboard.

Uploading existing local history requires Storage Blob Data Contributor on the
history account. The foundation assigns this automatically to the Terraform
execution identity when `grant_deployer_history_access=true`. Azure subscription
Owner or Contributor alone does not automatically provide Blob data-plane
access.

The hosted collector uses its user-assigned managed identity and has no client
secret. App Service Easy Auth requires a dashboard application credential;
Terraform creates it and stores the sensitive value in the secured Terraform
state and Web App application settings.

For this deployment, subscription Owner is sufficient for Azure resource and
role-assignment operations. An equivalent split is Contributor plus User
Access Administrator or Role Based Access Control Administrator at every scope
where Terraform creates role assignments. That person also needs Microsoft
Entra directory authority to create applications and service principals.
Whoever assigns dashboard users or groups needs permission to manage the
Enterprise Application. Global Administrator is sufficient; use narrower
approved roles when organizational policy requires them.

## Runtime identities and permissions

Terraform uses the signed-in operator only for deployment and explicitly
requested local storage operations. Hosted workloads use separate user-assigned
managed identities:

| Identity | Permission | Scope and purpose |
|---|---|---|
| Collector | Reader | Each subscription in `collector_subscription_reader_ids`; reads subscription inventory only |
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

Terraform creates infrastructure but does not publish the Python source.
`tfdeploy function` creates `function-source.zip` and uploads it to the existing
Function App. `tfdeploy webapp` creates `webapp-source.zip` and uploads it to the
existing Web App. Both packages are local build artifacts covered by
`.gitignore`; they should not be committed or uploaded to GitHub.

## Resource inventory

### Stage 1: protected foundation

`tfplan foundation` and `tfapply foundation` create:

1. One resource group.
2. One ADLS Gen2 history storage account:
   - StorageV2 with hierarchical namespace enabled.
   - HTTPS-only and TLS 1.2 minimum.
   - Shared-key access disabled.
   - Public blob access disabled.
   - Configurable LRS, ZRS, GRS, or GZRS replication.
   - Blob and container soft delete, 30 days by default.
   - Terraform `prevent_destroy`.
3. One private history container, `dvm-history` by default:
   - Holds append-only `raw/`, `curated/`, and `runs/` paths.
   - An unlocked 365-day time-based immutability policy protects existing and
     newly written blobs from modification or deletion during their retention period.
   - Terraform `prevent_destroy`.
4. One private current-pointer container, `dvm-current` by default:
   - Holds only `current/manifest.json`.
   - Has no immutability policy because the pointer must be replaceable.
   - Terraform `prevent_destroy`.
5. Storage Blob Data Contributor on the history account for the identity running
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

`tfplan function` and `tfapply function` retain the foundation and add:

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

`tfplan webapp` and `tfapply webapp` retain the foundation and Function and add:

1. One Linux B1 App Service plan and Web App.
2. One dedicated user-assigned managed identity.
3. Storage Blob Data Reader on the history account for that identity.
4. A private recommendation-workflow container and Storage Blob Data
   Contributor for the dashboard identity on that container only.
5. One single-tenant Entra app registration and Enterprise Application named
   `DVM Viewer`.
6. `Dashboard.Viewer`, `Data.Evidence.Reader`, and the legacy
   `Recommendation.Tracker` app roles for manual assignment. Shared local
   workflow updates require only normal dashboard access.
7. Assignment-required Enterprise Application access.
8. App Service Easy Auth with unauthenticated requests redirected to Entra.
9. Azure-backed FastAPI settings, a 300-second current-manifest refresh interval,
   and per-dataset caching for the active immutable run.

The Enterprise Application display name is `DVM Viewer`; the app registration
uses the same name. After apply, Terraform outputs
`dashboard_enterprise_application_object_id` and
`dashboard_entra_client_id` identify it. Manage assignments at **Microsoft
Entra ID > Enterprise applications > DVM Viewer > Users and groups**.

The proposed `app-dvmviewer-test` name was available when checked on
2026-09-27, but global availability must be confirmed again at apply time.
Group-based Enterprise Application assignment requires the applicable
Microsoft Entra ID licensing. If it is unavailable, assign individual users
at the same **Users and groups** page. Terraform intentionally leaves all
assignments to the tenant administrator. The Easy Auth application credential
has a two-year lifetime and an annual Terraform rotation trigger. Apply a
reviewed Web App plan at least annually so Terraform rotates it before
expiration.

Plan, review, apply, publish, and verify:

```bash
./infra/deploy.sh tfplan webapp
terraform -chdir=infra/terraform show webapp.tfplan
./infra/deploy.sh tfapply webapp
./infra/deploy.sh tfdeploy webapp
./infra/deploy.sh tfverify webapp
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
./infra/deploy.sh tfplan foundation
terraform -chdir=infra/terraform show foundation.tfplan
./infra/deploy.sh tfapply foundation
./infra/deploy.sh tfverify foundation
```

Review the saved plan before applying. It should create the resource group,
history account, two protected containers, and the deployer data-role
assignment. It must not delete or import an existing populated storage account.

Azure RBAC can take several minutes to propagate. If `tfverify foundation`
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
./infra/deploy.sh tfplan function
terraform -chdir=infra/terraform show function.tfplan
./infra/deploy.sh tfapply function
CONFIRM_LIVE_COLLECTION=yes ./infra/deploy.sh tfinvoke function
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

## Deploy the collector

```bash
./infra/deploy.sh tfplan function
terraform -chdir=infra/terraform show function.tfplan
./infra/deploy.sh tfapply function
./infra/deploy.sh tfdeploy function
./infra/deploy.sh tfverify function
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
CONFIRM_LIVE_COLLECTION=yes ./infra/deploy.sh tfinvoke function
./infra/deploy.sh tfverify function
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
./infra/deploy.sh tfplan function
terraform -chdir=infra/terraform show function.tfplan
./infra/deploy.sh tfapply function
CONFIRM_LIVE_COLLECTION=yes ./infra/deploy.sh tfinvoke function
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

Run `tfplan function`, review it, and run `tfapply function` again after
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

The equivalent direct Azure CLI query is:

```bash
WORKSPACE_ID="$(az monitor log-analytics workspace show \
  --subscription c1f464b9-639a-4495-8118-0c6916a3ba3e \
  --resource-group RG-DVMVIEWER \
  --workspace-name log-dvmviewer-test \
  --query customerId \
  --output tsv)"

az monitor log-analytics query \
  --subscription c1f464b9-639a-4495-8118-0c6916a3ba3e \
  --workspace "$WORKSPACE_ID" \
  --analytics-query "AppRequests
    | where Name == 'dataprep_snapshot'
    | top 10 by TimeGenerated desc
    | project TimeGenerated, Success, DurationMs, OperationId" \
  --output table
```

`TimeGenerated` is UTC. A failed invocation may not appear in
`check-runs.sh` because the current manifest advances only after successful
publication.

## Useful Terraform outputs

```bash
terraform -chdir=infra/terraform output
terraform -chdir=infra/terraform output -raw history_storage_account_name
terraform -chdir=infra/terraform output -raw function_runtime_storage_account_name
terraform -chdir=infra/terraform output -raw function_app_name
terraform -chdir=infra/terraform output -raw collector_identity_client_id
terraform -chdir=infra/terraform output -raw collector_identity_principal_id
terraform -chdir=infra/terraform output -raw dashboard_enterprise_application_object_id
terraform -chdir=infra/terraform output -raw dashboard_entra_client_id
```

## Safe replacement and teardown boundary

The Function stage is replaceable. The helper permits removal only when the
operator explicitly confirms it:

```bash
CONFIRM_TF_DESTROY_FUNCTION=yes ./infra/deploy.sh tfdestroy function
```

This removes only resources controlled by `deploy_function`. It must not remove
the protected history account, its containers, or retained data. Never use a
general reset, cleanup, rebuild, or redeploy request as authorization to delete
DVM history.
