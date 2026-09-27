# Environment and deployment plan

> **Author:** Kevin Tigges  
> **Last modified:** 2026-09-27  
> **Purpose:** Define local, test, and Azure deployment boundaries, resources, and production-readiness gates.

## Operating model

Development and Azure deployment are separate activities:

- Local live testing calls Defender with the developer's Azure identity and writes only local files.
- Replays use retained raw pages and make no Defender or Azure calls.
- Storage integration tests use one stable development storage account; they do not redeploy infrastructure.
- Production uses managed identities, scheduled collection, protected storage, and an authenticated web application.

The application code and data formats remain the same in every environment. Identity, storage names, schedules, and hosting settings change through configuration.

## Infrastructure tool

Use Terraform as the only infrastructure source of truth. The active configuration
creates a new greenfield resource group, protected history account, containers,
and optional Function resources. Existing populated accounts remain outside that
state and are not imported or deleted.

Terraform state must be stored outside the protected DVM history account. Use a separate secured backend so infrastructure state lifecycle cannot affect retained vulnerability history.

### Terraform variables

The Terraform implementation needs these inputs:

| Variable | Purpose |
|---|---|
| `subscription_id` | Target Azure subscription |
| `tenant_id` | Microsoft Entra tenant containing Defender |
| `resource_group_name` | New environment resource group |
| `location` | Function and monitoring region; set explicitly |
| `environment` | Development, test, or production naming and tags |
| `history_storage_account_name` | Globally unique new protected history account |
| `history_container_name` | `dvm-history` |
| `current_container_name` | `dvm-current` |
| `function_runtime_storage_account_name` | Separate storage for the Functions host and Durable task hub |
| `function_app_name` | Globally unique Function App name |
| `deploy_function` | Creates Function, identity, permissions, and monitoring when `true` |
| `collection_schedule` | Production NCRONTAB schedule |
| `recommendation_enrichment_mode` | `targeted`, `full`, `none`, or `auto` |
| `full_enrichment_weekday` | Weekly full relationship-reconciliation day |
| `tags` | Ownership, environment, application, and cost metadata |

The greenfield history account and its two containers use Terraform `prevent_destroy`. Existing populated accounts such as the current development account remain separate and are not referenced by this new state. Use `docs/greenfield-deployment.md` for the staged commands.

## Local live testing

Local live collection requires:

- Python 3.12 or 3.13 and the project virtual environment
- A developer identity authenticated through Azure CLI or another supported developer credential
- Defender permissions and device-group visibility
- `AUTH_MODE=local`
- `DEFENDER_API_BASE_URL=https://api.security.microsoft.com`
- `STORAGE_ACCOUNT_NAME` left empty when Azure Storage must not be changed

When Azure CLI lacks a required delegated Graph scope, local collection may instead use a dedicated app registration:

```dotenv
# LOCAL DEVELOPMENT ONLY. NEVER DEPLOY OR COMMIT THESE VALUES.
AUTH_MODE=client_secret
ALLOW_LOCAL_CLIENT_SECRET=true
AZURE_TENANT_ID=<tenant-id>
AZURE_CLIENT_ID=<local-collector-application-id>
AZURE_CLIENT_SECRET=<local-secret>
```

Grant that app registration the required Defender application permissions and Microsoft Graph `SecurityEvents.Read.All`, then grant tenant admin consent. Store the secret only in ignored `.env` or `local.settings.json`. Azure-hosted execution rejects this mode and uses managed identity.

Check access before downloading a full snapshot:

```bash
vulnerability-view show-config
vulnerability-view preflight
```

Collect live data without reading or writing Azure Storage:

```bash
vulnerability-view collect-live --local-only --enrichment targeted
vulnerability-view validate
python -m http.server 8000 --directory dashboard
```

This path calls Defender, creates `output/raw/<run-id>` and `output/history/<run-id>`, and rewrites the local dashboard JSON and CSV exports. It does not create, update, or deploy an Azure resource.

After one live collection, most application changes can be tested without another Defender call:

```bash
vulnerability-view simulate-scheduled-run --from-raw latest --local-only
vulnerability-view validate
```

Use the replay path for normalization, lifecycle, SLA, export, and dashboard work. Run a new live collection only when fresh source data or API behavior is needed.

## Local Function testing

The current Function is a timer wrapper around the same `collect-live` command used by the CLI. It is not yet a Durable Functions orchestration. Test it in two stages.

### Test the Function workload

This is the fastest check and does not require the Functions host:

```bash
vulnerability-view simulate-scheduled-run --from-raw latest --local-only
vulnerability-view simulate-scheduled-run --enrichment targeted
```

The first command tests processing without network calls. The second uses the local developer credential, calls Defender, reads prior history from Azure, uploads a new completed run, and advances the development current manifest.

### Test the Functions host

Azure Functions Core Tools v4 and Azurite are prerequisites. They are not currently installed in this development environment.

1. Copy `local.settings.example.json` to the ignored `local.settings.json` file.
2. Replace the tenant and development history-account placeholders.
3. Authenticate the developer identity in a separate terminal.
4. Start Azurite for `AzureWebJobsStorage=UseDevelopmentStorage=true`.
5. Start the Functions host with `func start`.
6. Invoke the timer once from another terminal:

   ```bash
   curl -i -X POST http://localhost:7071/admin/functions/dataprep_snapshot \
     -H 'Content-Type: application/json' \
     -d '{"input":null}'
   ```

7. Verify one completed run and stop the host.

The local Functions host uses `AUTH_MODE=local`; managed identity cannot be exercised from a workstation. Azurite stores only Functions host state. The collection itself uses the real Defender API, `dvm-history`, and `dvm-current` configured in `local.settings.json`.

Values in `local.settings.json` are injected as environment variables and take precedence over matching `.env` values.

### Validate the local host run

```bash
vulnerability-view status --azure
vulnerability-view restore-current
vulnerability-view validate
```

Confirm that the current run ID changed, the manifest is complete, and all referenced files are available before moving to Azure hosting.

## Storage integration testing

Provision one development storage account and keep it stable. Configure its name in `.env`, then replay an existing local run without calling Defender:

```bash
vulnerability-view simulate-scheduled-run --from-raw latest
vulnerability-view status --azure
```

This writes a new immutable run under `raw/`, `curated/`, and `runs/`, then advances `dvm-current/current/manifest.json`. It changes stored development data but does not change the storage account, containers, role assignments, or other Azure resources.

For a complete local-history migration, `vulnerability-view backfill-history` uploads every immutable run first and advances the current manifest only after the newest run uploads successfully.

Use a development account that is separate from production. Never point local integration tests at production storage.

## Azure resource inventory

| Resource | Purpose | Current repository status |
|---|---|---|
| Resource group per environment | Ownership, access, cost, and deployment boundary | Supplied by the operator |
| ADLS Gen2 history account | Immutable raw pages, curated snapshots, policies, and run manifests | Implemented in greenfield Terraform |
| `dvm-history` container | Append-only dated history | Implemented with `prevent_destroy` |
| `dvm-current` container | Replaceable current manifest pointer | Implemented with `prevent_destroy` |
| Function runtime storage | Function host state and deployment packages; separate from retained DVM history | Implemented when `deploy_function=true` |
| User-assigned managed identity | Defender access and Storage Blob Data Contributor for the collector | Implemented when `deploy_function=true` |
| Flex Consumption Function App | Daily scheduled collector | Implemented when `deploy_function=true`; durable orchestration remains future work |
| Application Insights | Function diagnostics, failures, and dependency timing | Implemented when `deploy_function=true` |
| Linux Web App and plan | Hosts the dashboard and a same-origin API that reads current data from private ADLS | Implemented as an optional B1 Terraform stage |
| Web App managed identity | Read-only access to `dvm-current` and referenced curated blobs | Implemented with Storage Blob Data Reader |
| Microsoft Entra authentication | Restricts dashboard and API access to approved users or groups | Implemented with Easy Auth, assignment-required Enterprise Application, and Terraform-managed group app-role assignments |
| Log Analytics | Function and Web App operational telemetry | Function workspace implemented; reporting queries deferred |
| Azure App Configuration | Future runtime settings that can change without code deployment | Planned; not connected to the application |

The retained-history account is a protected data resource. Function runtime storage and web hosting can be replaced without replacing or deleting DVM history.

Existing environments that use `dvm-raw` remain valid when `STORAGE_CONTAINER_NAME=dvm-raw` is set explicitly. Do not delete that container. Moving to `dvm-history` requires copying every historical blob, verifying the copy, and changing the configured container only after the current manifest and all referenced files are available in the new container.

## Dashboard data path

The implemented FastAPI server hosts the static dashboard and `/api/data/*` on the same origin. In local mode it reads `dashboard/data`. When hosted in Azure, the complete path:

1. Authenticates the user with Microsoft Entra ID.
2. Uses the server credential to read `dvm-current/current/manifest.json`.
3. Reads only the curated blobs referenced by that completed manifest.
4. Verifies blob sizes and SHA-256 checksums before serving data.
5. Serves the dashboard and data API from the same origin.
6. Caches the verified completed run briefly without copying or modifying historical blobs.

The first item is supplied by App Service Authentication. The application now has a second fail-closed check controlled by `DASHBOARD_AUTH_ENABLED`, but that flag does not configure the Azure authentication provider. Locally, keep the flag `false`; the same server uses the developer credential and can read the development history account directly:

```bash
DASHBOARD_DATA_SOURCE=azure ./start-app.sh
curl http://localhost:8000/api/status
```

The Web App uses these application settings:

```text
DASHBOARD_DATA_SOURCE=azure
DASHBOARD_CACHE_SECONDS=300
DASHBOARD_AUTH_ENABLED=true
DASHBOARD_DATA_BROWSER_ENABLED=false
DASHBOARD_DATA_BROWSER_ROLE=Data.Evidence.Reader
AUTH_MODE=managed_identity
AZURE_CLIENT_ID=<web-identity-client-id>
STORAGE_ACCOUNT_NAME=<history-account>
STORAGE_CONTAINER_NAME=dvm-history
STORAGE_CURRENT_CONTAINER_NAME=dvm-current
```

Its startup command is:

```bash
python -m uvicorn vulnerability_view.dashboard_server:app --host 0.0.0.0 --port 8000
```

Grant the web identity Storage Blob Data Reader on the history account. Do not grant contributor rights. Configure App Service Authentication before enabling `DASHBOARD_AUTH_ENABLED`; otherwise every request fails with HTTP 401. UI development does not require App Service deployment and keeps the flag disabled. Deploy the Web App only for Entra authentication, managed-identity, network, and hosted integration testing.

When the curated Data evidence browser is enabled, Terraform sets
`DASHBOARD_DATA_BROWSER_ROLE=Data.Evidence.Reader` and assigns that role to the
configured dashboard access group. The evidence API is read-only and exposes
only whitelisted normalized datasets.

### User and group access

The Enterprise Application display name is `DVM Viewer`; the app registration
uses the same name. After apply, Terraform outputs
`dashboard_enterprise_application_object_id` and
`dashboard_entra_client_id` identify it. Easy Auth and Enterprise Application
assignment perform different jobs:

- Easy Auth signs users in and injects the trusted identity header consumed by
  FastAPI.
- The Enterprise Application has **Assignment required** enabled, so Entra
  issues access only to assigned users and groups.
- Terraform creates `dashboard_access_group_name` when
  `dashboard_access_group_object_id` is empty, or uses the supplied existing
  group. It assigns that group to the `Dashboard.Viewer` app role.
- When the hidden evidence browser is enabled, Terraform also assigns
  `Data.Evidence.Reader` to that group.

Manage assignments at **Microsoft Entra ID > Enterprise applications > DVM
Viewer > Users and groups**. Keeping assignments in Terraform prevents
configuration drift. Group membership remains managed in Entra ID. Optional
initial members can be supplied through
`dashboard_access_member_object_ids`; users can also be added to the group
later through normal Entra administration.
Group-based Enterprise Application assignment requires the applicable
Microsoft Entra ID licensing. If it is unavailable, assign individual users
the `Dashboard.Viewer` role at the same **Users and groups** page.
The Terraform operator needs permission to create applications and service
principals and assign app roles, in addition to Azure permission to create the
Web App and its Storage Blob Data Reader assignment.

Populate `collector_subscription_reader_ids` with every Azure subscription
that should appear in the dashboard selector. The Function Terraform stage
then grants its managed identity Reader at those subscription scopes. This is
separate from the Web App's storage-reader role. The Terraform deployer needs
role-assignment permission in every listed subscription.

The browser must not receive storage account keys, SAS tokens, or direct access to the private history container.

## Environment boundaries

Development, test, and production need separate values for:

- Resource group
- History storage account
- Function runtime storage account
- Function App
- Web App
- Managed identities
- Application Insights instance
- Current manifest pointer
- SLA policy approval and version

Use the same Terraform modules and application packages for each environment. Keep environment-specific values in uncommitted variable files and Function application settings rather than editing source files.

## Deployment sequence

Use the three cumulative Terraform stages:

1. **Foundation:** protected history storage and containers.
2. **Function:** collector plan and app, runtime storage, identity, permissions,
   and monitoring.
3. **Web App:** dashboard plan and app, read-only identity, authentication,
   settings, and role assignments.

The foundation changes rarely. Application code can be deployed repeatedly
without modifying retained storage.

Before applying a Terraform infrastructure change, review it with:

```bash
terraform fmt -check
terraform validate
terraform plan -out=<environment>.tfplan -var-file=<environment>.tfvars
```

The current Terraform provisions the protected storage foundation and, when
`deploy_function=true`, the Flex Consumption Function, separate runtime
storage, managed identity, permissions, and monitoring. The Function remains a
synchronous pilot rather than a Durable Functions orchestration.

### Function pilot deployment

Follow `docs/greenfield-deployment.md` and `infra/deploy.sh`:

1. Plan and apply the new resource group and protected history storage.
2. Set `deploy_function=true`, then plan and apply the Function resources and permissions.
3. Publish the Function package with the deployment helper.
4. Verify host readiness and timer discovery.
5. Run local preflight, then explicitly confirm one live Function invocation.

The existing timer wrapper proves identity, packaging, Defender access, history reads, and durable publication. Before production use, replace the long synchronous collection with bounded Durable Functions activities, retries, concurrency control, and missed-run alerting.

The exact commands use the `tf` prefix:

```bash
./infra/deploy.sh tfplan foundation
./infra/deploy.sh tfapply foundation
./infra/deploy.sh tfplan function
./infra/deploy.sh tfapply function
./infra/deploy.sh tfdeploy function
./infra/deploy.sh tfverify function
```

Web App hosting recommendations are documented in
`docs/web-app-deployment-recommendations.md`.

## Deployed Function operation

The normal path is the UTC timer configured by `collection_schedule`. Operators
also have a guarded one-shot path for initial validation or an intentional
out-of-band snapshot:

```bash
CONFIRM_LIVE_COLLECTION=yes ./infra/deploy.sh tfinvoke function
./infra/deploy.sh tfverify function
```

Both paths execute `collect-live`, create a new immutable run, and update only
the current manifest after successful publication. Do not invoke a one-shot run
while a scheduled invocation is active. Change the recurring schedule through
the Terraform value and a reviewed `tfplan function`/`tfapply function`, not by
editing the Function App setting out of band.

## Production readiness gates

Production deployment requires all of the following:

- The synchronous Flex Consumption pilot is either proven to stay within the
  execution limit or replaced with bounded Durable Functions activities.
- Function package deployment, retry behavior, concurrency control, and missed-run alerting are tested.
- The collector managed identity has Defender application permissions with tenant admin consent.
- The Function identity has write access to the history account without delete permissions in application code.
- The web service and managed identity can read current curated data without exposing storage credentials.
- Entra authentication and user/group authorization are tested.
- Development, test, and production parameter files use separate resource names and identities.
- The production SLA policy is approved and versioned.
- Backup, soft-delete, network-access, monitoring, and cost settings are reviewed.
- A Terraform plan confirms that protected history is not managed, replaced, or deleted.

Passing local tests proves the application behavior. It does not make the current Function reference or hosted dashboard production-ready.