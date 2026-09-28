# Operations and configuration

> **Last modified:** 2026-09-27  
> **Purpose:** Define authentication, runtime configuration, dashboard controls, and operational status sources.

## Authentication for service-to-service access

Managed identity remains the production authentication model. Client-secret authentication is available only as an explicitly acknowledged local-development bridge when Azure CLI cannot obtain the required application permissions.

- Normal local development uses `DefaultAzureCredential` with environment credentials, workload identity, and managed identity explicitly excluded. This allows developer authentication such as Azure CLI or VS Code without silently activating a secret.
- `AUTH_MODE=client_secret` uses `ClientSecretCredential` only when `ALLOW_LOCAL_CLIENT_SECRET=true` is also set.
- Client-secret mode refuses to start when Azure host markers are present.
- Azure-hosted execution uses `ManagedIdentityCredential` only.
- `AUTH_MODE=auto` selects local credentials off Azure and managed identity when Azure managed-identity host variables are present.
- `AUTH_MODE=local`, `AUTH_MODE=client_secret`, and `AUTH_MODE=managed_identity` allow explicit credential selection.
- `AZURE_CLIENT_ID` identifies the user-assigned managed identity when hosted. It is not a secret.

A managed identity endpoint exists only on an Azure host. Local development cannot obtain a real managed-identity token. Local tests verify credential selection with mocks, while real local Azure access uses the developer identity. This preserves the same authorization requirements without retaining an application secret.

The collector managed identity receives:

- Defender application permissions and tenant admin consent
- Storage Blob Data Contributor on the required storage scope

## Configuration layers

### Configuration sources

| Location | Used by | Commit to source control |
|---|---|---|
| `.env` | Direct local CLI commands | No |
| `local.settings.json` | Local Azure Functions host; values become process environment variables | No |
| `local.settings.example.json` | Safe template for local Functions testing | Yes |
| Function App settings | Deployed Function bootstrap and runtime configuration | Managed by infrastructure code |
| Terraform variable files | Azure resource names, regions, identities, and feature selection | Commit non-secret examples only |
| `config/sla-policies.json` | Versioned SLA rules retained with each run | Yes |

Environment variables override values loaded from `.env`. When the Functions host is running locally, values from `local.settings.json` therefore take precedence over matching `.env` values.

### Application settings

| Setting | Default | Local CLI | Local Functions host | Deployed Function | Purpose |
|---|---|---|---|---|---|
| `AUTH_MODE` | `auto` | `local`, `client_secret`, or `auto` | `local` or `client_secret` | `managed_identity` | Selects the credential implementation |
| `ALLOW_LOCAL_CLIENT_SECRET` | `false` | Must be `true` with client-secret mode | Must be `true` with client-secret mode | Forbidden | Explicit acknowledgement of local-only secret use |
| `AZURE_TENANT_ID` | Empty | Required with client-secret mode | Required with client-secret mode | Optional metadata | Tenant for the local app registration |
| `AZURE_CLIENT_ID` | Empty | Required with client-secret mode | Required with client-secret mode | Required for a user-assigned identity | Application or managed-identity client identifier; it is not a secret |
| `AZURE_CLIENT_SECRET` | Empty | Required with client-secret mode | Required with client-secret mode | Forbidden | Local app-registration secret; store only in ignored local configuration |
| `DEFENDER_API_BASE_URL` | `https://api.security.microsoft.com` | Required for live collection | Required | Required | Defender API request host |
| `STORAGE_ACCOUNT_NAME` | Empty | Empty for isolated work; account name for integration tests | Development history account | Production history account | Enables durable history reads and writes |
| `STORAGE_CONTAINER_NAME` | `dvm-history` | Optional override | Set explicitly | Set explicitly | Immutable raw, curated, policy, and run history |
| `STORAGE_CURRENT_CONTAINER_NAME` | `dvm-current` | Optional override | Set explicitly | Set explicitly | Current completed-run manifest pointer |
| `APP_MODE` | `synthetic` | `live`, `synthetic`, or `combined` | `live` | Terraform `app_mode` | Selects data mode for build commands; deployed `combined` mode carries forward explicitly seeded synthetic rows but never generates them |
| `RECOMMENDATION_ENRICHMENT_MODE` | `auto` | Usually `targeted` | `targeted` for local host testing | `auto` or approved value | Controls recommendation-machine API calls |
| `ENABLE_EXPERIMENTAL_ENDPOINTS` | `false` | Keep disabled | Keep disabled unless testing compatibility | Keep disabled unless explicitly approved | Enables undocumented Defender compatibility probes such as `/api/remediationTasks`; these are not required for core findings, lifecycle, SLA, recommendations, devices, or Secure Score |
| `FULL_ENRICHMENT_WEEKDAY` | `6` | Optional | Optional | Required when enrichment is `auto` | Weekly full-reconciliation day, Monday `0` through Sunday `6` |
| `COLLECTION_SCHEDULE` | `0 0 5 * * *` | Not used by direct CLI commands | Temporary test schedule | Production NCRONTAB schedule | Timer-trigger schedule |
| `SYNTHETIC_SEED` | `24017` | Optional | Not needed for live Function test | Not needed | Reproducible sample data |
| `SYNTHETIC_MONTHS` | `6` | Optional | Not needed for live Function test | Not needed | Sample history depth |
| `SYNTHETIC_DEVICE_COUNT` | `2500` | Optional | Not needed for live Function test | Not needed | Number of distinct fictional endpoints generated across the sample history; accepted range is 1 through 100,000 |
| `AZURE_SUBSCRIPTION_ID` | Empty | Operator convenience | Not required by collection | Managed by deployment | Subscription context; the collector does not use it for API calls |
| `AZURE_RESOURCE_GROUP` | Empty | Operator convenience | Not required by collection | Managed by deployment | Resource group context |
| `AZURE_LOCATION` | `eastus` | Operator convenience | Not required by collection | Managed by deployment | Deployment region; do not infer it from the resource-group metadata location |
| `DASHBOARD_DATA_SOURCE` | `local` | `local` or `azure` | Not used | `azure` on the Web App | Selects generated local files or the verified Azure current bundle |
| `DASHBOARD_STATIC_DIR` | Empty | Usually empty | Not used | `dashboard` | Resolves static assets relative to the Oryx application directory, including compressed build extraction paths |
| `DASHBOARD_CACHE_SECONDS` | `30` | Optional | Not used | Recommended | Controls how often the Web App checks the current manifest; requested immutable datasets are cached for the active run |
| `DASHBOARD_AUTH_ENABLED` | `false` | Keep `false` | Not used | `true` only after App Service Authentication is enabled | Requires a trusted App Service Easy Auth principal for every dashboard and API request |
| `DASHBOARD_DATA_BROWSER_ENABLED` | `false` | Enable only when evidence inspection is needed | Not used | Explicit opt-in | Exposes the read-only curated Data evidence view and its bounded API |
| `DASHBOARD_DATA_BROWSER_ROLE` | Empty | Usually empty | Not used | Recommended app role such as `Data.Evidence.Reader` | When set, requires that role in the authenticated App Service principal |
| `DASHBOARD_RECOMMENDATION_TRACKING_ENABLED` | `false` | Keep disabled | Not used | Explicit opt-in | Enables shared recommendation display-state reads and writes |
| `DASHBOARD_RECOMMENDATION_TRACKING_ROLE` | `Recommendation.Tracker` | Not used | Not used | Legacy compatibility setting | No longer used; authenticated dashboard access authorizes the local shared workflow API |
| `DASHBOARD_RECOMMENDATION_TRACKING_CONTAINER` | `dvm-workflow` | Not used | Not used | Private Blob container | Stores append-only recommendation workflow events separately from retained evidence |

## Dashboard presentation configuration

The dashboard keeps data retrieval in the FastAPI service and presentation settings in `dashboard/config.js`. This file requires no build step and controls:

- header branding;
- primary and accent colors;
- comfortable or compact density;
- navigation order and hidden views;
- whether the top filter workspace starts expanded;
- default severity, recommendation types, and asset domains;
- whether authentication status and experimental endpoint diagnostics are shown.

Browser presentation settings are not security controls. Keep `diagnostics.showExperimentalEndpoints` set to `false` for normal users. Collector execution is controlled separately by `ENABLE_EXPERIMENTAL_ENDPOINTS`.

### Curated data evidence

The Data evidence view is available only when
`DASHBOARD_DATA_BROWSER_ENABLED=true`. Enabling it does not add a navigation
item. An authorized operator who knows the exact URI opens
`/?view=data-browser`; ordinary dashboard navigation and Statistics cards do
not advertise the feature. It provides:

- a whitelist of normalized datasets used by the dashboard;
- row counts, field discovery, search, and bounded pagination;
- complete formatted JSON for a selected record;
- direct evidence links from supported calculated metrics;
- current data-source and snapshot context.

The browser is read-only and does not expose arbitrary filesystem/blob paths,
storage credentials, raw Defender responses, or mutation operations. In a
hosted environment, configure `DASHBOARD_DATA_BROWSER_ROLE` and assign that
App Service application role only to approved operators or auditors. A hidden
URI obscurity is not an authorization boundary; the server enforces both the
feature flag and optional role.

App Service Authentication protects the hidden `/?view=data-browser` page and
all `/api/data-browser/*` routes through the same global authentication
middleware as the rest of the dashboard. The optional data-browser role is an
additional authorization check after authentication.

### Dashboard user authentication

`DASHBOARD_AUTH_ENABLED` is a server-side feature flag:

- `false` is the default and preserves unrestricted local UI development.
- `true` is valid only on Azure App Service, detected through `WEBSITE_HOSTNAME`.
- When enabled, middleware requires and decodes the trusted `X-MS-CLIENT-PRINCIPAL` header injected by App Service Authentication.
- Missing or malformed identity headers return HTTP 401 before static files or `/api/*` data are served.
- Local startup with the flag enabled fails immediately because local clients can forge headers and cannot reproduce the App Service trust boundary.

The flag does not enable Easy Auth, create an Entra application, assign users or groups, or configure redirect behavior. Those remain Web App infrastructure settings. Both platform authentication and this application flag must be enabled for hosted enforcement.

The deployed Enterprise Application display name is `DVM Viewer`. After apply,
Terraform outputs `dashboard_enterprise_application_object_id` and
`dashboard_entra_client_id` identify it. Manage assignments at **Microsoft
Entra ID > Enterprise applications > DVM Viewer > Users and groups**.
Group-based Enterprise Application assignment requires the applicable
Microsoft Entra ID licensing; if it is unavailable, assign individual users
the `Dashboard.Viewer` role and any enabled optional roles.

### Shared recommendation tracking

`DASHBOARD_RECOMMENDATION_TRACKING_ENABLED=true` enables recommendation-level
workflow status for authenticated dashboard users. The
private `dvm-workflow` container remains deployed when the feature is disabled
so prior workflow history is not deleted. The Web App managed identity retains
Storage Blob Data Contributor on that container only. The application does not
read or write the workflow container while the feature flag is disabled. The
identity remains a reader on retained history and has no Defender or Graph
permissions.

The API appends an event for **In progress**, **Fixed**, or **Clear**. It does
not delete prior events. A fixed recommendation is confirmed only after a newer
current run reports no active live finding for that recommendation; otherwise
it is shown as still detected. Synthetic recommendations cannot be updated.
Tracking is shared dashboard workflow metadata rather than a Defender
assignment or lock:
**In progress** remains in the recommendation lists, and another authorized
tracker can update it. The Recommendations and Prioritize views show the latest
status, updater, and update time. All work statuses are visible by default; the
global filter can narrow the dashboard to Needs attention, Untracked / not
started, In progress, Needs reassignment, Marked fixed / awaiting collection,
Confirmed fixed, or Still detected after validation. A newer collection clears
In progress from active work when no live findings remain. If fresh collection
evidence still shows findings seven days after the last update, the effective
state becomes Needs reassignment while preserving the prior user and timestamp.
Finding lifecycle and SLA calculations continue to use collected Defender
evidence.
Changing the App Service setting restarts the application and does not require
republishing the Web App package:

```bash
az webapp config appsettings set \
  --resource-group <resource-group> \
  --name <web-app-name> \
  --settings DASHBOARD_RECOMMENDATION_TRACKING_ENABLED=true
```

Use `false` to hide the controls and make the tracking API unavailable.
Terraform retains the same value in
`dashboard_recommendation_tracking_enabled`; update that variable before the
next Terraform apply so infrastructure configuration does not reverse the
runtime setting.

### Dashboard server settings

The dashboard runs as a same-origin FastAPI application. The browser always requests `/api/data/<dataset>.json`; only the server knows whether those rows came from local files or Azure Storage.

| Mode | Credential | User authentication | Data location | Intended use |
|---|---|---|---|---|
| `DASHBOARD_DATA_SOURCE=local` | None | `DASHBOARD_AUTH_ENABLED=false` | `dashboard/data` | Fast UI development, replay, and offline demonstrations |
| `DASHBOARD_DATA_SOURCE=azure` locally | Developer credential | `DASHBOARD_AUTH_ENABLED=false` | Current manifest and immutable curated blobs | Production-like data integration testing without deployment |
| `DASHBOARD_DATA_SOURCE=azure` in App Service | Web App managed identity | `DASHBOARD_AUTH_ENABLED=true` plus App Service Authentication | Current manifest and immutable curated blobs | Hosted dashboard |

Azure mode rejects incomplete manifests and verifies each requested curated blob's compressed size and SHA-256 before returning it. The Web App refreshes the current pointer after `DASHBOARD_CACHE_SECONDS` and caches only requested datasets for the active immutable run. A new run ID invalidates those dataset entries. This avoids downloading large optional datasets during the initial dashboard load and never writes to storage.

Available operational endpoints are:

```text
GET /api/health
GET /api/auth
GET /api/diagnostics
GET /api/status
GET /api/recommendation-tracking
PUT /api/recommendation-tracking
GET /api/data-browser/catalog
GET /api/data-browser/<dataset>?offset=0&limit=50&query=<text>
GET /api/data/<dataset>.json
GET /api/data/cve-details/<cve-id>.json
```

`GET /api/diagnostics` reports bounded, in-process request timings, current
data-loading activity, cached dataset names, manifest state, and recent storage
operations. It requires the same authenticated access as the dashboard and does
not expose tokens, user identities, query strings, or vulnerability records.

### Azure Functions host settings

These settings belong to the Functions host rather than the collection library:

| Setting | Local value | Azure value | Purpose |
|---|---|---|---|
| `AzureWebJobsStorage` | `UseDevelopmentStorage=true` with Azurite | Identity-based connection to dedicated Function runtime storage | Timer monitor, host state, and extension storage |
| `FUNCTIONS_WORKER_RUNTIME` | `python` | `python` | Selects the Python worker |
| `AZURE_FUNCTIONS_ENVIRONMENT` | `Development` | Environment-specific | Host diagnostics and environment behavior |

Function runtime storage is separate from the DVM history account. It can be rebuilt without replacing `dvm-history` or `dvm-current`.

### Bootstrap settings

Keep settings required before other services can be reached in Function application settings:

- `AUTH_MODE=managed_identity`
- `AZURE_CLIENT_ID` for a user-assigned identity
- Storage account and container names
- App Configuration endpoint when introduced
- `COLLECTION_SCHEDULE`
- Defender API base URL

These settings change infrequently and can require a Function restart.

## Operational status sources

### ADLS manifests

ADLS manifests are the authoritative application-level run history. They contain:

- Run and snapshot identity
- Completeness
- Endpoint statuses and row counts
- Schema, normalization, and SLA policy versions
- File inventory, sizes, and SHA-256 checksums

`dvm-current/current/manifest.json` identifies the current completed run. Immutable historical manifests remain under `runs/YYYY/MM/DD/<run-id>/manifest.json`.

### Current curated datasets

The current manifest points to current findings, devices, lifecycle events, recommendations, summaries, collection status, Secure Score, and the Azure subscription inventory accessible to the collector identity. The subscription inventory includes accessible subscriptions with zero current findings so the dashboard can prove collection scope separately from vulnerability workload.

Set `collector_subscription_reader_ids` to every subscription that should appear by name in the selector. During the Function Terraform stage, Terraform grants the collector managed identity **Reader** at each listed subscription scope and retains those assignments in state. A subscription not accessible to that identity cannot be listed, even when stale Defender device metadata still contains its subscription ID.

```json
"collector_subscription_reader_ids": [
  "00000000-0000-0000-0000-000000000001",
  "00000000-0000-0000-0000-000000000002"
]
```

The identity running Terraform must have permission to create role assignments
at every listed subscription scope, such as Owner or User Access Administrator.
If organizational policy requires out-of-band RBAC management, leave the list
empty and have an authorized operator grant each assignment explicitly:

```bash
COLLECTOR_PRINCIPAL_ID="$(cd infra/terraform && terraform output -raw collector_identity_principal_id)"
az role assignment create \
  --assignee-object-id "$COLLECTOR_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role Reader \
  --scope /subscriptions/<subscription-id>
```

With either method, deploy the updated collector and run a new collection. Historical bundles remain unchanged; the new run publishes `subscriptions.json.gz` and updates `current/manifest.json` only after successful validation.

### Function platform telemetry

When deployed, Azure Functions monitoring should capture execution failures, duration, retries, and dependencies. Use sampled OpenTelemetry/Application Insights only for platform diagnostics. It should not become the vulnerability history store.

## Local operational interface

Show effective non-secret configuration:

```text
vulnerability-view show-config
```

Show local datasets, lifecycle counts, local raw/history runs, and recent manifests:

```text
vulnerability-view status
vulnerability-view status --runs 30
```

Add one low-cost Azure read of the current manifest:

```text
vulnerability-view status --azure
```

The report never prints credential values. It reports whether a legacy secret is present but ignored.
