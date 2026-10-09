# Complete configuration reference

> **Last modified:** 2026-10-08
> **Purpose:** List every operator-controlled configuration file and setting used by the collector, dashboard, Terraform, and operational scripts.

For executable workflows and safety guidance, see the
[Command reference](command-reference.md).

## 1. Configuration sources and precedence

The repository uses several configuration surfaces because infrastructure,
collector runtime, dashboard runtime, and local development have different
lifecycles.

| Source | Scope | Commit it? |
|---|---|---|
| `infra/terraform/main.tfvars.json` | Azure infrastructure and generated App Settings | No; environment-specific |
| `infra/terraform/main.tfvars.example.json` | Safe Terraform template | Yes |
| Environment variables or `.env` | Collector and dashboard runtime overrides | Do not commit `.env` |
| `config/vulnerability-view.json` | Optional local application configuration | Normally no; derive from the example |
| `config/vulnerability-view.example.json` | Safe application configuration template | Yes |
| `local.settings.json` | Local Azure Functions settings and secrets | No |
| `local.settings.example.json` | Safe local Functions template | Yes |
| `config/sla-policies.json` | Finding lifecycle and SLA policy | Yes |
| `dashboard/config.js` | Browser presentation and default filters | Yes |
| `host.json` | Azure Functions host behavior | Yes |
| `pyproject.toml` and `requirements.txt` | Python runtime, dependencies, tests, and package entry point | Yes |

Application runtime precedence is:

1. Process environment, including values loaded from `.env`.
2. `config/vulnerability-view.json` when the command supplies that path.
3. Defaults in `Settings`.

Terraform does not read `.env` or `config/vulnerability-view.json`. It reads
`infra/terraform/main.tfvars.json` and writes the required Azure App Settings.

Do not edit Terraform state, saved `*.tfplan` files, deployment ZIP files, or
Azure-generated Easy Auth settings as configuration sources.

## 2. Terraform inputs

Authoritative schema: `infra/terraform/variables.tf`
Environment values: `infra/terraform/main.tfvars.json`

| Setting | Default / allowed values | Effect |
|---|---|---|
| `subscription_id` | Required Azure subscription GUID | Subscription containing the deployment resource group |
| `tenant_id` | Required Entra tenant GUID | Tenant containing Defender, managed identities, and dashboard authentication |
| `collector_management_group_id` | Empty; management group ID | Grants the collector Reader once at the management-group scope and inventories all nested subscriptions |
| `collector_subscription_reader_ids` | `[]`; set of subscription GUIDs | Compatibility fallback used only when `collector_management_group_id` is empty |
| `resource_group_name` | Required | Resource group containing application infrastructure |
| `location` | Required | Azure region; must support Functions Flex Consumption |
| `project_name` | `dvmviewer` | Naming component for monitoring and Azure resources |
| `environment` | `test` | Environment suffix and tag value |
| `history_storage_account_name` | Required, globally unique | Protected ADLS Gen2 account containing immutable history and current pointer containers |
| `history_storage_replication_type` | `LRS`; `LRS`, `ZRS`, `GRS`, or `GZRS` | Replication for retained history |
| `history_container_name` | `dvm-history` | Append-only raw, curated, and run history container |
| `current_container_name` | `dvm-current` | Separate container containing replaceable `current/manifest.json` |
| `storage_soft_delete_days` | `30`; 7-365 | Blob/container recovery window |
| `history_immutability_days` | `365`; 1-146000 | Minimum WORM retention for history blobs |
| `lock_history_immutability_policy` | `false` | Permanently locks WORM policy when true; cannot be reversed or shortened |
| `grant_deployer_history_access` | `true` | Grants the Terraform execution identity Blob Data Contributor for status, restore, backfill, and seeding |
| `network_security_perimeter_enabled` | `true` | Creates a shared Storage Network Security Perimeter profile and associates the history and Function runtime accounts |
| `network_security_perimeter_access_mode` | `Enforced`; `Audit`, `Enforced`, or `Learning` | Controls the access mode used by both Storage associations |
| `network_security_perimeter_allowed_ip_cidrs` | `["0.0.0.0/0"]`; valid IPv4/IPv6 CIDRs | Allows public source networks through the perimeter; the default does not restrict IPv4 addresses yet |
| `deploy_function` | `false` | Cumulative-stage switch used by the deployment helper to create the collector stack |
| `deploy_web_app` | `false` | Cumulative-stage switch used by the deployment helper to create the dashboard stack |
| `function_runtime_storage_account_name` | Required, globally unique | Replaceable Functions host/deployment storage; not retained DVM history |
| `function_app_name` | Required, globally unique | Collector Function App name |
| `function_instance_memory_in_mb` | `2048`; `2048` or `4096` | Memory assigned to each Flex Consumption collector instance |
| `collection_schedule` | `0 0 5 * * *` | Six-field UTC NCRONTAB timer schedule |
| `app_mode` | `live`; `live` or `combined` | Controls whether a newly published run contains live rows only or live plus retained labeled synthetic rows |
| `recommendation_enrichment_mode` | `auto`; `auto`, `targeted`, `full`, or `none` | Controls recommendation-to-machine API enrichment |
| `enable_experimental_endpoints` | `false` | Enables undocumented Defender compatibility probes |
| `full_enrichment_weekday` | `6`; Monday `0` through Sunday `6` | Full-enrichment day when mode is `auto` |
| `web_app_name` | Required, globally unique | Dashboard Web App name |
| `web_app_service_plan_name` | Required | Linux App Service plan name |
| `web_app_identity_name` | Required | User-assigned identity used by the dashboard |
| `web_app_sku_name` | `B1` | App Service plan SKU |
| `dashboard_entra_application_name` | `DVM Viewer` | App registration and Enterprise Application display name |
| `dashboard_data_browser_enabled` | `false` | Enables Data Evidence UI/API and assigns `Data.Evidence.Reader` to the access group |
| `dashboard_recommendation_tracking_enabled` | `false` | Enables shared dashboard-local work-status UI/API |
| `dashboard_recommendation_tracking_container` | `dvm-workflow` | Append-only workflow-event container |
| `dashboard_cache_seconds` | `300`; zero or greater | Per-process cache lifetime for verified current Azure datasets |
| `tags` | Application/environment/managed-by map | Tags merged onto Azure resources |

For **Tenant Root Group**, set `collector_management_group_id` to the Microsoft
Entra tenant GUID. Azure uses that GUID as the root management-group ID, so it
is expected for `tenant_id` and `collector_management_group_id` to match. Do
not use the display name `Tenant Root Group` or the full resource path.

`tfplan webapp` is cumulative: it preserves and plans the Function and Web App.
Terraform plan output normally displays only differences. A setting absent from
a no-op plan may already match Azure.

When the perimeter is enabled, Terraform also adds an inbound subscription rule
for `subscription_id`. This permits the Function, hosted Web App, and Azure
deployment service to reach Storage from the deployment subscription. Network
permission does not replace authentication: the private containers still
require Microsoft Entra tokens and the appropriate Storage data-plane role.

For the initial customer deployment,
`network_security_perimeter_allowed_ip_cidrs=["0.0.0.0/0"]` intentionally
leaves IPv4 sources unrestricted while the perimeter behavior is validated.
Replace it with approved operator or corporate egress CIDRs later. Customer
policy must permit `publicNetworkAccess=SecuredByPerimeter`; forcing
`publicNetworkAccess=Disabled` prevents the no-VNet architecture from operating.

## 3. Data-mode behavior

| `APP_MODE` / `app_mode` | Published current run |
|---|---|
| `live` | Current Defender/Graph/Azure data only |
| `combined` | Current live data plus retained rows labeled `DataOrigin=Synthetic` |
| `synthetic` | Local generation/build mode only; rejected by deployed Terraform |

Changing from `combined` to `live` does not delete any blob, run, directory,
container, storage account, or historical evidence. The first successful live
run writes a new immutable run and then replaces only
`current/manifest.json`. Until that succeeds, readers continue using the prior
combined run. Older synthetic and combined runs remain retained and immutable.

## 4. Collector and dashboard runtime settings

These can be environment variables or keys in
`config/vulnerability-view.json`. Environment variables take precedence.

| Environment variable | JSON key | Default | Effect |
|---|---|---|---|
| `AUTH_MODE` | `authMode` | `auto` | Normal Azure authentication setting: current Azure CLI identity locally and managed identity when hosted; `client_secret` is an explicit local-only exception |
| `AZURE_TENANT_ID` | `azureTenantId` | Empty | Entra tenant for local or explicit credentials |
| `AZURE_CLIENT_ID` | `azureClientId` | Empty | Leave empty for normal deployment/local Web App use; client ID and application ID are the same Entra identifier and are needed only for explicit local client-secret mode |
| `AZURE_CLIENT_SECRET` | None | Empty | Local-only service-principal secret; never place in tracked JSON |
| `ALLOW_LOCAL_CLIENT_SECRET` | None | `false` | Explicit acknowledgement required for local client-secret auth |
| `DEFENDER_API_BASE_URL` | `defenderApiBaseUrl` | `https://api.security.microsoft.com` | Defender for Endpoint API root |
| `AZURE_SUBSCRIPTION_ID` | `azureSubscriptionId` | Empty | Local Azure subscription context and diagnostic-script override |
| `AZURE_MANAGEMENT_GROUP_ID` | `azureManagementGroupId` | Empty | Management group whose nested subscriptions are collected |
| `AZURE_RESOURCE_GROUP` | `azureResourceGroup` | Empty | Local Azure resource-group context and diagnostic-script override |
| `AZURE_LOCATION` | `azureLocation` | `eastus` | Local Azure location metadata |
| `STORAGE_ACCOUNT_NAME` | `storageAccountName` | Empty | History storage account |
| `STORAGE_CONTAINER_NAME` | `storageContainerName` | `dvm-history` | Immutable history container |
| `STORAGE_CURRENT_CONTAINER_NAME` | `storageCurrentContainerName` | `dvm-current` | Current-pointer container |
| `APP_MODE` | `appMode` | `live` | `live` is the default; `combined` and `synthetic` are explicit test/evaluation options, and deployed Terraform permits only live/combined |
| `SYNTHETIC_SEED` | `syntheticSeed` | `24017` | Deterministic synthetic generator seed |
| `SYNTHETIC_MONTHS` | `syntheticMonths` | `6` | Number of synthetic history months |
| `SYNTHETIC_DEVICE_COUNT` | `syntheticDeviceCount` | `2500`; 1-100000 | Number of generated synthetic devices |
| `RECOMMENDATION_ENRICHMENT_MODE` | `recommendationEnrichmentMode` | `auto` | `auto`, `targeted`, `full`, or `none` |
| `ENABLE_EXPERIMENTAL_ENDPOINTS` | `enableExperimentalEndpoints` | `false` | Enables undocumented optional endpoint probes |
| `FULL_ENRICHMENT_WEEKDAY` | `fullEnrichmentWeekday` | `6` | Weekly full-enrichment weekday, Monday 0 through Sunday 6 |
| `COLLECTION_SCHEDULE` | `collectionSchedule` | `0 0 5 * * *` | UTC Functions timer schedule |
| `DASHBOARD_DATA_SOURCE` | `dashboardDataSource` | `local` | `local` reads `dashboard/data`; `azure` reads current manifest and curated blobs |
| `DASHBOARD_STATIC_DIR` | `dashboardStaticDir` | Empty | Override path for dashboard static assets |
| `DASHBOARD_CACHE_SECONDS` | `dashboardCacheSeconds` | `30`; zero or greater | Verified dataset cache duration |
| `DASHBOARD_AUTH_ENABLED` | `dashboardAuthEnabled` | `false` | Requires App Service Easy Auth identity when enabled |
| `DASHBOARD_DATA_BROWSER_ENABLED` | `dashboardDataBrowserEnabled` | `false` | Enables read-only Data Evidence surface |
| `DASHBOARD_DATA_BROWSER_ROLE` | `dashboardDataBrowserRole` | Empty | Optional Easy Auth role required by Data Evidence |
| `DASHBOARD_RECOMMENDATION_TRACKING_ENABLED` | `dashboardRecommendationTrackingEnabled` | `false` | Optional dashboard-only collaboration state; not required for collection, lifecycle reporting, or remediation evidence |
| `DASHBOARD_RECOMMENDATION_TRACKING_ROLE` | `dashboardRecommendationTrackingRole` | `Recommendation.Tracker` | Legacy compatibility setting; tracking no longer requires this role |
| `DASHBOARD_RECOMMENDATION_TRACKING_CONTAINER` | `dashboardRecommendationTrackingContainer` | `dvm-workflow` | Workflow event container |

Azure-host markers `WEBSITE_HOSTNAME`, `IDENTITY_ENDPOINT`, and `MSI_ENDPOINT`
are platform-provided. They are used to identify managed hosting and must not be
fabricated for local development.

## 5. Terraform-generated Function App Settings

The collector Function receives these from `main.tf`; edit the corresponding
Terraform input rather than changing the generated setting in the portal.

| Azure App Setting | Source / purpose |
|---|---|
| `APP_MODE` | `var.app_mode` |
| `AUTH_MODE` | Fixed to `managed_identity` |
| `AZURE_CLIENT_ID` | Collector user-assigned managed identity |
| `AzureWebJobsFeatureFlags` | `EnableWorkerIndexing` for Python Functions |
| `AzureWebJobsStorage__accountName` | Function runtime storage account |
| `AzureWebJobsStorage__clientId` | Collector managed identity |
| `AzureWebJobsStorage__credential` | Fixed to `managedidentity` |
| `COLLECTION_SCHEDULE` | `var.collection_schedule` |
| `DEFENDER_API_BASE_URL` | Microsoft Defender API root |
| `ENABLE_EXPERIMENTAL_ENDPOINTS` | `var.enable_experimental_endpoints` |
| `FULL_ENRICHMENT_WEEKDAY` | `var.full_enrichment_weekday` |
| `RECOMMENDATION_ENRICHMENT_MODE` | `var.recommendation_enrichment_mode` |
| `STORAGE_ACCOUNT_NAME` | Protected history storage account |
| `STORAGE_CONTAINER_NAME` | Immutable history container |
| `STORAGE_CURRENT_CONTAINER_NAME` | Current-pointer container |

## 6. Terraform-generated Web App Settings

| Azure App Setting | Source / purpose |
|---|---|
| `AUTH_MODE` | Fixed to `managed_identity` |
| `AZURE_CLIENT_ID` | Dashboard user-assigned managed identity |
| `DASHBOARD_AUTH_ENABLED` | Fixed to `true` in Azure |
| `DASHBOARD_CACHE_SECONDS` | `var.dashboard_cache_seconds` |
| `DASHBOARD_DATA_BROWSER_ENABLED` | `var.dashboard_data_browser_enabled` |
| `DASHBOARD_DATA_BROWSER_ROLE` | `Data.Evidence.Reader` when enabled |
| `DASHBOARD_DATA_SOURCE` | Fixed to `azure` |
| `DASHBOARD_RECOMMENDATION_TRACKING_CONTAINER` | Workflow container variable |
| `DASHBOARD_RECOMMENDATION_TRACKING_ENABLED` | Tracking feature variable |
| `DASHBOARD_RECOMMENDATION_TRACKING_ROLE` | Legacy compatibility value |
| `DASHBOARD_STATIC_DIR` | Fixed to `dashboard` |
| `MICROSOFT_PROVIDER_AUTHENTICATION_SECRET` | Terraform-created Easy Auth secret; sensitive |
| `SCM_DO_BUILD_DURING_DEPLOYMENT` | Enables App Service/Oryx build |
| `STORAGE_ACCOUNT_NAME` | Protected history storage account |
| `STORAGE_CONTAINER_NAME` | Immutable history container |
| `STORAGE_CURRENT_CONTAINER_NAME` | Current-pointer container |

## 7. SLA and lifecycle policy

File: `config/sla-policies.json`

| Setting | Effect |
|---|---|
| `schemaVersion` | Policy document schema |
| `policyVersion` | Version copied into findings and retained run metadata |
| `lifecycle.fixedConfirmationRuns` | Consecutive absent runs required before a finding becomes fixed |
| `lifecycle.deviceFreshnessHours` | Device freshness window used when interpreting absence |
| `policies[].policyName` | Stable policy label |
| `policies[].severity` | Finding severity matched by the policy |
| `policies[].knownExploitRequired` | Whether known exploit evidence is required |
| `policies[].slaDays` | Days from SLA start to due time |

Changing this file affects newly processed runs. Prior immutable runs retain
their original policy file and policy version.

## 8. Dashboard presentation

File: `dashboard/config.js`

| Setting | Effect |
|---|---|
| `revision` | Source revision displayed locally; `tfdeploy webapp` replaces it in the deployment package with that package's UTC build time |
| `workloadGrouping.rules` | Ordered UI grouping rules. Each rule supports `id`, `label`, `field`, and `operator` (`prefix`, `contains`, or `exact`) plus `value`; first match wins. Azure VM scale-set resource IDs are grouped automatically before configured rules. |
| `branding.eyebrow` | Small header label |
| `branding.title` | Main dashboard title |
| `theme.primary` | Primary six-digit hex color |
| `theme.accent` | Accent six-digit hex color |
| `theme.density` | Presentation density label |
| `navigation.order` | Dashboard section order |
| `navigation.hidden` | Section IDs hidden from navigation |
| `filters.expandedByDefault` | Initial filter-panel state |
| `filters.defaultSeverity` | Initial severity selection |
| `filters.defaultHideNonReporting` | Whether devices outside the reporting-age window are hidden initially; defaults to `false` so retained evidence remains visible |
| `filters.defaultReportingDays` | Initial reporting-age window; supported values are `7`, `14`, `30`, `60`, and `90` |
| `filters.defaultIncludeDiscoveredOnly` | Whether non-onboarded discovery-only devices appear in Assets initially; defaults to `false` |
| `filters.defaultRecommendationTypes` | Initial recommendation-type selections |
| `filters.defaultDomains` | Initial asset-domain selections |
| `diagnostics.showExperimentalEndpoints` | Whether experimental endpoint diagnostics are shown |
| `authentication.showStatus` | Whether authentication status is displayed |

Workload grouping changes presentation and remediation counts only. It never
removes raw instances or findings. Azure resource IDs containing
`/virtualMachineScaleSets/<name>` group automatically. Add ordered rules for
organization-specific naming conventions:

```javascript
workloadGrouping: {
  rules: [
    {
      id: "generated-scale-hosts",
      label: "Generated scale workload",
      field: "DeviceName",
      operator: "prefix",
      value: "gen-",
    },
  ],
},
```

Supported operators are `prefix`, `contains`, and `exact`, compared
case-insensitively. The first matching rule wins. Use separate, more-specific
rules before a broad prefix when multiple scale sets share a naming stem.

Asset query versions in `dashboard/index.html` control browser cache busting for
`styles.css`, `config.js`, and `app.js`.

## 9. Azure Functions host and local launch controls

`host.json`:

| Setting | Effect |
|---|---|
| `version` | Functions host schema version |
| `logging.applicationInsights.samplingSettings.isEnabled` | Enables Application Insights sampling |
| `logging.applicationInsights.samplingSettings.excludedTypes` | Telemetry types excluded from sampling |
| `extensionBundle.id` | Functions extension bundle |
| `extensionBundle.version` | Allowed extension-bundle range |

`local.settings.json` contains local Functions host values such as
`AzureWebJobsStorage`, `FUNCTIONS_WORKER_RUNTIME`, and
`AZURE_FUNCTIONS_ENVIRONMENT`, plus any runtime variables from section 4.

`start-app.sh` controls:

| Value | Default | Effect |
|---|---|---|
| Positional port argument | `8000` | Local dashboard TCP port |
| `HOST` | `127.0.0.1` | Local bind address |
| `DASHBOARD_RELOAD` | `true` | Enables Uvicorn source/static reload |
| `DASHBOARD_RECOMMENDATION_TRACKING_ENABLED` | `false` | Optional; when explicitly enabled locally, tracking is in memory and resets with the process |

## 10. Operational script inputs

| Script | Input | Effect |
|---|---|---|
| `infra/deploy.sh` | `tfplan`, `tfapply`, `tfdeploy`, `tfverify`, `tfinvoke`, or `tfdestroy` plus stage | Selects the deployment operation |
| `infra/deploy.sh` | `CONFIRM_LIVE_COLLECTION=yes` | Required acknowledgement before manual collection |
| `infra/deploy.sh` | `CONFIRM_TF_DESTROY_FUNCTION=yes` | Required before removing only replaceable Function infrastructure |
| `infra/check-runs.sh` | Optional positive count | Number of published immutable run manifests to inspect |
| `infra/check-runs.sh` | `STORAGE_ACCOUNT_NAME`, `STORAGE_CONTAINER_NAME` | Optional history-location overrides |
| `infra/check-runs.sh` | `ENABLE_EXPERIMENTAL_ENDPOINTS` | Includes experimental endpoint results |
| `infra/check-function-logs.sh` | Optional positive hours and count | Log window and invocation count |
| `infra/check-function-logs.sh` | `AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP`, `FUNCTION_APP_NAME`, `LOG_ANALYTICS_WORKSPACE_NAME` | Optional diagnostic target overrides |

Operational status scripts are read-only. `check-runs.sh` lists only completed,
published manifests; failed invocations that never publish a manifest appear
only in Function diagnostics.

## 11. Dependency and packaging configuration

`pyproject.toml` defines Python `>=3.12`, runtime dependencies, the
`vulnerability-view` CLI entry point, setuptools package discovery, and pytest
paths. `requirements.txt` is the deployment dependency lock used by Azure
package builds. Change dependency versions coherently in both files.
