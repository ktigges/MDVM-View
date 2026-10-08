# Greenfield Azure deployment

> **Last modified:** 2026-10-08
> **Purpose:** Create and validate a new protected Azure environment from Windows PowerShell, macOS, or Linux in three reviewed Terraform stages.

This workflow creates a new environment without changing or deleting any
existing DVM history. It does not manage or remove storage accounts,
containers, or populated data outside the reviewed Terraform state.

Use this document as the concise operator checklist. The canonical explanation
of requirements, permissions, resource behavior, package deployment, dashboard
assignment, and recovery boundaries is the
[Azure deployment guide](../DEPLOY.md). New evaluators should complete
[Local evaluation and datasets](local-evaluation.md) only when they need the
separate local-only development path.

The `vulnerability-view-ops` commands keep Terraform planning, application,
deployment, and verification as separate explicit operations.

## Values to set

Environment-specific values are intentionally excluded from source control. Create the
local variable file from the tracked example, then replace every sample value:

```bash
cp infra/terraform/main.tfvars.example.json infra/terraform/main.tfvars.json
```

Keep `main.tfvars.json`, `*.tfvars`, and `*.auto.tfvars*` out of source control.
Only example files belong in the source repository.

| Value | What to provide |
|---|---|
| `subscription_id` | Azure subscription GUID that will own the environment |
| `tenant_id` | Microsoft Entra tenant GUID containing Defender |
| `collector_management_group_id` | Management group ID containing the subscriptions to inventory; use the ID, not the display name or full resource path |
| `resource_group_name` | New resource group name |
| `location` | Region supported by Azure Functions Flex Consumption |
| `history_storage_account_name` | Globally unique name for protected ADLS Gen2 history |
| `function_runtime_storage_account_name` | Globally unique name for replaceable Functions host storage |
| `function_app_name` | Globally unique Function App name |
| `function_instance_memory_in_mb` | `2048` normally; use `4096` when measured collector working set requires it |
| `app_mode` | `combined` for labeled synthetic plus live test data; `live` for production |
| `collection_schedule` | Six-field NCRONTAB expression in UTC; `0 0 5 * * *` means daily at 05:00 UTC |
| `history_storage_replication_type` | `LRS`, `ZRS`, `GRS`, or `GZRS` |
| `storage_soft_delete_days` | Recovery period from 7 through 365 days |
| `history_immutability_days` | Minimum WORM retention for history blobs; 365 days for this environment |
| `lock_history_immutability_policy` | Keep `false` until validation is complete; locking cannot be reversed or shortened |
| `grant_deployer_history_access` | Grants the Terraform execution identity Blob data access for local seeding, backfill, restore, and status |
| `tags` | Organization ownership, environment, application, and cost tags |

Storage names must contain only lowercase letters and numbers and be 3-24
characters. The Function App name must be globally unique.

All supplied example resource names use `dvmviewer` as the product prefix.

For **Tenant Root Group**, use the Microsoft Entra tenant GUID as
`collector_management_group_id`. The matching values for `tenant_id` and
`collector_management_group_id` are expected because Azure uses the tenant GUID
as the root management-group ID.

## Required operator permissions

The person running Terraform needs permission to:

- Create resources and Azure role assignments in the subscription.
- Create the collector Reader assignment at the configured management-group
  scope.
- Create Microsoft Entra application-role assignments.
- Read the WindowsDefenderATP and Microsoft Graph enterprise applications.
- Grant the managed identity these application permissions:
  - `Machine.Read.All`
  - `Vulnerability.Read.All`
  - `SecurityRecommendation.Read.All`
  - `SecurityEvents.Read.All`

The Terraform AzureAD provider creates those four assignments during the
Function stage. No client secret is created or stored.

## Sign in

```bash
az login --tenant "<tenant-id>"
az account set --subscription "<subscription-id>"
az account show --query "{name:name,id:id,tenantId:tenantId}" --output table
```

## Stage 1: foundation

This creates:

- A new resource group.
- A protected ADLS Gen2 storage account.
- Private `dvm-history` and `dvm-current` containers.
- Thirty-day blob and container soft delete by default.
- An unlocked 365-day WORM policy on `dvm-history`; `dvm-current` remains
  mutable so its manifest pointer can advance.

Historical storage and both containers have Terraform `prevent_destroy`
protection. Application writes under `raw/`, `curated/`, and `runs/` remain
append-only. Only `dvm-current/current/manifest.json` is replaceable.

Soft delete provides a recovery window after an eligible deletion. WORM blocks
modification and deletion during the retention period. Soft delete does not
delete active data, but its retained deleted copy expires after the recovery
window. WORM expiration does not delete history, and this deployment does not
configure a lifecycle deletion rule.

```bash
vulnerability-view-ops plan foundation
terraform -chdir=infra/terraform show foundation.tfplan
vulnerability-view-ops apply foundation
vulnerability-view-ops verify foundation
```

Review the plan before applying. It should contain creates only.
The verification command confirms that the signed-in deployment identity can
list the two private containers using Microsoft Entra authentication. Role
assignment propagation can take several minutes.

## Stage 2: collector Function

Change `deploy_function` to `true`, then run:

```bash
vulnerability-view-ops plan function
terraform -chdir=infra/terraform show function.tfplan
vulnerability-view-ops apply function
vulnerability-view-ops deploy function
vulnerability-view-ops verify function
```

This creates the Flex Consumption plan, separate runtime storage, collector
managed identity, storage RBAC, Defender/Graph application-role assignments,
Log Analytics, Application Insights, diagnostics, and the Function App. The
Function runs at the UTC schedule in `collection_schedule`.

The deployment helper removes the AzureRM provider's legacy
`AzureWebJobsStorage` setting before publishing. The Function then uses only
managed-identity host-storage settings.

To populate a test environment with six months of synthetic history, follow the
one-time local seed procedure in `DEPLOY.md` after the foundation is created.
The Function does not generate synthetic data. With `app_mode=combined`, later
live collections preserve the seeded rows under their `Synthetic` data-origin
label.

### Deployed collector run options

| Option | Use | Operation |
|---|---|---|
| Scheduled timer | Normal unattended collection | The Function runs at the UTC `collection_schedule`; the default is daily at 05:00 UTC. |
| Guarded one-shot run | Initial validation, recovery from a missed schedule, or an intentional out-of-band snapshot | Run `vulnerability-view-ops invoke function --confirm`. |
| Schedule change | Change the recurring cadence | Update `collection_schedule`, run and review `tfplan function`, then run `tfapply function`. A code-package deployment is not required for only an application-setting change. |

The one-shot helper invokes the existing timer function through the Azure
Functions admin endpoint. It retrieves the host master key into a temporary
shell variable and does not print or persist it. Prefer the helper over copying
the key into a command, script, shell history, or operator document.

Every option executes the same `collect-live` path. A successful run writes new
immutable `raw/`, `curated/`, and `runs/` paths, then replaces only
`dvm-current/current/manifest.json`. The current synchronous pilot does not have
an application-level distributed lock. Check Application Insights for an active
invocation and do not start a one-shot run while the timer is running.

## Stage 3: Web App

The optional cumulative Web App stage creates:

- one Linux B1 App Service plan and Web App;
- one user-assigned managed identity with Storage Blob Data Reader;
- one single-tenant Entra application and Enterprise Application named `DVM Viewer`;
- `Dashboard.Viewer` and `Data.Evidence.Reader` app roles;
- assignment-required access for the configured Entra group;
- App Service Easy Auth with unauthenticated requests redirected to Entra;
- Azure-backed dashboard settings and a 300-second verified-bundle cache.

Terraform creates the assignment-required `DVM Viewer` Enterprise Application
but does not create an access group or assign users. A tenant administrator
assigns authorized existing users or groups to `Dashboard Viewer` and any
required optional roles through the Enterprise Application.

Group-based Enterprise Application assignment requires the applicable
Microsoft Entra ID licensing. If it is unavailable, assign individual users
the `Dashboard.Viewer` role.

```bash
vulnerability-view-ops plan webapp
terraform -chdir=infra/terraform show webapp.tfplan
vulnerability-view-ops apply webapp
vulnerability-view-ops deploy webapp
vulnerability-view-ops verify webapp
```

After apply, Terraform outputs
`dashboard_enterprise_application_object_id` and
`dashboard_entra_client_id` identify `DVM Viewer`. Manage assignments at
**Microsoft Entra ID > Enterprise applications > DVM Viewer > Users and
groups**. Confirm the proposed globally unique `web_app_name` before apply.

The Web App plan is cumulative and preserves the foundation and Function.
After the Web App exists, use the `webapp` planning stage for subsequent
infrastructure changes so Terraform retains all three stages.

The application rejects requests that do not contain the trusted Easy Auth
principal. The Enterprise Application independently prevents unassigned users
from signing in. If the hidden Data evidence browser is enabled, authorized
group members open `/?view=data-browser`; its API also verifies the
`Data.Evidence.Reader` role.

Easy Auth uses an application credential with a two-year lifetime and an annual
Terraform rotation trigger. Run and apply a reviewed Web App plan at least
annually. Terraform then replaces the credential and updates the protected Web
App setting together, leaving a one-year renewal margin.

## Validation and utilities

Check Defender access locally before invoking a collection:

```bash
vulnerability-view-ops preflight
```

This tests the signed-in developer identity. The deployed managed identity is
tested by invoking the timer workload:

```bash
vulnerability-view-ops invoke function --confirm
vulnerability-view-ops verify function
```

The confirmation is required because invocation writes a new immutable live
run and advances the new environment's current manifest.

The Azure portal's timer **Test/Run** operation reaches the same administrative
invocation surface, but the repository helper is preferred because it makes the
write confirmation explicit and avoids manually handling the host key.

For normal development, point the locally running Web App at the new account:

```dotenv
DASHBOARD_DATA_SOURCE=azure
STORAGE_ACCOUNT_NAME=<new-history-storage-account>
STORAGE_CONTAINER_NAME=dvm-history
STORAGE_CURRENT_CONTAINER_NAME=dvm-current
```

Then run `./start-app.sh`. UI, normalization, SLA, and replay work can remain
local; redeploy only when testing hosted Function behavior.

## Removing the replaceable Function stage

The helper can remove only the Function stage. It cannot target protected
history storage or the foundation resource group.

```bash
vulnerability-view-ops destroy function --confirm
```

Review the displayed destroy plan before Terraform asks for final approval.
The history account and its containers have `prevent_destroy` protection and
are not included in this operation.

## Command reference

| Command | Purpose |
|---|---|
| `tfplan foundation` | Save a plan for the resource group and protected storage |
| `tfapply foundation` | Apply the reviewed foundation plan |
| `tfverify foundation` | Verify deployer Blob data access to the history account |
| `tfplan function` | Save a plan for Function infrastructure and permissions |
| `tfapply function` | Apply the reviewed Function plan |
| `tfdeploy function` | Build and publish the Function code |
| `tfverify function` | Verify host readiness, timer discovery, and Azure data |
| `tfpreflight` | Test Defender routes with the local signed-in identity |
| `tfinvoke function` | Explicitly invoke one live collection |
| `tfdestroy function` | Remove only replaceable Function resources |
