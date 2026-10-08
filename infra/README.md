# Infrastructure operations and `deploy.sh` reference

> **Last modified:** 2026-10-08
> **Purpose:** Provide identical Windows, macOS, and Linux operations while explaining what the legacy `infra/deploy.sh` wrapper does, which tools and identities are used, and when to plan, apply, package, verify, invoke, or remove an application stage.

The supported platform-neutral interface is
`python -m vulnerability_view.operations_cli`. The Bash
scripts remain available for compatibility. Use the repository-level
[Azure deployment guide](../DEPLOY.md) for the complete greenfield procedure and
permissions model.

## Cross-platform operations CLI

The same commands work in Windows PowerShell, macOS, and Linux after activating
the platform's virtual environment:

```text
python -m vulnerability_view.operations_cli plan foundation
python -m vulnerability_view.operations_cli apply foundation
python -m vulnerability_view.operations_cli deploy function
python -m vulnerability_view.operations_cli verify function
python -m vulnerability_view.operations_cli deploy webapp
python -m vulnerability_view.operations_cli verify webapp
python -m vulnerability_view.operations_cli check-runs --limit 10 --progress
python -m vulnerability_view.operations_cli check-function-logs --hours 1 --limit 10 --status-only
python -m vulnerability_view.operations_cli invoke function --confirm
```

Install or refresh the editable project once after pulling CLI changes on
macOS or Linux:

```text
python -m pip install -e ".[dev]"
```

Activate the environment on macOS/Linux:

```bash
source .venv/bin/activate
```

On Windows PowerShell, create and activate a separate environment:

```powershell
python3 --version
python3 -m venv .venv-win
.\.venv-win\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -c "import sys, vulnerability_view; print(sys.executable)"
```

If `python3` is not available on Windows, use `py -3.14` for the first two
commands.

The verification output must end in `.venv-win\Scripts\python.exe`. After
activation, run operations as
`python -m vulnerability_view.operations_cli <command>`. If activation is
blocked, use
`.\.venv-win\Scripts\python.exe -m vulnerability_view.operations_cli <command>`
as a fallback.

The Python CLI replaces platform-sensitive Bash, `date`, `jq`, `curl`, and
external ZIP operations with Python implementations. Azure CLI, Terraform, and
Git remain external prerequisites because they perform the actual Azure,
infrastructure, and source-version operations.

The legacy equivalents remain:

```text
./infra/deploy.sh tfdeploy function
./infra/check-runs.sh 10 --progress
./infra/check-function-logs.sh 1 10 --status-only
```

On native Windows, use `python -m vulnerability_view.operations_cli`; the `.sh` scripts require WSL or
another Bash environment.

## Identity model

There are two different identities.

### Local operator identity

Terraform and Azure CLI commands normally run as the user currently authenticated
by `az login`. Before planning, applying, deploying, verifying, or invoking, check:

```bash
az account show \
  --query '{User:user.name,UserType:user.type,Tenant:tenantId,Subscription:name,SubscriptionId:id}' \
  --output table
```

The tenant and subscription must match `tenant_id` and `subscription_id` in the
environment-specific `terraform/main.tfvars.json`.

`az account set --subscription ...` selects a subscription for the current login.
It does not change the signed-in user or tenant.

Terraform's AzureRM and AzureAD providers use the current Azure CLI login unless
the workstation deliberately supplies another supported authentication method,
such as service-principal environment variables. Azure CLI operations in
`deploy.sh` always use the active Azure CLI context.

The local operator identity performs:

- Terraform initialization, validation, planning, and apply;
- role and Microsoft Entra changes described by the Terraform plan;
- Function and Web App package upload;
- deployment verification;
- source API preflight;
- explicitly confirmed manual Function invocation.

### Deployed runtime identities

Scheduled Function collections and Web App requests do not run as the interactive
operator.

- The Function uses its configured collector managed identity.
- The Web App uses its configured dashboard managed identity.
- Terraform assigns the required Azure RBAC and application permissions.

Signing out of Azure CLI after deployment does not change either runtime identity.

## Local prerequisites

Run commands from the repository root. The script expects:

| Tool or file | Used for |
|---|---|
| Python 3.12 or tested Python 3.14.7 | Cross-platform orchestration, ZIP creation, HTTP, JSON, and time handling; Azure runtimes remain on Python 3.12 |
| `az` | Azure package deployment, verification, keys, settings, and invocation |
| Terraform 1.10+ | Infrastructure initialization, plan, apply, output, and validation; on Windows it may be on `PATH` or saved as repository-root `terraform.exe` |
| `git` | Function commit metadata and fallback release version |
| `.venv/` or `.venv-win/` | Project Python, status, and Defender preflight commands |
| `terraform/main.tfvars.json` | Ignored environment names, IDs, settings, and Function version |
| Terraform state | Existing-resource identity and outputs consumed by package operations |

The supplied configuration writes Terraform state locally to
`infra/terraform/terraform.tfstate` on the deployment workstation. A shared
remote backend can be configured separately, but remote-state setup and
migration are not part of this deployment documentation.

Do not commit `main.tfvars.json`, Terraform state, saved plans, packages, or local
operator notes.

On Windows, the operations CLI first checks for `terraform.exe` in the
repository root and then checks `PATH`. This allows a customer to use an
approved standalone Terraform executable without changing the system or user
`PATH`. Keep the executable at the repository root, not in `infra/terraform/`;
it is excluded from Git.

## What the script calls

The Python operations CLI calls:

- `terraform init`, `validate`, `plan`, `show`, `apply`, and `output`;
- `az storage container list`;
- `az functionapp` settings, restart, ZIP deployment, keys, and function listing;
- Azure Resource Manager trigger synchronization through `az rest`;
- `az webapp deploy`, deployment-log queries, and Web App inspection;
- the local `vulnerability-view` CLI for preflight and current-storage status;
- Git for version metadata;
- Python `zipfile`, `requests`, `json`, and `datetime` for portable packaging,
  HTTP, configuration, and UTC timestamp handling.

`deploy.sh` calls the same Azure and Terraform surfaces but uses Bash, `zip`,
`jq`, `curl`, and platform shell utilities.

It does not directly delete retained ADLS history.

## Cumulative Terraform stages

The Terraform stages are cumulative:

1. `foundation` — resource group and protected history storage;
2. `function` — foundation plus collector Function, identities, permissions,
   runtime storage, schedule, and monitoring;
3. `webapp` — foundation and Function plus the authenticated dashboard.

The Function stage grants its managed identity Reader once at
`collector_management_group_id`. The collector then inventories subscriptions
under that management group and nested management groups.

Once the Web App exists, use `tfplan webapp` for later infrastructure changes so
the saved plan preserves all deployed stages. The helper blocks lower-stage plans
when they would omit a known higher stage.

## Command matrix

| Command | What it does | Terraform? | Azure login? |
|---|---|---:|---:|
| `plan foundation/function/webapp` | Initializes, validates, and saves the stage plan | Plan only | Yes |
| `apply <stage>` | Applies only the already-saved reviewed plan | Apply | Yes |
| `deploy function` | Builds and uploads Function code to existing infrastructure | No | Yes |
| `deploy webapp` | Builds and uploads dashboard code to existing infrastructure | No | Yes |
| `verify foundation/function/webapp` | Reads deployed resources and current state | Outputs only | Yes |
| `preflight` | Tests Defender source access as the local signed-in user | No | Yes |
| `invoke function --confirm` | Starts one live collection after explicit confirmation | No | Yes |
| `destroy function --confirm` | Plans, shows, and applies removal of replaceable Function resources | Apply | Yes |
| `check-runs --progress` | Shows active telemetry plus durable completed runs | No | Yes |
| `check-function-logs` | Queries Function invocation telemetry | No | Yes |

## `tfplan`

Example:

```bash
python -m vulnerability_view.operations_cli plan function
```

The command calls:

```text
terraform init -input=false
terraform validate
terraform plan -input=false -var-file=main.tfvars.json ... -out=function.tfplan
```

It does not apply the plan. Review it:

```bash
python -m vulnerability_view.operations_cli show function
```

Saved plans can contain environment-specific information and must not be
committed.

## `tfapply`

Example:

```bash
python -m vulnerability_view.operations_cli apply function
```

The command refuses to continue unless the matching saved plan exists. It applies
that exact plan and does not regenerate or refresh it. If configuration changed
after planning, create and review a new plan.

## `tfdeploy function`

Example:

```bash
python -m vulnerability_view.operations_cli deploy function
```

This is a code-package update. It does not run Terraform. It requires existing
Terraform outputs for the resource group and Function App.

The command:

1. Reads `function_version` from `main.tfvars.json`.
2. Uses `FUNCTION_VERSION` as a one-command override when supplied.
3. Falls back to the Git tag/commit when no configured version exists.
4. Creates temporary build metadata with version, UTC time, and Git commit.
5. Packages `function_app.py`, `host.json`, dependencies, `src/`, the SLA policy,
   and build metadata.
6. Removes the legacy `AzureWebJobsStorage` setting that would override the
   managed-identity host-storage configuration.
7. Restarts the Function and waits for configuration/RBAC propagation.
8. Uploads the ZIP using Azure Function remote build.
9. Sets `COLLECTOR_VERSION` only after successful package deployment.
10. Synchronizes Function triggers through Azure Resource Manager.

The command does not invoke a collection. A scheduled run occurs only when its
timer is due; a manual run requires `tfinvoke function`.

## `tfdeploy webapp`

Example:

```bash
python -m vulnerability_view.operations_cli deploy webapp
```

This is also a code-package update and does not run Terraform. It reads
`dashboard_version` from `main.tfvars.json` (or a one-command
`DASHBOARD_VERSION` override), stamps that release plus the UTC deployment
revision into the UI, packages the dashboard and Python server without local
dashboard data, uploads a clean ZIP deployment, and monitors Kudu/Oryx
deployment status. A client-side timeout is treated as provisional until Kudu
reports success or failure.

Function and Web App package deployments are independent:

```bash
./infra/deploy.sh tfdeploy function  # collector only
./infra/deploy.sh tfdeploy webapp    # dashboard only
```

## `tfverify`

Verification is read-only against the deployed resources.

Function verification prints the configured collector version, lists keys and
timer triggers, then uses the local CLI with the current local Azure credential
and Terraform-provided storage names to report the current durable run.

Web App verification shows the site state and hostname, checks that an anonymous
request receives the expected authentication redirect, and prints the Enterprise
Application assignment details.

## `tfpreflight`

```bash
./infra/deploy.sh tfpreflight
```

This tests Defender endpoints as the current local Azure CLI identity. A successful
preflight does not prove that the Function managed identity has the same access;
verify the deployed Function separately.

## `tfinvoke function`

First confirm that no run is active:

```bash
python -m vulnerability_view.operations_cli check-runs --limit 5 --progress
```

Then explicitly acknowledge that the invocation writes a new immutable run:

```bash
python -m vulnerability_view.operations_cli invoke function --confirm
```

The script retrieves the Function host key using the current Azure CLI identity and
posts to the Function administration endpoint. The collector itself then runs as
the Function managed identity.

Never invoke when status is `ACTIVE` or `INDETERMINATE`.

## `tfdestroy function`

This is not part of normal deployment or code updates. It requires:

```bash
python -m vulnerability_view.operations_cli destroy function --confirm
```

The command targets replaceable Function resources only, displays its destruction
plan, and preserves the protected history account and retained evidence. Always
review the plan. Never interpret “start over,” “reset,” or “redeploy” as approval
to delete retained Azure Storage data.

## Common workflows

### Initial deployment

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

python -m vulnerability_view.operations_cli plan webapp
python -m vulnerability_view.operations_cli show webapp
python -m vulnerability_view.operations_cli apply webapp
python -m vulnerability_view.operations_cli deploy webapp
python -m vulnerability_view.operations_cli verify webapp
```

### Function code only

Update `function_version` in `terraform/main.tfvars.json`, then:

```bash
python -m vulnerability_view.operations_cli deploy function
python -m vulnerability_view.operations_cli verify function
```

### Dashboard code only

```bash
python -m vulnerability_view.operations_cli deploy webapp
python -m vulnerability_view.operations_cli verify webapp
```

### Infrastructure change after the Web App exists

```bash
python -m vulnerability_view.operations_cli plan webapp
python -m vulnerability_view.operations_cli show webapp
python -m vulnerability_view.operations_cli apply webapp
```

Deploy code afterward only when application code or its package changed.

## Safety boundaries

- `tfplan` does not apply.
- `tfapply` applies only a saved reviewed plan.
- `tfdeploy` does not create infrastructure or invoke collection.
- `tfinvoke` writes a new immutable run.
- Package updates do not delete Azure history.
- Local `output/` cleanup does not authorize Azure deletion.
- Paths under `raw/`, `curated/`, and `runs/` remain append-only.
- Only `current/manifest.json` is replaceable after successful run validation.
- The protected history account must survive Function or Web App replacement.

## Related documentation

- [Complete Azure deployment guide](../DEPLOY.md)
- [Greenfield deployment checklist](../docs/greenfield-deployment.md)
- [Command reference](../docs/command-reference.md)
- [Operations and monitoring](../docs/operations-and-configuration.md)
- [Troubleshooting](../docs/troubleshooting.md)
- [Configuration reference](../docs/configuration-reference.md)
