# Greenfield deployment checklist

This is the short installation sequence. The [deployment guide](../DEPLOY.md)
contains prerequisites, permission details, network requirements, and recovery
boundaries. It is not a procedure for replacing an existing environment.

## Before deployment

- Python, Azure CLI, Terraform, and Git are installed and verified.
- The deployment identity has the documented Azure, Entra, and management-group
  role-assignment permissions.
- `infra/terraform/main.tfvars.json` has been copied from the example and all
  placeholders replaced, including unique names and the actual management-group ID.
- The target tenant, subscription, region, data policy, and SLA settings are approved.
- The state file and environment values have a protected backup location.

The [configuration reference](configuration-reference.md) defines the inputs.
Terraform controls hosted settings; `.env` controls local commands only.
Neither environment values nor state belongs in source control.

## Sign in

```bash
az login --tenant "<tenant-id>"
az account set --subscription "<subscription-id>"
az account show --query "{name:name,id:id,tenantId:tenantId}" --output table
```

The signed-in operator deploys resources. The applications use their managed
identities after deployment; they do not depend on that operator staying signed in.

## Streamlined complete deployment

```bash
./infra/deployment-menu.sh
```

```powershell
.\infra\deployment-menu.ps1
```

Menu option **1** plans the cumulative `webapp` stage, displays the plan,
requires approval, deploys and verifies both applications, and offers an initial
collection. Approval of a deployment is not approval to delete protected storage.

## Separate stages

Separate review can use the operations CLI instead. Each apply uses the saved,
reviewed plan:

| Stage | Resources | Operations |
|---|---|---|
| Foundation | Resource group, protected history/pointer/workflow storage, retention controls, network perimeter | `plan`, `show`, `apply`, `verify foundation` |
| Function | Dedicated B2 collector, runtime storage, identity, permissions, monitoring | `plan`, `show`, `apply`, `deploy`, `verify function` |
| Web App | Dashboard plan/app, identity, Entra application, authentication, viewer cache | `plan`, `show`, `apply`, `deploy`, `verify webapp` |

For example:

```bash
python -m vulnerability_view.operations_cli plan webapp
python -m vulnerability_view.operations_cli show webapp
python -m vulnerability_view.operations_cli apply webapp
python -m vulnerability_view.operations_cli deploy webapp
python -m vulnerability_view.operations_cli verify webapp
```

After the Web App exists, later infrastructure plans use `webapp` so all
deployed stages remain included. A dashboard-only code update needs menu
option **4**, not an infrastructure apply or new collection.

## Access and validation

Terraform creates an assignment-required Enterprise Application but does not
assign users or groups. Entra administrators assign **Dashboard Viewer** and
any approved optional roles. The [deployment guide](../DEPLOY.md#deploy-the-authenticated-dashboard-web-app)
covers sign-in and credential renewal.

A manual collection uses:

```bash
python -m vulnerability_view.operations_cli invoke function --confirm
python -m vulnerability_view.operations_cli check-runs --limit 5 --progress
```

The Durable workflow coordinates active work. A successful trigger request is
not a completed run; status must show progress and a verified publication.
An active or failed run retains its original scope and identity during recovery.

Dashboard validation includes ordinary-user sign-in, `dashboardReady`, snapshot
identity/time, representative queries, and any enabled role-restricted features.
The shell can load while indexes are still preparing.

## Storage boundary

The history account survives application replacement. Retained paths are
append-only; only the separate current manifest pointer is replaceable.
Soft-delete and WORM settings do not automatically purge history.

The Function runtime account is separate from retained DVM evidence. Existing
Flex deployments need the [reviewed hosting migration](../infra/README.md#collector-hosting-and-upgrading-existing-flex-deployments),
not this greenfield checklist.

Routine teardown is not part of this installation path. Exact destructive
targets require separate human approval.
