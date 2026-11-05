# Environment boundaries

The same Python application runs locally and in Azure. Configuration determines
the identity, data source, storage target, and enabled features. Separate
environments need separate resource names and state; changing `.env` does not
create a new Azure environment.

## Operating model

| Environment | Data and identity | Writes |
|---|---|---|
| Local replay or synthetic evaluation | Local files; no cloud credential needed for replay | Local generated output |
| Local live collection with `--local-only` | Authorized developer credential; real Defender, Graph, and Azure inventory calls | Local raw and curated files, not Azure Storage |
| Local Azure-backed viewer | Developer credential with approved blob access | Reads the published snapshot; enabled features must be reviewed separately |
| Hosted collector | Collector managed identity | New immutable evidence and completed current pointer |
| Hosted dashboard | Separate Web App managed identity; users sign in through Entra | Evidence reads plus explicitly enabled workflow, branding, and viewer-cache writes |

Local collection without `--local-only` can publish to configured Azure Storage.
It is not an isolated test merely because it runs on a workstation.
Sample files and snapshots contain unredacted security and device data.

## Infrastructure and state

Terraform defines the protected foundation, collector, and Web App. The stages
are cumulative. After the Web App exists, later infrastructure plans use
`webapp`, not a lower stage that would remove application resources.

Environment values are in uncommitted `infra/terraform/main.tfvars.json`.
Local application settings are in `.env`; local Functions host settings are
in `local.settings.json`. Terraform does not read either local runtime file.
The [configuration reference](configuration-reference.md) explains overlap
and precedence.

The supplied backend stores state locally at
`infra/terraform/terraform.tfstate`. State and its backup are part of the
deployment handoff. Recreating the values file or cloning the repository does
not recover state. A shared remote backend needs its own provisioned storage,
access controls, migration, and recovery procedure; the project does not set
one up automatically.

## Environment separation

Development, test, and production have their own:

- Resource group and Terraform state.
- Protected history and separate Function runtime storage accounts.
- Function App, Web App, plans, and managed identities.
- Entra application and user/group assignments.
- Collection schedule, approved policy, and monitoring.

The history account is a protected data resource. Replacing a Function or
Web App does not replace that account. Existing retained containers remain
protected even if newer deployments use different naming defaults.

## Current hosted design

The collector is a Python Durable Functions application on a separate Linux
Dedicated B2 plan, with one worker and Always On. The timer or manual starter
requests a workflow; bounded collection work and retained processing checkpoints
support continuation after interruptions. Dedicated hosting does not prevent
maintenance, deployment, process, or resource-limit restarts.

The dashboard is a FastAPI application on a separate Linux App Service plan.
The default is B2 with one Uvicorn worker. Easy Auth handles Entra sign-in;
the application also checks the trusted principal. Users and groups receive
Enterprise Application roles outside Terraform.

The Web App reads retained evidence. Its separate workflow and viewer-cache
permissions do not grant writes to the history or current-pointer containers.
The full runtime sequence is in [Application flow](application-flow.md).

Existing Flex-hosted collectors need the reviewed
[hosting migration](../infra/README.md#collector-hosting-and-upgrading-existing-flex-deployments).
Deploying a new code package alone does not change hosting.

## Deployment handoff

The successor needs the authoritative state, protected environment values,
repository access, deployment permissions, and the administrators who manage
Entra assignments. The [deployment guide](../DEPLOY.md) defines permissions
and steps; the [operations guide](operations-and-configuration.md) covers
ongoing checks.

An operational handoff also records:

- The latest completed run and any active or failed collection.
- Installed collector and dashboard versions.
- The policy version and approved SLA targets.
- Schedule, expected freshness, alert recipients, and escalation ownership.
- Storage growth and available Web App disk/compute capacity.
- How state and operational records are backed up and recovered.

These are environment records, not source-controlled customer details.

## What remains environment-specific

The code supplies publication checks, authentication, progress reporting, and
cache verification. The deployment record supplies the approved collection scope,
SLA policy, access assignments, monitoring recipients, cost ownership, and recovery
arrangements. Those are operating decisions, not additional performance features
waiting to be built.
