# Vulnerability View

> **Last modified:** 2026-09-28
> **Purpose:** Start in the right place to evaluate, install, operate, troubleshoot, and understand Vulnerability View.

Vulnerability View is a read-only collection and dashboard application for
Microsoft Defender Vulnerability Management. It correlates findings,
recommendations, devices, Secure Score, remediation activity, lifecycle state,
and example SLA calculations while retaining point-in-time evidence in
application-owned Azure Storage.

It does not change Defender data, perform remediation, or send dashboard state
back to Defender. Optional recommendation work status coordinates users in this
dashboard only.

## Start here

| Goal | Start with |
|---|---|
| Review the dashboard locally before creating Azure resources | [Local evaluation before Azure deployment](docs/local-evaluation.md) |
| Deploy protected storage, the collector Function, and the Web App | [Azure deployment guide](DEPLOY.md) |
| Use the shortest greenfield deployment checklist | [Greenfield Azure deployment](docs/greenfield-deployment.md) |
| Operate collections, monitoring, history, and dashboard access | [Operations and monitoring](docs/operations-and-configuration.md) |
| Diagnose a local, Function, storage, deployment, or UI problem | [Troubleshooting](docs/troubleshooting.md) |
| Understand finding lifecycle, priority, SLA, and work status | [Dashboard and collection logic](LOGIC.md) |
| Find a command | [Command reference](docs/command-reference.md) |
| Find a setting | [Complete configuration reference](docs/configuration-reference.md) |

The recommended adoption sequence is:

1. Run a [local evaluation](docs/local-evaluation.md).
2. Confirm the organization’s permissions, data scope, scale, SLA policy, and cost
   assumptions.
3. Review and apply the three cumulative Azure deployment stages.
4. Validate one Function collection and immutable publication.
5. Assign authorized dashboard users.
6. Follow the operations and troubleshooting runbooks.

## Installation paths

### Local evaluation

Local evaluation requires Python 3.12+, Bash, and Azure CLI only when collecting
live data. It does not require Terraform or create Azure resources.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
```

Then follow [Local evaluation before Azure deployment](docs/local-evaluation.md)
for live collection, sample replay, synthetic history, output
validation, and the local dashboard.

### Azure deployment

Azure deployment additionally requires:

- Terraform 1.10 or newer;
- Azure CLI authenticated to the target tenant and subscription;
- Bash, `zip`, `jq`, and `curl`;
- globally unique Azure resource names;
- an organization-defined Terraform state backend for production;
- Azure and Microsoft Entra permissions described in
  [Required operator permissions](DEPLOY.md#required-operator-permissions).

Create the ignored environment-specific values file:

```bash
cp infra/terraform/main.tfvars.example.json \
  infra/terraform/main.tfvars.json
```

The deployment has three cumulative reviewed stages:

1. Protected history foundation
2. Collector Function and managed identity
3. Authenticated dashboard Web App

Use [Azure deployment guide](DEPLOY.md) as the canonical full procedure. Use
[Greenfield Azure deployment](docs/greenfield-deployment.md) as the shorter
operator checklist.

## What gets deployed

The complete Azure design contains:

- one protected ADLS Gen2 history account;
- immutable `raw/`, `curated/`, and `runs/` paths;
- a separate mutable current-pointer container;
- a separate replaceable Function runtime storage account;
- a Python Flex Consumption collector Function;
- collector managed identity and least-scope RBAC/API permissions;
- Log Analytics and Application Insights;
- an optional Linux B1 dashboard Web App;
- a dashboard read identity;
- an assignment-required Microsoft Entra Enterprise Application;
- an optional private append-only recommendation-workflow container.

The history account is protected data and must survive replacement of the
Function or Web App.

## Day-to-day operations

Common read-only checks:

```bash
./infra/check-function-logs.sh 1 3 --status-only
./infra/check-runs.sh 5 --progress
.venv/bin/vulnerability-view status
```

Do not manually invoke the collector while the status check reports `ACTIVE` or
`INDETERMINATE`.

For schedules, manual invocation, deployment updates, monitoring, current-run
verification, history restore, and dashboard user assignments, use:

- [Operations and monitoring](docs/operations-and-configuration.md)
- [Command reference](docs/command-reference.md)
- [Troubleshooting](docs/troubleshooting.md)

## Data and retention boundaries

Every successful collection creates a new immutable run. Raw response pages,
curated datasets, manifests, checksums, collection status, and the versioned SLA
policy are retained together. The current pointer advances only after a run is
complete and verified.

Paths under `raw/`, `curated/`, and `runs/` are append-only. Application code
does not delete them. `history_immutability_days` is a minimum no-change period,
not an automatic expiration or purge policy.

Local `output/` cleanup never authorizes deletion of Azure history. Starting
over means creating a new immutable run and advancing only
`current/manifest.json` after successful validation.

The dashboard distinguishes:

- live Defender evidence;
- labeled synthetic demonstration history;
- combined views only when the visible data-origin label/filter distinguishes
  both sources.

See [Data structure and retention](docs/data.md) for the full schema and storage
contract.

## SLA notice

The checked-in SLA thresholds demonstrate aging, lifecycle, and reporting
behavior. They are not an adopted organizational policy. Replace them with
organization-defined remediation targets before using SLA results for
operational or compliance decisions.

The finding SLA clock is separate from Defender remediation-task due dates.
See [Dashboard and collection logic](LOGIC.md) for the exact implemented rules.

## Documentation

The ordered documentation index is [docs/README.md](docs/README.md).

### Installation

1. [Local evaluation before Azure deployment](docs/local-evaluation.md)
2. [Azure deployment guide](DEPLOY.md)
3. [Greenfield Azure deployment checklist](docs/greenfield-deployment.md)
4. [Environment and deployment design](docs/environment-and-deployment.md)
5. [Publishing and Azure cost options](docs/web-app-deployment-recommendations.md)

### Operations

1. [Operations and monitoring](docs/operations-and-configuration.md)
2. [Command reference](docs/command-reference.md)
3. [Collect and replay a sample](docs/sample-replay.md)
4. [Complete configuration reference](docs/configuration-reference.md)

### Troubleshooting

1. [Troubleshooting](docs/troubleshooting.md)
2. [Command reference: diagnostics](docs/command-reference.md#6-collection-progress-runs-failures-and-memory)

### Logic and data

1. [Dashboard and collection logic](LOGIC.md)
2. [Data collection and dashboard workflow](docs/data-collection-and-workflow.md)
3. [Data structure and retention](docs/data.md)

### Development

1. [Development, demonstration, and source control](docs/development.md)
2. [Infrastructure helper summary](infra/README.md)

## Independent project, trademarks, and disclaimer

Vulnerability View is an independent project. It is not a Microsoft product and
is not affiliated with, sponsored, endorsed, supported, or warranted
by Microsoft. References to Microsoft, Microsoft Azure, Microsoft Defender, and
other Microsoft products or services are used only to identify the products and
services with which this software interoperates. Microsoft and the names of its
products and services are trademarks of the Microsoft group of companies.

THE SOFTWARE AND DOCUMENTATION ARE PROVIDED "AS IS" AND "AS AVAILABLE," WITHOUT
WARRANTY OF ANY KIND, EXPRESS, IMPLIED, OR STATUTORY, INCLUDING WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, NON-INFRINGEMENT,
ACCURACY, AVAILABILITY, SECURITY, OR RELIABILITY. TO THE MAXIMUM EXTENT
PERMITTED BY APPLICABLE LAW, THE PROJECT CONTRIBUTORS DISCLAIM LIABILITY FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, EXEMPLARY, OR OTHER
DAMAGES, INCLUDING LOSS OF DATA, LOSS OF PROFITS, SERVICE INTERRUPTION,
SECURITY INCIDENTS, OR COSTS ARISING FROM USE OF, INABILITY TO USE, DEPLOYMENT
OF, OR RELIANCE ON THE SOFTWARE OR DOCUMENTATION.

Users are solely responsible for evaluating suitability, validating the design,
securing the deployment, reviewing permissions, protecting data, testing backup
and recovery, complying with applicable laws and organizational requirements,
and monitoring availability and cost. The documentation does not constitute
legal, compliance, security, or professional advice.

Every deployed Azure resource can incur charges. Review current Azure pricing,
budgets, alerts, consumption, and retained-history growth. Protected DVM history
must not be deleted as part of ordinary cost reduction or application cleanup.
