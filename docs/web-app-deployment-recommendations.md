# Hosting and cost notes

These notes describe the current Terraform baseline and the decisions that
change its cost. Installation is covered in [DEPLOY.md](../DEPLOY.md);
runtime behavior is covered in [Application flow](application-flow.md).

## Current hosting

| Component | Current baseline |
|---|---|
| Collector | Separate Linux Dedicated B2 plan, one fixed worker, Always On |
| Dashboard | Separate Linux App Service B2 plan, one instance and one Uvicorn process |
| Protected data | Standard ADLS Gen2 history account; replication is configured per environment |
| Functions state | Separate runtime storage account for host state and Durable Functions |
| Viewer cache | Separate private container in the history account, with scoped Web App write access |
| Monitoring | Application Insights and Log Analytics for collection diagnostics |
| Authentication | Managed identities and Microsoft Entra / Easy Auth |

Both plans incur continuous compute charges. The collector is **not** Flex
Consumption and does not scale to zero between runs. Older Flex deployments
need the [hosting migration](../infra/README.md#collector-hosting-and-upgrading-existing-flex-deployments).

The plans are separate so collection and interactive reporting do not compete
for the same worker. Dedicated collector hosting was chosen to avoid
consumption-driven scale-in during long collections. Durable checkpoints address
interrupted work; Always On alone does not provide that recovery.

The dashboard baseline accepts a single-instance outage during recovery or
redeployment. It is not a high-availability design. Retained evidence is separate
from replaceable application hosting.

## Dashboard hosting options

| Choice | Reason to consider it | Limitation or cost |
|---|---|---|
| Local | Development, replay, or offline evaluation | Not the hosted service |
| Basic B2, one instance | Existing deployment baseline | No deployment slots or autoscale |
| Larger supported SKU | Measured CPU, memory, or disk pressure | Higher continuous compute cost |
| Standard/Premium tier with deployment slots | Staged deployment and warm-up before switching production | Tier cost and slot resource contention |
| Multiple instances | Instance-level availability or measured concurrent demand | Each instance prepares its own local caches |
| Second region | An approved regional recovery requirement | Additional hosting, traffic routing, and tested recovery procedures |

App Service features and capacity vary by tier and region. Deployment preflight
checks the configured SKU and approved candidate regions; it does not select a
more expensive tier without operator confirmation.

## Cache and scale controls

The dashboard serves aggregates and bounded pages from server-side SQLite.
It does not send complete findings or lifecycle history to each browser.
The configured viewer cache can restore compatible completed indexes and reports
after a process restart. A new snapshot still needs preparation.

FastAPI serves the shell while preparation runs in the background. HTTP liveness
is different from data readiness. A previous complete snapshot stays available
during replacement preparation or failure.

The default worker has an 8 GiB/two-snapshot local retention budget, plus
additional SQLite and restoration scratch needs. Increasing processes or
instances multiplies local preparation, memory, disk, and download work.
It is not a substitute for measuring the actual bottleneck.

Published indexes and persistent viewer-cache generations also consume Azure
Storage. There is no automatic cloud cache purge. Cost estimates include these
alongside raw and curated evidence, not just compressed findings JSON.

The [runtime reference](application-flow.md#7-web-app-startup-indexing-memory-and-caches)
explains readiness, reuse, and limits. [Performance checks](development.md#performance-checks)
cover local validation; customer data and hosting still need separate testing.

## Storage, monitoring, and networking

Replication is an environment decision. LRS is the lower-cost baseline;
zone/geo redundancy adds durability options and cost, not application failover
by itself. WORM duration is a minimum protection period, not an expiry that
deletes evidence. No lifecycle deletion rule is provisioned for retained data.

Log ingestion, retention, and diagnostic volume are separate cost inputs.
Collection failure, stale publication, and application availability need an
agreed alerting and response process. Their existence should not be inferred
from deploying Application Insights.

The default network perimeter configuration initially allows all IPv4 sources.
Authentication and RBAC still apply, but this is not private networking.
Private endpoints, Front Door, WAF, NAT, additional regions, or other services
need their own design, validation, and cost approval.

## Calculator worksheet

The standalone [Azure cost calculator](../tools/calculator.html) opens locally.
It can read an environment values file and published manifest without uploading
them. It is excluded from the deployed dashboard.

The estimate includes:

- Continuous collector and dashboard compute, with actual instance counts.
- Existing history, retained bytes per collection, and collection frequency.
- Published indexes, checkpoints, failed runs, and viewer-cache writes/growth.
- Function runtime storage and append-only workflow/branding events.
- Storage reads, writes, lists, and transfers.
- Monitoring ingestion/retention and any added networking.
- Optional licensing or other organizational costs.

The timer default is one collection per day. Rates remain editable and must
be checked for the target region, currency, agreement, and date. The
[Azure Pricing Calculator](https://azure.microsoft.com/pricing/calculator/)
provides current pricing inputs. No historical dollar table in this repository
is a current quote.

The calculator's bounded-retention option is hypothetical. It does not
configure deletion or authorize removal of any retained data.

## Cost behavior and remaining environment decisions

Retained runs and viewer-cache generations accumulate, so storage growth remains
part of the running cost. There is no automatic cloud cleanup in the app.
Deleting retained evidence is not an application cost-control operation.

Budgets, ownership, alert recipients, and any reservation commitments belong
to the environment record. SKU, region, replication, and worker count affect
both cost and behavior; the existing deployment approval covers those changes.
The current application does not depend on a larger tier, Redis, a second
region, or additional networking being added.
