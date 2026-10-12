# Vulnerability View

Vulnerability View augments Microsoft Defender Vulnerability Management with
retained history, remediation lifecycle tracking, SLA reporting, and simpler
week-to-week operational views.

It helps answer:

- What is currently open?
- What was fixed between runs or reporting periods?
- Which machines, CVEs, and recommendations are involved?
- Which remediation was observed within or outside SLA?
- Which findings are pending confirmation or returned after remediation?
- What does management need to know about SLA exposure, workload movement, and
  where risk is concentrated?

The application reads Defender data. It does not change Defender findings or
perform remediation. Optional recommendation work status exists only inside
Vulnerability View.

## Deploy or update

Use the interactive deployment menu for every normal customer deployment,
update, verification, collection, and diagnostic operation.

Before the first deployment, complete the one-time
[workstation, permissions, and configuration preparation](DEPLOY.md#before-using-the-menu).
This establishes the required tools, customer-specific Terraform values, and
Azure CLI sign-in.

Then start the menu from the repository root.

macOS or Linux:

```bash
./infra/deployment-menu.sh
```

Windows:

```powershell
.\infra\deployment-menu.ps1
```

On a clean Windows clone, the PowerShell menu creates `.venv-win` and installs
Vulnerability View and its deployment dependencies when they are missing.
Python 3.12 or newer must already be installed.

Choose the menu entry that describes the work being performed. For a first
installation or complete update, use **Complete initial deployment or update**.
Review every Terraform plan and approve it only when it contains the expected
changes and preserves retained history.

After deployment, assign approved users or groups the **Dashboard Viewer** role
under **Enterprise applications > DVM Viewer > Users and groups**. Assign
specialized roles separately when required.

See the [Azure deployment guide](DEPLOY.md) for prerequisites, permissions,
configuration, identities, networking, and protected-history boundaries.

## Normal operations

Start the same deployment menu and choose the task shown there. Use the
smallest deployment option that matches the change:

- Dashboard-only changes require only Web App deployment.
- Collector changes require Function deployment.
- Infrastructure or identity changes require a reviewed Terraform plan.
- A collection is needed only when source data or collector output must be
  refreshed.

Direct CLI, Terraform, and Azure commands are not the normal operating path.
Use the [command reference](docs/command-reference.md) only for troubleshooting,
automation, or an individually required operation.

## Dashboard flow

The navigation follows the way the work is normally reviewed:

1. **Summary** shows current exposure, SLA results, Secure Score, and the
   highest-impact recommendations.
2. **Recommendations** and **Prioritize** group finding instances into work
   that can be assigned and completed.
3. **Vulnerabilities** and **Endpoint assets** provide the detailed CVE,
   finding, and machine evidence.
4. **Remediate** shows SLA and remediation outcomes.
5. **Reporting** compares lifecycle changes by finding, machine, CVE, or
   recommendation and exports the filtered detail.
6. **Executive Snapshot** produces a separate management view for a selected
   timeframe, subscription, and operating team. It can be printed or saved as
   PDF and exported to CSV.
7. **How to use** keeps the daily workflow available inside the application.

Executive Snapshot can show either finding instances or recommendation
workload. Recommendation workload is a rollup of linked finding evidence. It
does not create a separate recommendation SLA clock; the displayed SLA result
still comes from finding deadlines.

## How the application works

At a high level:

1. The Azure Function authenticates with its managed identity.
2. It collects machines, vulnerability findings, recommendations, vulnerability
   details, recommendation-machine relationships, Secure Score, and Azure
   subscription context.
3. The collector retains original source pages and normalizes the data into
   machine/CVE finding instances.
4. The current run is compared with retained prior evidence to identify new,
   pending, fixed, returned, and reopened findings.
5. SLA state is calculated from first observation, severity policy, and the
   first qualified remediation absence.
6. Raw evidence, curated datasets, policies, checksums, and run manifests are
   written to immutable Azure history.
7. Only after successful validation does `current/manifest.json` advance to the
   completed run.
8. The Web App reads the current manifest and curated evidence using its
   separate managed identity.

Routine collections use Defender vulnerability deltas. An initial collection,
the configured weekly reconciliation, or a stale/missing baseline uses a full
vulnerability snapshot. A manual full operation also refreshes complete
recommendation-machine relationships.

Detailed implementation is intentionally kept in the following authoritative
documents:

- [Dashboard and collection logic](LOGIC.md) — finding identity, priority,
  lifecycle, remediation, reopening, SLA, filtering, and reporting rules.
- [Data collection and dashboard workflow](docs/data-collection-and-workflow/)
  — APIs, pagination, retries, full/delta behavior, normalization, scaling, and
  end-to-end processing.
- [Data structure and retention](docs/data/) — raw and curated schemas,
  manifests, replay, storage paths, published datasets, and lineage.
- [Daily remediation workflow](docs/daily-vulnerability-remediation-workflow.md)
  — how operators use pending, fixed, SLA, machine, CVE, and recommendation
  reporting.

## Data protection boundary

Every successful collection creates a new retained run.

- `raw/`, `curated/`, and `runs/` are append-only.
- Application code does not delete retained history.
- Only `current/manifest.json` is replaceable.
- The current pointer advances only after a complete run is validated.
- Local `output/` cleanup never authorizes Azure history deletion.
- Replacing application infrastructure must preserve the history Storage
  account.

See [Data structure and retention](docs/data/) for the complete storage
contract.

## Authentication and authorization

- The Function uses a user-assigned managed identity for Defender, Graph,
  Storage, and Azure inventory access.
- The Web App uses a separate managed identity to read protected history.
- Dashboard users authenticate through App Service Easy Auth and Microsoft
  Entra.
- General access requires `Dashboard Viewer`.
- Optional evidence, tracking, and administration capabilities use additional
  application roles.
- Operator passwords and Azure CLI tokens are not stored in the application.

## Documentation

Start with the document that matches the task:

| Need | Document |
|---|---|
| Deploy or update Azure | [Azure deployment guide](DEPLOY.md) |
| Understand calculations and lifecycle | [Dashboard and collection logic](LOGIC.md) |
| Understand data collection and processing | [Data collection and workflow](docs/data-collection-and-workflow/) |
| Understand schemas and retained Storage | [Data structure and retention](docs/data/) |
| Operate the dashboard | [Daily remediation workflow](docs/daily-vulnerability-remediation-workflow.md) |
| Troubleshoot or run an individual command | [Command reference](docs/command-reference.md) |
| Configure a setting | [Configuration reference](docs/configuration-reference.md) |
| Diagnose a problem | [Troubleshooting](docs/troubleshooting.md) |
| Browse all documents | [Documentation index](docs/README.md) |

## Repository map

```text
dashboard/                  Browser application
src/vulnerability_view/     Collection, processing, Storage, and Web App code
infra/                      Terraform and deployment menus
config/                     Versioned policy and configuration examples
docs/                       Detailed installation, operations, logic, and data guides
tests/                      Automated tests
function_app.py             Azure Function entry point
LOGIC.md                    Calculation and lifecycle specification
DEPLOY.md                   Complete Azure deployment reference
```

## Important notices

The checked-in SLA thresholds are examples, not an adopted organizational
policy. Replace them with approved targets before using SLA results for
operational or compliance decisions.

Vulnerability View is an independent project and is not a Microsoft product.
The software and documentation are provided as-is without warranty. Users are
responsible for validating suitability, security, permissions, recovery,
compliance, availability, and Azure cost.

Every deployed Azure resource can incur charges. Review the assumptions with
the local [Azure cost calculator](tools/calculator.html) and the official
[Azure Pricing Calculator](https://azure.microsoft.com/pricing/calculator/).

Local dashboard use, sample replay, development, testing, and source-control
procedures are intentionally separated from the customer deployment path. See
the [Local development README](docs/local/README.md) only when performing local
or development work.
