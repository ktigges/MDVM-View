# Vulnerability View

> **Author:** Kevin Tigges  
> **Last modified:** 2026-09-27  
> **Purpose:** Set up, run, validate, and operate the Vulnerability View collector and dashboard.

Microsoft Defender Vulnerability Management provides strong vulnerability
discovery, device assessment, and remediation guidance. Day-to-day review can
still require moving among separate vulnerability, recommendation, device, and
finding views. Vulnerability View brings those related records together in a
low-cost, read-only dashboard built from the APIs available for the operator's
Defender environment.

The viewer does not change Defender data, perform remediation, or send data,
telemetry, status, or results back to Defender. It collects read-only source
data, preserves snapshots in application-owned storage, correlates related
records, and presents them through a unified workflow. Those retained snapshots
provide the activity-over-time view that is not available by default in the
point-in-time Defender workflow.

The repository includes example SLA thresholds only to demonstrate aging,
status, and reporting behavior. Replace them with remediation targets approved
by the organization before using SLA results for operational or compliance
decisions.

## Project status and responsibility

Vulnerability View is an independent project created by Kevin Tigges. The
author is a Microsoft employee, but Microsoft did not commission, authorize,
endorse, approve, support, or warrant this project. It is not a Microsoft
product, and its content does not represent Microsoft guidance or policy.

The software and documentation are provided as-is, without warranties. Users
are responsible for validating the design, securing the deployment, reviewing
permissions, protecting collected data, testing recovery, and confirming that
the solution is appropriate for their environment. To the extent permitted by
law, the author and Microsoft are not responsible for damage, loss, service
interruption, data exposure, or other consequences resulting from deployment
or use.

The design favors low-cost Azure services, but every deployed resource can
incur charges. The operator is responsible for reviewing current Azure pricing,
setting budgets and alerts, monitoring consumption and retention growth, and
removing or resizing replaceable resources when they are no longer required.
Protected DVM history must not be deleted as part of ordinary cost reduction or
application cleanup.

Architecture, deployment, and operations documents are indexed in [docs/README.md](docs/README.md).

## 1. Prerequisites

- Python 3.12 (the project also passes under Python 3.13)
- Terraform 1.10 or later
- Azure CLI for deployment and interactive workstation authentication
- Bash, `zip`, `jq`, and `curl` for the deployment helper
- Git and GitHub CLI only when publishing the source repository
- Defender Vulnerability Management data and tenant consent for the live path

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
```

The CLI and Function load `.env` automatically when the file is present; variables already exported in the process environment take precedence. Never commit `.env`.

### Command-line application

`vulnerability-view` is the installed command-line entry point for the complete
data-preparation and operator application, not a synthetic-data-only tool. It
provides commands for:

- Defender permission preflight and live collection.
- Raw-response replay and durable history backfill.
- Synthetic test generation and explicit Azure synthetic seeding.
- Combined live/synthetic test builds.
- Output validation, status inspection, and current-bundle restoration.

Run `vulnerability-view --help` for the complete command list. The Azure
Function imports the same CLI application and invokes only `collect-live`.

## 2. Authentication

There are two independent authentication boundaries:

- **Service credentials** let the collector call Defender/Graph and let the dashboard server read private Azure Storage.
- **Dashboard user authentication** controls which people may load the dashboard and its same-origin API.

Local service access normally uses `DefaultAzureCredential` and Azure CLI. Azure-hosted service access uses `ManagedIdentityCredential` only. For a workstation:

```bash
az login --tenant "$AZURE_TENANT_ID"
az account set --subscription "$AZURE_SUBSCRIPTION_ID"
```

When Azure CLI cannot obtain required application permissions, the collector supports an explicitly acknowledged client secret for local development only. Put these values only in the ignored `.env` file:

```dotenv
# LOCAL DEVELOPMENT ONLY. NEVER DEPLOY OR COMMIT THESE VALUES.
AUTH_MODE=client_secret
ALLOW_LOCAL_CLIENT_SECRET=true
AZURE_TENANT_ID=<tenant-id>
AZURE_CLIENT_ID=<local-collector-application-id>
AZURE_CLIENT_SECRET=<local-secret>
```

The app registration needs the Defender application permissions listed below and Microsoft Graph `SecurityEvents.Read.All`, all with tenant admin consent. Azure host detection rejects `client_secret` mode. The CLI prints a warning on every command and the dashboard displays a persistent red development banner.

Inspect the effective non-secret configuration with:

```bash
vulnerability-view show-config
vulnerability-view status
```

Dashboard user authentication is disabled by default for local UI development:

```dotenv
DASHBOARD_AUTH_ENABLED=false
```

When deploying the dashboard Web App, set `DASHBOARD_AUTH_ENABLED=true` and
enable Microsoft Entra authentication in Azure App Service. The Enterprise
Application display name is `DVM Viewer`. After apply, the Terraform outputs
`dashboard_enterprise_application_object_id` and
`dashboard_entra_client_id` identify it. Manage assignments at **Microsoft
Entra ID > Enterprise applications > DVM Viewer > Users and groups**.
Group-based Enterprise Application assignment requires the applicable
Microsoft Entra ID licensing; if it is unavailable, assign individual users
the `Dashboard.Viewer` role.

The FastAPI middleware then requires the trusted
`X-MS-CLIENT-PRINCIPAL` header injected by App Service for every page and API
request. Enabling the flag locally is rejected because a workstation cannot
establish the App Service trust boundary. The flag does not create an app
registration or configure Easy Auth by itself.

The optional curated-data evidence browser is also disabled by default:

```dotenv
DASHBOARD_DATA_BROWSER_ENABLED=false
DASHBOARD_DATA_BROWSER_ROLE=
```

Shared recommendation workflow tracking is independently controlled:

```dotenv
DASHBOARD_RECOMMENDATION_TRACKING_ENABLED=false
DASHBOARD_RECOMMENDATION_TRACKING_ROLE=Recommendation.Tracker
DASHBOARD_RECOMMENDATION_TRACKING_CONTAINER=dvm-workflow
```

When enabled, authorized users can mark a live recommendation **In progress**,
**Fixed**, or clear its tracking state. “Fixed” waits for a newer collection:
the dashboard then displays **Confirmed** when no active live findings remain,
or **Still detected** when Defender continues to report affected findings.
These shared display states are stored as append-only events in the separate
workflow container. They do not change Defender records, finding lifecycle, or
SLA calculations.

When enabled, a hidden **Data evidence** navigation item becomes available and
serves read-only, paginated views of the normalized datasets used by dashboard
calculations. `DASHBOARD_DATA_BROWSER_ROLE` can require an App Service principal
role such as `Data.Evidence.Reader`. The browser never provides write/delete
operations, storage credentials, or unrestricted blob paths.

Requests use the current `https://api.security.microsoft.com` endpoint, but tokens are acquired for `https://api.securitycenter.microsoft.com/.default`. Microsoft documents that several Defender for Endpoint APIs still require this legacy token audience; using the endpoint host as the token audience returns HTTP 403 even with the correct permissions.

The identity needs Defender application or delegated access and device-group visibility. The minimum Defender application permissions used here are `Machine.Read.All`, `Vulnerability.Read.All`, and `SecurityRecommendation.Read.All`, each with tenant admin consent. Actual Microsoft Secure Score is optional and requires Microsoft Graph `SecurityEvents.Read.All` with admin consent; when unavailable, the dashboard displays `Unavailable` rather than a synthetic score. Storage upload needs Storage Blob Data Contributor; Logs Ingestion needs Monitoring Metrics Publisher on the DCR.

## 3. Defender API permission validation

```bash
vulnerability-view preflight
```

Preflight obtains a token and requests only one row per route. It exits nonzero when a required route fails and prints the specific permission. On 2026-09-16 the following public Microsoft documentation was verified:

- [Vulnerabilities by machine](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities-by-machines): `GET /api/vulnerabilities/machinesVulnerabilities`
- [Machines](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines): `GET /api/machines`
- [Vulnerabilities](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities): `GET /api/vulnerabilities`
- [Recommendations](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-recommendations): `GET /api/recommendations`
- [Devices by recommendation](https://learn.microsoft.com/en-us/defender-endpoint/api/get-recommendation-machines): `GET /api/recommendations/{id}/machineReferences`

The remediation-task and vulnerability-change routes were not found in the current public Defender Endpoint API documentation. They are disabled by default through `ENABLE_EXPERIMENTAL_ENDPOINTS=false` and are not required for a successful snapshot. Microsoft Graph Secure Score is also optional.

## 4. Local setup

Edit `config/sla-policies.json` for sample policy changes. Asset classification is evidence-based: Azure resource metadata or configured tags yield `AzureCloud`; onboarded devices without Azure evidence yield `TraditionalIT`; missing machine metadata yields `Unknown`. `ClassificationReason` records why. Azure machine `subscriptionId` and `resourceId` values are normalized into the finding and recommendation-machine exports. The dashboard can filter every view by subscription while displaying only a shortened subscription identifier.

Supported modes are `synthetic`, `live`, and `combined`. If required live settings are absent, configuration defaults to `synthetic`. Every record includes `DataOrigin`, `ScenarioId`, `SnapshotTimeUtc`, and `CollectionRunId`.

## 5. One-command synthetic build

```bash
vulnerability-view build-sample --mode synthetic
vulnerability-view validate
```

The fixed default seed produces 2,500 distinct fictional endpoints across six
months of lifecycle events, plus a rolling 90-day daily summary of new, fixed,
reopened, remaining, known-exploit, and SLA outcomes. It also includes
assignments, remediation activities, a stale device, and a collection warning.
Set `SYNTHETIC_DEVICE_COUNT` to change the endpoint count for a local scale
test. No live device identifier is used.

The sample is structurally grounded in the normalized live schema and exercises
open, fixed, reopened, pending-confirmation, stale-device, out-of-scope, and
unknown lifecycle states. It includes within/outside SLA outcomes, incomplete
ownership and ticketing, active/completed/late/overdue/canceled remediation
tasks, supported and unsupported onboarding states, recommendation-machine
relationships, CVE details, and a fictional Secure Score. Synthetic generation
samples real CVE identifiers from the latest retained live snapshot while
keeping every device association, date, SLA result, assignment, and remediation
outcome labeled `Synthetic`. Synthetic generation stops if retained live CVE
references are unavailable. None of the synthetic scenarios should be
interpreted as Defender evidence or approved policy.

## 6. Local live snapshot

```bash
vulnerability-view preflight
vulnerability-view collect-live --local-only --enrichment targeted
vulnerability-view validate
```

`--local-only` calls Defender and writes the raw archive, history bundle, dashboard JSON, and CSV exports on this machine without reading or writing Azure Storage. Leave `STORAGE_ACCOUNT_NAME` empty during isolated local testing.

Recommendation-machine enrichment defaults to `auto`: targeted enrichment on normal days and a full relationship reconciliation on Sunday (`FULL_ENRICHMENT_WEEKDAY=6`). Override when needed:

```bash
vulnerability-view collect-live --local-only --enrichment targeted
vulnerability-view collect-live --local-only --enrichment full
```

If downloading succeeds but a later normalization/export step fails, replay the latest archived snapshot without querying Defender again:

```bash
vulnerability-view collect-live --from-raw latest --local-only
```

The collector follows `@odata.nextLink`, honors `Retry-After`, and uses bounded exponential backoff. It interprets HTTP 401 and 403 responses, stops the collection cleanly, and provides guidance to check tenant access, API permissions, and admin consent. It retrieves machine references for each exposed recommendation so configuration and vulnerability recommendation pivots use Defender's recommendation relationship rather than product-name inference. Every unmodified response page is written to `output/raw/<run-id>/*.json.gz` before normalization. When `STORAGE_ACCOUNT_NAME` is configured and `--local-only` is omitted, the completed raw and curated bundle is uploaded to private ADLS Gen2 paths. No remediation write API is called.

This is point-in-time collection, not a real-time stream. Each command captures a new Defender snapshot; refreshing the browser only rereads the most recently generated local JSON. If the optional Function is deployed, its default timer captures one snapshot daily at 05:00 UTC. Raw pages use deterministic `raw/YYYY/MM/DD/<collection-run-id>/` paths, never overwrite an existing blob, and can be replayed idempotently without consuming duplicate storage.

## 7. Combined build

```bash
vulnerability-view build-sample --mode combined
```

To rebuild the combined presentation from the latest completed raw snapshot without downloading Defender again:

```bash
vulnerability-view build-sample --mode combined --from-raw latest
```

`build-sample` is always a local presentation build, even when Azure Storage
is configured. It does not upload a run or advance the Azure current manifest.
Use the explicitly confirmed `seed-synthetic-history` operation followed by a
successful live collector run to publish a combined Azure bundle.

Live rows and synthetic history remain separately labeled and independently filterable. If live collection is blocked, the synthetic build remains intact and the warning appears in `output/run-summary/latest.json` and `latest.md`.

## 8. Azure deployment

Use the detailed [Azure deployment guide](DEPLOY.md) for the two-account
storage model, complete resource inventory, configuration mapping, permissions,
data migration, Function deployment, invocation, validation, and safe teardown
boundaries.

Use the staged commands below after creating the ignored
`infra/terraform/main.tfvars.json` file. Runtime settings and their owners are
also listed in
[Operations and configuration](docs/operations-and-configuration.md).

```bash
./infra/deploy.sh tfplan foundation
terraform -chdir=infra/terraform show foundation.tfplan
./infra/deploy.sh tfapply foundation

./infra/deploy.sh tfplan function
terraform -chdir=infra/terraform show function.tfplan
./infra/deploy.sh tfapply function
./infra/deploy.sh tfdeploy function
./infra/deploy.sh tfverify function
```

Review each saved plan before applying. The protected storage foundation and
replaceable Function stage remain separate. See
[Web App deployment recommendations](docs/web-app-deployment-recommendations.md)
for the next hosting stage.

To seed six months of clearly labeled synthetic test history after the
foundation is created:

```bash
vulnerability-view seed-synthetic-history --confirm-azure-write
```

This is a local operator command; the Azure Function never generates synthetic
data. Set Terraform `app_mode` to `combined` in a test environment if later live
collections should retain the seeded synthetic rows in the current bundle. See
[Azure deployment guide](DEPLOY.md) for prerequisites and behavior.

After deployment, the collector runs automatically at the UTC
`collection_schedule`. To start one immediate live run in the deployed Function:

```bash
CONFIRM_LIVE_COLLECTION=yes ./infra/deploy.sh tfinvoke function
./infra/deploy.sh tfverify function
```

The confirmation is intentional: each invocation publishes a new immutable run
and advances only `dvm-current/current/manifest.json`. Do not invoke a manual run
while a scheduled run is active. To change the recurring time, update
`collection_schedule` in the ignored Terraform values file, review a new
`tfplan function`, and apply it. See
[Greenfield Azure deployment](docs/greenfield-deployment.md) for all deployed
run options and validation steps.

## 9. Dashboard development

To simulate the scheduled collection pipeline locally without Defender or Azure access:

```bash
vulnerability-view simulate-scheduled-run --from-raw latest --local-only
```

To replay locally retained source pages and test configured Azure Blob/ADLS upload without calling Defender, omit `--local-only`.

The dashboard server serves the UI and `/api/data/*` from one origin. Local mode reads the generated files under `dashboard/data` and is the fastest option while changing the UI:

```bash
./start-app.sh
```

Azure mode reads `dvm-current/current/manifest.json`, verifies every referenced curated blob, and serves the remote current run without copying it into `dashboard/data`:

```bash
DASHBOARD_DATA_SOURCE=azure ./start-app.sh
curl http://localhost:8000/api/status
```

Azure mode uses the storage account and containers configured in `.env` and authenticates with the local developer credential. It is read-only. UI edits remain local and Uvicorn reloads server changes automatically, so App Service deployment is not required during normal design work.

Pass a different port as the first argument, for example `./start-app.sh 8080`. Open [http://localhost:8000](http://localhost:8000). Set `DASHBOARD_RELOAD=false` to disable the development reloader. Stop the server with `Ctrl+C`.

## 10. Ten-minute walkthrough script

1. State the five goals: identify, prioritize, track remediation/SLA, show trend, and separate ownership.
2. On **Find**, select `Live Defender snapshot` when available and show Critical/High and exploit indicators. Otherwise show the preflight 403 and explicitly use synthetic data.
3. On **Recommendations**, select a live recommendation title to open **Exposure management → Recommendations** and copy its exact title and recommendation ID. Defender does not expose selected recommendation flyouts as deep-link URLs, so select **Vulnerabilities** and paste the copied reference before choosing **Request remediation**. CVE details open Defender Vulnerabilities and copy the CVE ID; recommendation-machine details retain the exact machine-ID link.
4. On **Prioritize**, open the highest score and explain severity, CVSS, exploit, internet, exposure, and asset components. State that this is a custom priority score, not Defender native scoring.
5. Switch Data Source to `Synthetic sample history`.
6. On **Remediate**, distinguish the two clocks. Global vulnerability SLA compares finding discovery and Defender-confirmed remediation with the policy due date. Remediation task performance separately compares task creation/completion with the assigned task due date. Show each within/outside result by Critical, High, Medium, and Low severity or priority.
7. Inspect remediation target/fixed progress. Explain implementation, reassessment, and reporting delay; manual completion is not technical proof.
8. On **Trend**, compare this month-to-date with the same number of days last month, review policy-SLA outcomes, and use the weekly New/Fixed chart. The separate task history shows tasks completed by or after their assigned due date and open tasks before or beyond due. These comparisons are derived in the browser from datasets already loaded, so they add no historical-storage cost.
9. On **Ownership**, show engineer/team/ticket fields, compare Traditional IT with Azure Cloud, and state that assignments are an added workflow.
10. Close with the implemented operating path: scheduled collection, immutable history, authenticated dashboard access, and source-data health.

## 11. Troubleshooting

| Symptom | Action |
|---|---|
| Preflight 401 | Run `az login --tenant <tenant>` and verify `DefaultAzureCredential` inputs. |
| Preflight 403 | Grant/admin-consent the printed permission and verify Defender device-group access. |
| Optional route 404 | Expected for an unsupported compatibility route; the run is `PartialSuccess`. |
| Dashboard shows data unavailable | Check `/api/status`; verify `DASHBOARD_DATA_SOURCE`, storage settings, and local files or Azure read access. |
| Azure dashboard mode returns 503 | Set `STORAGE_ACCOUNT_NAME`, confirm the current manifest exists, and grant the local identity Storage Blob Data Reader. |
| Secure Score is unavailable | Inspect `collection-runs.json` for the `secure_scores` endpoint. A Graph 403 requires `SecurityEvents.Read.All` and tenant admin consent on the collector identity. |
| SLA is Unknown | No collector observation or matching versioned SLA policy is available. |
| Logs ingestion 403 | Grant Monitoring Metrics Publisher on the DCR to the calling principal. |
| Storage upload 403 | Grant Storage Blob Data Contributor on the storage account. |
| Azure changes are delayed | Software commonly appears in about two hours; configuration can take 4-24 hours; Exposure Score can take 24 hours, plus report refresh. |

## 12. Publish the source repository

Review the staged file list before the first commit. The ignore rules exclude
credentials, customer values, Terraform state and plans, generated data,
deployment ZIP files, local notes, editor state, and local environments.

```bash
git init -b main
git add .
git status --short
git diff --cached --check
git diff --cached --name-only
git commit -m "Initial"
gh auth login
gh repo create <repository-name> --private --source=. --remote=origin --push
```

Create the repository as private first unless public release has completed its
own legal, licensing, and organizational review. Do not use `git add -f` to
override an ignored file.

## 13. Cleanup

Stop the local HTTP server. Local generated files can be rebuilt, but local cleanup does not authorize deletion from Azure Storage.

Never delete the ADLS storage account, container, or retained paths under `raw/`, `curated/`, or `runs/` as part of cleanup, reset, redeployment, or "start over" work. Preserve the storage account separately from replaceable application infrastructure. The application contains no Azure Storage delete operation.

Only `current/manifest.json` is replaced during normal operation. It points to
immutable completed history. Retention deletion requires separate, explicit
approval for the exact target and must not be inferred from a general cleanup
request.

## Data boundaries

- Live pages show current findings, known exploits, current priority, device
  context, freshness, and supported live remediation snapshots.
- Synthetic-history pages show six-month trends, lifecycle transitions,
  demonstration assignments, tickets, and SLA examples.
- Combined pages show current and historical records only when the visible
  Data Origin label or slicer distinguishes both sources.