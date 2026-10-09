# Troubleshooting

> **Last modified:** 2026-09-28
> **Purpose:** Diagnose local collection, Azure Function, Web App, storage, authentication, and data-publication problems.

Start with the smallest read-only check that can distinguish the failure.
Commands and their effects are listed in the
[Command reference](command-reference.md).

## 1. Quick triage

```bash
.venv/bin/vulnerability-view show-config
.venv/bin/vulnerability-view status
./infra/check-function-logs.sh 1 3 --status-only
./infra/check-runs.sh 5 --progress
```

Interpret the sources separately:

- Function telemetry proves that an invocation started, completed, or failed.
- Immutable run manifests prove that publication completed.
- `current/manifest.json` identifies the run currently served by the dashboard.
- A successful platform invocation is not proof that a complete run was
  published.

## 2. Local installation and dashboard

| Symptom | Check and action |
|---|---|
| `vulnerability-view` is not found | Activate `.venv` or run `.venv/bin/vulnerability-view`; reinstall with `python -m pip install -e '.[dev]'`. |
| Windows reports `No module named vulnerability_view` | The wrong Python interpreter is running or the project was not installed into `.venv-win`. Run `.\.venv-win\Scripts\Activate.ps1`, install with `python -m pip install -e ".[dev]"`, and verify with `python -c "import sys, vulnerability_view; print(sys.executable)"`. The path must end in `.venv-win\Scripts\python.exe`. |
| Dashboard has no data | Run a live collection, rebuild imported sample data, or build synthetic history, then run `vulnerability-view validate`. |
| Synthetic build reports no CVE references | Collect or import one live raw snapshot first; synthetic generation intentionally requires retained live CVE references. |
| Port 8000 is in use | Run `./start-app.sh 8080`. |
| Local tracking resets | Expected. Local tracking is an in-memory preview and resets when the process stops. |
| Dashboard data is unavailable | Check `http://127.0.0.1:8000/api/status`, `DASHBOARD_DATA_SOURCE`, and either local files or Azure read access. |
| SLA is `Unknown` | Confirm the exact finding has a collector observation and matches a versioned SLA policy. |
| A subscription appears to have no vulnerabilities | Reset the dashboard filters, select the subscription, and confirm **Vulnerability** is selected. If **Hide non-reporting devices** is enabled, widen **Last reported within** or turn the switch off. The dashboard retains fixed findings even when Defender no longer presents them as current. |
| Defender and the dashboard show different device totals | Confirm the dashboard snapshot time and the device `LastSeenUtc` values. The optional reporting-age filter is evaluated relative to the immutable dataset snapshot, not the current browser time. It hides presentation rows only and does not delete retained evidence. |

## 3. Defender and Microsoft Graph authentication

| Symptom | Check and action |
|---|---|
| Preflight 401 | Run `az login --tenant <tenant-id>` and confirm the selected tenant. Check the configured credential mode. |
| Preflight 403 | Grant and admin-consent the permission printed by preflight; confirm Defender device-group visibility. |
| Required route fails | Collection stops. Resolve the required permission or endpoint access before retrying. |
| Optional route is unavailable | The run can complete as partial success. Experimental compatibility routes are disabled by default. |
| Secure Score is unavailable | Check the `secure_scores` collection status. Microsoft Graph requires `SecurityEvents.Read.All` with tenant admin consent. |
| Client-secret mode is rejected in Azure | Expected. Client-secret authentication is restricted to explicitly acknowledged local development. Hosted workloads use managed identity. |
| A manual trigger is accepted but no run appears | Check Function telemetry. An `Executed ... (Failed)` record is not a completed collection. If runtime storage reports `AuthenticationFailed`, remove the legacy base `AzureWebJobsStorage` setting and retain the `AzureWebJobsStorage__*` managed-identity settings. Current apply/verify helpers reconcile and validate this automatically. |

Run:

```bash
.venv/bin/vulnerability-view preflight
```

The request host is `https://api.security.microsoft.com`, while the Defender
token audience remains
`https://api.securitycenter.microsoft.com/.default`.

## 4. Collector progress, failure, and memory

Check whether a collection is active before invoking manually:

```bash
./infra/check-function-logs.sh 1 3 --status-only
```

Continuously watch it:

```bash
watch -n 20 './infra/check-function-logs.sh 1 1 --status-only'
```

Inspect recent invocations, errors, exceptions, and memory:

```bash
./infra/check-function-logs.sh 24 10
```

Show active progress plus completed immutable runs:

```bash
./infra/check-runs.sh 5 --progress
```

Do not invoke manually when status is `ACTIVE` or `INDETERMINATE`.

If the Python worker exits near its configured memory limit:

1. Confirm peak working set in Function telemetry.
2. Confirm the run did not publish a complete manifest.
3. Increase `function_instance_memory_in_mb` only after measurement.
4. Review and apply a new cumulative Terraform plan.
5. Run one controlled collection and measure again.

Large endpoint pages are archived and streamed during normalization, but larger
scales still require measured certification. Do not infer 10,000-device
support solely from a smaller successful run.

## 5. Scheduled invocation but no current run

`check-runs.sh` lists only immutable runs that reached publication. A timer can
start successfully and still fail before publication.

```bash
./infra/check-function-logs.sh 24 10
./infra/check-runs.sh 10
```

Common causes:

- memory exhaustion;
- missing Defender or Graph permission;
- throttling that exceeded retry limits;
- storage authorization failure;
- required endpoint failure;
- a deployment restart during execution.

The current manifest advances only after the new bundle passes validation.
Until then the dashboard correctly continues serving the prior complete run.

## 6. Azure Storage

| Symptom | Check and action |
|---|---|
| Upload returns 403 | Grant Storage Blob Data Contributor to the collector or authorized local publisher at the history-account scope. |
| Dashboard Azure mode returns 503 | Confirm the current manifest exists and the reader identity has Storage Blob Data Reader. |
| Subscription selector omits a subscription | Confirm it is nested under `collector_management_group_id`, the collector has inherited Reader, and the next collection completed after the subscription was added. |
| Old history remains after switching to live mode | Expected. The current pointer changes; immutable prior synthetic or combined runs remain retained. |
| 365-day immutability did not purge data | Expected. Immutability is a minimum no-change period, not expiration or automatic deletion. |

Never resolve a storage problem by deleting protected history. Application code
and Terraform do not delete retained paths.

## 7. Terraform and deployment

| Symptom | Check and action |
|---|---|
| Terraform cannot create a role assignment | The deployer needs Owner, or Contributor plus User Access Administrator/Role Based Access Control Administrator, at every affected scope. |
| AzureAD provider cannot create applications or app-role assignments | Use an authorized identity with the required Microsoft Entra directory authority. |
| A plan proposes deleting protected storage | Do not apply it. Stop and reconcile state/configuration while preserving the storage account and containers. |
| `tfapply` says the plan is missing | Run the matching `tfplan` command and review the saved plan first. |
| ZipDeploy returns HTTP 504 | The client can time out while Kudu continues. Inspect the newest deployment record before retrying. Do not start a second deployment while the newest Kudu record is still building. |
| Function code changed but infrastructure did not | Run `tfdeploy function`, then `tfverify function`; do not create a new Terraform plan solely for code. |
| Dashboard code changed but infrastructure did not | Run `tfdeploy webapp`, then `tfverify webapp`. |

Inspect a Web App deployment:

```bash
az webapp log deployment list \
  --resource-group "<resource-group>" \
  --name "<web-app-name>" \
  --query 'sort_by(@,&start_time)[-1].{id:id,status:status,active:active,start:start_time,end:end_time}' \
  --output table
```

Kudu status `4` is successful and `3` is failed.

## 8. Web App and browser

| Symptom | Check and action |
|---|---|
| Authentication redirects repeatedly | Confirm App Service Authentication settings, redirect URI, Enterprise Application assignment, and tenant. |
| User receives 403 | Assign `Dashboard Viewer` in the `DVM Viewer` Enterprise Application. Assign optional roles only when required. |
| UI code changed but the old layout remains | Confirm the newest deployment succeeded, then reload. Deployment packages stamp a new UI revision and static assets require revalidation. |
| UI revision did not change | Check the `Packaged Web App UI revision ...` deployment output and the latest Kudu deployment status. |
| Data timestamp did not change after Web App deployment | Expected. Publishing UI code does not run the collector. Wait for the Function schedule or intentionally invoke one run after confirming none is active. |
| Changes appear several minutes late | The verified Azure data cache can retain the current bundle for `dashboard_cache_seconds`. |

## 9. API retrieval and performance checks

### Dashboard APIs

Dashboard APIs use the same global authentication policy as the dashboard,
except `GET /api/health`. That endpoint permits anonymous App Service health
probes, returns only non-secret service configuration, and does not access
Azure Storage or load a dataset. The data-browser APIs additionally require
the feature to be enabled and may require the `Data.Evidence.Reader` role.

| Method and route | Retrieval or diagnostic purpose |
|---|---|
| `GET /api/health` | Public liveness endpoint used by App Service Health Check. It confirms server availability and non-secret configuration without forcing a dataset download. |
| `GET /api/auth` | Confirms the current dashboard identity and authentication state. |
| `GET /api/diagnostics` | Reports bounded request timings, active and recent Azure Storage operations, pending requests, manifest-cache lifetime, and cached dataset names. It returns no dataset rows or identity details. |
| `GET /api/status` | Reads the local run status or retrieves the Azure current manifest and reports its run ID, snapshot time, source, and Secure Score availability. |
| `GET /api/sla-policy` | Retrieves the SLA policy retained with the current run. |
| `GET /api/recommendation-tracking` | Retrieves shared workflow state and the findings required to build the tracking view. |
| `PUT /api/recommendation-tracking` | Appends a workflow event. This is a write operation; do not use it for read-only availability or load testing. |
| `GET /api/data-browser/catalog` | Retrieves metadata for every evidence-browser dataset. This can load all datasets and requires data-browser authorization. |
| `GET /api/data-browser/<dataset>?offset=0&limit=50&query=<text>` | Retrieves a filtered, paginated evidence view. `limit` is 1–200 and `query` is at most 200 characters. |
| `GET /api/data/<asset>.json` | Retrieves one complete dashboard dataset from local files or the verified current Azure bundle. |
| `GET /api/data/cve-details/<cve-id>.json` | Retrieves one CVE record; the first request can load and verify the vulnerabilities dataset. |

If a tracking `PUT` succeeds but the following tracking `GET` returns 502 or
503 with `JSONDecodeError`, check whether the workflow container uses
hierarchical namespace directory markers under `events/`. Current application
versions read only immutable `.json` event blobs and ignore those zero-byte
directory markers. Do not delete the markers or retained workflow events to
repair this condition; deploy the application fix instead.

Valid `<dataset>` values for the data browser are:

```text
findings
finding-events
devices
vulnerabilities
recommendations
recommendation-machines
remediation-activities
daily-summary
collection-runs
reconciliation
secure-scores
subscriptions
```

The corresponding full dashboard assets use the same names with `.json`.
Use a valid CVE identifier such as `CVE-2024-0001` only when that identifier
exists in the current vulnerabilities dataset.

For local testing, capture HTTP status, time to first byte, and total time:

```bash
BASE_URL="http://127.0.0.1:8000"
curl --silent --show-error --output /dev/null \
  --write-out 'status=%{http_code} start=%{time_starttransfer}s total=%{time_total}s bytes=%{size_download}\n' \
  "$BASE_URL/api/status"
curl --silent --show-error --output /dev/null \
  --write-out 'status=%{http_code} start=%{time_starttransfer}s total=%{time_total}s bytes=%{size_download}\n' \
  "$BASE_URL/api/data/findings.json"
curl --silent --show-error "$BASE_URL/api/diagnostics"
```

Compare the first request after process start or a new run with a second request
to distinguish Azure retrieval and integrity verification from an in-process
cache hit. `GET /api/diagnostics` identifies cached datasets and records the
most recent API and storage-operation durations. Query strings, tokens,
identities, and response rows are intentionally omitted from diagnostics.

For the deployed Web App, use an authenticated browser session and the browser
Network panel, or an authorized authenticated HTTP client. An anonymous `curl`
request to a data or diagnostics endpoint should be rejected by App Service
Authentication and is not a valid retrieval-performance measurement.
`GET /api/health` is the deliberate anonymous exception and does not test
Azure Storage retrieval.

### Collection source APIs

The collector uses these source endpoints:

| Service | Endpoint | Requirement |
|---|---|---|
| Defender | `GET https://api.security.microsoft.com/api/vulnerabilities/machinesVulnerabilities` | Required; `Vulnerability.Read.All` |
| Defender | `GET https://api.security.microsoft.com/api/machines` | Required; `Machine.Read.All` |
| Defender | `GET https://api.security.microsoft.com/api/vulnerabilities` | Required; `Vulnerability.Read.All` |
| Defender | `GET https://api.security.microsoft.com/api/recommendations` | Required; `SecurityRecommendation.Read.All` |
| Defender | `GET https://api.security.microsoft.com/api/recommendations/<recommendation-id>/machineReferences` | Optional relationship enrichment; `SecurityRecommendation.Read.All` |
| Microsoft Graph | `GET https://graph.microsoft.com/v1.0/security/secureScores?$top=1` | Optional; `SecurityEvents.Read.All` |
| Azure Resource Manager | `GET .../providers/Microsoft.Management/managementGroups/<id>/descendants?api-version=2020-05-01` | Optional; Reader on the configured management group |
| Defender compatibility probe | `GET https://api.security.microsoft.com/api/remediationTasks` | Experimental, disabled by default |
| Defender compatibility probe | `GET https://api.security.microsoft.com/api/machines/SoftwareVulnerabilityChangesByMachine` | Experimental, disabled by default |

Validate authorization and a one-row response from the Defender routes plus
Microsoft Graph Secure Score:

```bash
.venv/bin/vulnerability-view preflight
```

Preflight also reports the two experimental compatibility probes as optional;
it does not call every recommendation-specific relationship route or Azure
Resource Manager. Preflight is an access check, not a full-volume performance
test.

Measure complete retrieval with one controlled collection. The retained
`collection-runs.json` dataset records endpoint status, row count, and duration;
collector logs report page or row progress and elapsed time. A controlled
collection also validates the optional Azure Resource Manager subscription
route. Use `./infra/check-runs.sh 5 --progress` and
`./infra/check-function-logs.sh 24 10` for Azure runs.

The Defender token audience is
`https://api.securitycenter.microsoft.com/.default` even though requests use
`https://api.security.microsoft.com`. Microsoft Graph and Azure Resource
Manager use their own token audiences. Do not reuse a token across these
services.

### Azure Storage and Function endpoints

Azure-mode dashboard retrieval starts with:

```text
GET https://<history-account>.blob.core.windows.net/<current-container>/current/manifest.json
```

It then retrieves only the immutable curated blob referenced by that manifest
from:

```text
GET https://<history-account>.blob.core.windows.net/<history-container>/<manifest-file-path>
```

The server verifies compressed size and SHA-256 before returning a dataset.
Use `/api/status`, `/api/data/<asset>.json`, and `/api/diagnostics` to test this
complete path. Direct Blob requests require Microsoft Entra authorization and
must not be made anonymous.

The collector has no public data-retrieval HTTP endpoint. Its timer function can
be invoked through the key-protected Azure Functions admin route
`POST /admin/functions/dataprep_snapshot`, but that starts a collection and can
publish a new immutable run. Use only the guarded helper after confirming no run
is active:

```bash
CONFIRM_LIVE_COLLECTION=yes ./infra/deploy.sh tfinvoke function
```

Do not use the Function admin route as a health check or performance probe.

## 10. Escalation evidence

Capture without including secrets or raw source data:

- command and UTC time;
- run ID or Function operation ID;
- deployment ID;
- HTTP status and required endpoint name;
- manifest status;
- configured Function memory;
- peak working set;
- relevant error/exception text;
- whether the current pointer changed.

Do not paste access tokens, Function keys, client secrets, raw response pages, or
tenant identifiers into tickets or chat.

## Related documents

- [Local evaluation](local-evaluation.md)
- [Azure deployment guide](../DEPLOY.md)
- [Operations and monitoring](operations-and-configuration.md)
- [Command reference](command-reference.md)
- [Data structure and retention](data.md)
