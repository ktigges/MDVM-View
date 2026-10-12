# Documentation

> **Last modified:** 2026-10-12
> **Purpose:** Provide one ordered entry point for installation, operations, troubleshooting, application logic, and deep reference material.

Return to the [project README](../README.md) for the product overview and
shortest start paths.

## Recommended reading order

### 1. Deploy or update the hosted application

Use the interactive deployment menu described in the
[project README](../README.md#deploy-or-update). Supporting references are:

1. [Azure deployment guide](../DEPLOY.md) — prerequisites, permissions,
   configuration, protected storage, Function, hosted Web App, and safety
   boundaries
2. [Greenfield Azure deployment](greenfield-deployment.md) — concise operator
   checklist
3. [Environment and deployment design](environment-and-deployment.md) —
   design decisions, environment separation, and production-readiness gates
4. [Publishing and Azure cost options](web-app-deployment-recommendations.md) —
   hosting alternatives, scale, availability, networking, monitoring, and cost

### 2. Local development and evaluation

Local work is intentionally separated from hosted deployment. Start with the
[Local development README](local/README.md).

### 3. Operate

1. [Daily vulnerability remediation workflow](daily-vulnerability-remediation-workflow.md) —
   simple daily steps for selecting, performing, and confirming remediation
2. [Operations and monitoring](operations-and-configuration.md) —
   credentials, managed identities, dashboard access, current-run evidence, and
   operational interfaces
3. [Command reference](command-reference.md) — troubleshooting, automation,
   and individually required commands
4. [Complete configuration reference](configuration-reference.md) — every
   Terraform input, environment variable, JSON key, presentation setting, and
   script override

### 4. Troubleshoot

1. [Troubleshooting](troubleshooting.md) — symptom-led diagnosis for local
   collection, Function runs, storage, Terraform, deployment, authentication,
   and browser behavior
2. [Command reference](command-reference.md) — monitoring and diagnostic
   command details

### 5. Understand SLA and application logic

1. [Application flow](application-flow.md) — exact calls, telemetry, files,
   compression, weekly full behavior, dashboard loading, caching, and lazy CVE
   detail
2. [Dashboard and collection logic](../LOGIC.md) — concise source of truth for
   lifecycle, priority, SLA, recommendation ordering, filters, and work status
3. [Data collection and dashboard workflow](data-collection-and-workflow/) —
   end-to-end collector and user workflow
4. [Data structure and retention](data/) — detailed schema, lineage,
   manifests, overwrite rules, and history semantics

## Find a document by task

| Task | Document |
|---|---|
| See the dashboard before deployment | [Local evaluation](local-evaluation.md) |
| Confirm what the Terraform operator needs | [Azure deployment: required operator permissions](../DEPLOY.md#required-operator-permissions) |
| Create the environment | [Greenfield deployment](greenfield-deployment.md) |
| Deploy Function code | [Azure deployment: deploy the collector](../DEPLOY.md#deploy-the-collector-function) |
| Deploy Web App code | [Azure deployment: deploy the dashboard Web App](../DEPLOY.md#deploy-the-authenticated-dashboard-web-app) |
| Collect data now | [Operations and monitoring](operations-and-configuration.md) |
| Follow the daily remediation process | [Daily vulnerability remediation workflow](daily-vulnerability-remediation-workflow.md) |
| Build or export the management report | [Daily workflow: Executive Snapshot](daily-vulnerability-remediation-workflow.md#7-build-the-executive-snapshot) |
| Check active progress or failed runs | [Troubleshooting](troubleshooting.md#4-collector-progress-failure-and-memory) |
| Find a command | [Command reference](command-reference.md) |
| Find a setting | [Configuration reference](configuration-reference.md) |
| Understand what a job calls and what files it creates | [Application flow](application-flow.md) |
| Understand fixed/reopened logic | [Dashboard and collection logic](../LOGIC.md#6-finding-completion-and-reopening) |
| Understand SLA clocks | [Dashboard and collection logic](../LOGIC.md#5-sla-targeting) |
| Understand retention and purge behavior | [Data structure and retention](data/) |
| Estimate Azure cost | [Publishing and Azure cost options](web-app-deployment-recommendations.md#calculator-worksheet) |
| Collect or replay sample data | [Collect and replay a sample](sample-replay.md) |

## Document roles

The long reference documents are intentionally retained:

- `DEPLOY.md` is the canonical full Azure installation runbook.
- `greenfield-deployment.md` is the short deployment checklist, not a second
  architecture specification.
- `operations-and-configuration.md` describes ongoing operation.
- `command-reference.md` answers “what command do I run?”
- `configuration-reference.md` answers “what does this setting do?”
- `application-flow.md` answers “what happens from job start through dashboard
  rendering?”
- `LOGIC.md` answers “how is this result calculated?”
- `data-collection-and-workflow/README.md` explains end-to-end behavior.
- `data/README.md` is the detailed data contract and lineage reference.
- `environment-and-deployment.md` and
  `web-app-deployment-recommendations.md` retain design rationale and options;
  they are not first-run procedures.
