# Documentation

The [project README](../README.md) covers the purpose, technology, architecture,
and maintenance handoff. The documents below cover the details without repeating
the same setup in each guide.

## Main references

| Subject | Document | What belongs there |
|---|---|---|
| Architecture and runtime | [Application flow](application-flow.md) | Collection, publication, dashboard startup, indexes, caches, and source map |
| Calculation rules | [Dashboard and collection logic](../LOGIC.md) | Finding identity, lifecycle, SLA, priority, filtering, and work status |
| Azure installation and updates | [Deployment guide](../DEPLOY.md) | Prerequisites, permissions, configuration, deployment, and verification |
| Daily operation | [Operations and monitoring](operations-and-configuration.md) | Run status, manual collection, access, logs, and snapshot export |
| Dashboard use | [Daily remediation workflow](daily-vulnerability-remediation-workflow.md) | Reviewing exposure, selecting work, and confirming outcomes |
| Maintenance and tests | [Development](development.md) | Local work, validation, release versions, benchmarks, and index maintenance |
| Problem diagnosis | [Troubleshooting](troubleshooting.md) | Symptoms, checks, and recovery |
| Settings | [Configuration reference](configuration-reference.md) | Configuration files, precedence, runtime settings, and Terraform inputs |
| Commands | [Command reference](command-reference.md) | CLI syntax and what each operation changes |
| Data contract | [Data structure and retention](data/README.md) | Schemas, manifests, storage layout, lineage, and overwrite rules |

## Supporting guides

- [Greenfield deployment checklist](greenfield-deployment.md): installation
  sequence for an operator who already has the required access and tools.
- [Infrastructure tooling](../infra/README.md): deployment CLI internals,
  cumulative Terraform stages, and migration from earlier collector hosting.
- [Environment boundaries](environment-and-deployment.md): local, test, and
  production separation and the deployment handoff.
- [Hosting and cost notes](web-app-deployment-recommendations.md): current
  hosting baseline, capacity choices, and calculator assumptions.
- [Local evaluation](local-evaluation.md): viewing the application without a
  hosted deployment.
- [Sample collection and replay](sample-replay.md): authorized transfer of
  raw evidence and local replay.

## Documentation maintenance

Behavior belongs in the runtime or calculation reference. Commands belong in
the command reference; setting definitions belong in the configuration
reference. Other guides link to those details instead of maintaining another copy.

Measurements need their data shape, runtime, hardware, and test scope. A local
benchmark is not a hosted performance guarantee. Temporary timings and completed
implementation notes do not belong in the project overview.

Environment-specific access, resource names, Terraform state, and customer
data belong in the organization's protected records, not in these guides.
