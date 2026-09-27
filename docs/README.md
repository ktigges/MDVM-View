# Design documents

> **Author:** Kevin Tigges  
> **Last modified:** 2026-09-27  
> **Purpose:** Index the architecture, deployment, data, and operations documentation.

- [Azure deployment guide](../DEPLOY.md) - Operator guide covering both storage accounts, all Terraform-created resources and permissions, data migration, collector deployment, invocation, and safe teardown.
- [Data collection and dashboard workflow](data-collection-and-workflow.md) - Collection, raw retention, normalization, finding lifecycle, SLA calculations, exports, storage, and dashboard behavior.
- [Data structure and retention](data.md) - Detailed reference for live sources, retained datasets, per-run downloads, overwrite behavior, finding lifecycle, Graph relationships, and SLA history.
- [Operations and configuration](operations-and-configuration.md) - Managed identity, local credentials, default-off dashboard user authentication, curated data evidence controls, runtime configuration, status sources, and local commands.
- [Environment and deployment plan](environment-and-deployment.md) - Local live testing, Azure resource inventory, hosted data path, environment separation, and production readiness gates.
- [Greenfield Azure deployment](greenfield-deployment.md) - Required values and staged `tf*` commands for storage and the collector Function.
- [Web App deployment recommendations](web-app-deployment-recommendations.md) - Low-cost hosting, Microsoft Entra/App Service authentication, caching, and scale recommendations.
