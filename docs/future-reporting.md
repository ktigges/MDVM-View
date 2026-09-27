# Future reporting integrations

> **Author:** Kevin Tigges  
> **Last modified:** 2026-09-27  
> **Purpose:** Record the boundaries and open decisions for deferred reporting integrations.

Power BI, KQL workbooks, and standalone reporting visualizations are deferred.
Their implementation artifacts are intentionally excluded from the active
workspace while development focuses on:

1. Protected Azure Storage.
2. The scheduled collector Function.
3. The authenticated, read-only Web App.

Web App deployment remains deferred. Its infrastructure and application-side
authentication framework are implemented, but production use requires both
App Service Authentication and `DASHBOARD_AUTH_ENABLED=true`.

Future reporting work can consume the immutable curated datasets after the
core collection and web-serving architecture is stable. Before restoring any
reporting implementation, decide:

- Whether Power BI imports curated files or queries a reporting store.
- Refresh frequency, capacity, licensing, and row-level security.
- Whether Log Analytics remains operational telemetry only or also receives
  selected reporting rows.
- Retention and cost requirements for any duplicated reporting data.
- Which SLA and ownership definitions are approved for customer use.

Reporting integrations must remain downstream readers. They must not delete or
rewrite retained paths under `raw/`, `curated/`, or `runs/`.
