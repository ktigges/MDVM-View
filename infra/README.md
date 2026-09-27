# Azure infrastructure

> **Author:** Kevin Tigges  
> **Last modified:** 2026-09-27  
> **Purpose:** Summarize the staged Terraform infrastructure and point operators to the deployment procedures.

The active Terraform configuration is in [`terraform/`](terraform/). It
supports three cumulative reviewed stages:

1. Greenfield resource group and protected history storage.
2. Optional collector Function, managed identity, permissions, and monitoring.
3. Optional authenticated B1 Linux Web App, read-only identity, and Entra group assignment.

Run the stages through [`deploy.sh`](deploy.sh) using `tfplan`, `tfapply`,
`tfdeploy`, `tfverify`, and guarded `tfdestroy` commands. Full prerequisites,
required values, and commands are documented in
[`../docs/greenfield-deployment.md`](../docs/greenfield-deployment.md).

Before planning, copy `terraform/main.tfvars.example.json` to the ignored
`terraform/main.tfvars.json` and replace all customer-specific values. Never
commit real tenant IDs, subscription IDs, names, or environment values.

The Web App stage creates one Linux B1 App Service, a dedicated read-only
managed identity, an Entra app registration and Enterprise Application named
`DVM Viewer`, Easy Auth, and app-role assignments for an Entra group. After
apply, Terraform outputs `dashboard_enterprise_application_object_id` and
`dashboard_entra_client_id` identify the application. Manage assignments at
**Microsoft Entra ID > Enterprise applications > DVM Viewer > Users and
groups**. Group-based assignment requires the applicable Microsoft Entra ID
licensing; if it is unavailable, assign individual users the
`Dashboard.Viewer` role.

By default Terraform creates `DVM Viewer Users`; supply
`dashboard_access_group_object_id` to reuse an existing group. When
`dashboard_data_browser_enabled=true`, the same group also receives
`Data.Evidence.Reader`; the link remains hidden and is opened directly at
`/?view=data-browser`. Hosting, security, caching, and scale recommendations are in
[`../docs/web-app-deployment-recommendations.md`](../docs/web-app-deployment-recommendations.md).
Existing storage accounts and retained DVM history are outside this Terraform
state and must not be deleted or imported into it.

The collector also queries Azure Resource Manager for a named subscription
inventory. Set `collector_subscription_reader_ids` to every subscription that
should appear, including subscriptions with zero findings. The Function
Terraform stage manages the Reader assignments. Its deployer must have
role-assignment permission in every listed subscription.
