# Last modified: 2026-10-08
# Purpose: Provision protected Azure infrastructure for the collector and authenticated dashboard.

terraform {
  required_version = ">= 1.10.0"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
    azurecaf = {
      source  = "aztfmod/azurecaf"
      version = "~> 1.2"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.13"
    }
  }
}

provider "azuread" {
  tenant_id = var.tenant_id
}

provider "azurerm" {
  subscription_id     = var.subscription_id
  storage_use_azuread = true

  features {}
}

provider "azurecaf" {}
provider "time" {}

data "azurerm_client_config" "current" {}

locals {
  function_instances = var.deploy_function ? { collector = true } : {}
  web_app_instances  = var.deploy_web_app ? { dashboard = true } : {}
  network_security_perimeter_instances = var.network_security_perimeter_enabled ? {
    storage = true
  } : {}
  role_definition_ids = {
    storage_blob_data_owner        = "/subscriptions/${var.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/b7e6dc6d-f1e8-4753-8033-0f276bb0955b"
    storage_blob_data_contributor  = "/subscriptions/${var.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/ba92f5b4-2d11-453d-a403-e96b0029c9fe"
    storage_blob_data_reader       = "/subscriptions/${var.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
    storage_queue_data_contributor = "/subscriptions/${var.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/974c5e8b-45b9-4653-ba55-5f855dd0fb88"
    storage_table_data_contributor = "/subscriptions/${var.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3"
    monitoring_metrics_publisher   = "/subscriptions/${var.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/3913510d-42f4-4e42-8a64-420c390055eb"
  }
}

resource "azurerm_resource_group" "environment" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

resource "azurerm_network_security_perimeter" "storage" {
  for_each = local.network_security_perimeter_instances

  name                = "nsp-${var.project_name}-${var.environment}"
  resource_group_name = azurerm_resource_group.environment.name
  location            = azurerm_resource_group.environment.location
  tags                = var.tags
}

resource "azurerm_network_security_perimeter_profile" "storage" {
  for_each = local.network_security_perimeter_instances

  name                          = "storage"
  network_security_perimeter_id = azurerm_network_security_perimeter.storage[each.key].id
}

resource "azurerm_network_security_perimeter_access_rule" "deployment_subscription" {
  for_each = local.network_security_perimeter_instances

  name                                  = "allow-deployment-subscription"
  network_security_perimeter_profile_id = azurerm_network_security_perimeter_profile.storage[each.key].id
  direction                             = "Inbound"
  subscription_ids                      = ["/subscriptions/${var.subscription_id}"]
}

resource "azurerm_network_security_perimeter_access_rule" "public_ips" {
  for_each = var.network_security_perimeter_enabled && length(var.network_security_perimeter_allowed_ip_cidrs) > 0 ? {
    storage = true
  } : {}

  name                                  = "allow-configured-public-ips"
  network_security_perimeter_profile_id = azurerm_network_security_perimeter_profile.storage[each.key].id
  direction                             = "Inbound"
  address_prefixes                      = sort(tolist(var.network_security_perimeter_allowed_ip_cidrs))
}

resource "azurerm_storage_account" "history" {
  name                            = var.history_storage_account_name
  resource_group_name             = azurerm_resource_group.environment.name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = var.history_storage_replication_type
  account_kind                    = "StorageV2"
  access_tier                     = "Hot"
  is_hns_enabled                  = true
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = true
  shared_access_key_enabled       = false
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true

  blob_properties {
    delete_retention_policy {
      days = var.storage_soft_delete_days
    }
    container_delete_retention_policy {
      days = var.storage_soft_delete_days
    }
  }

  tags = var.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_storage_container" "history" {
  name                  = var.history_container_name
  storage_account_id    = azurerm_storage_account.history.id
  container_access_type = "private"

  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_storage_container_immutability_policy" "history" {
  storage_container_resource_manager_id = azurerm_storage_container.history.id
  immutability_period_in_days           = var.history_immutability_days
  locked                                = var.lock_history_immutability_policy

  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_storage_container" "current" {
  name                  = var.current_container_name
  storage_account_id    = azurerm_storage_account.history.id
  container_access_type = "private"

  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_storage_container" "dashboard_workflow" {
  count = var.deploy_web_app ? 1 : 0

  name                  = var.dashboard_recommendation_tracking_container
  storage_account_id    = azurerm_storage_account.history.id
  container_access_type = "private"

  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_network_security_perimeter_association" "history_storage" {
  for_each = local.network_security_perimeter_instances

  name                                  = "history-storage"
  network_security_perimeter_profile_id = azurerm_network_security_perimeter_profile.storage[each.key].id
  resource_id                           = azurerm_storage_account.history.id
  access_mode                           = var.network_security_perimeter_access_mode

  depends_on = [
    azurerm_storage_container.current,
    azurerm_storage_container_immutability_policy.history,
  ]
}

resource "azurerm_role_assignment" "history_blob_contributor_deployer" {
  count = var.grant_deployer_history_access ? 1 : 0

  scope              = azurerm_storage_account.history.id
  role_definition_id = local.role_definition_ids.storage_blob_data_contributor
  principal_id       = data.azurerm_client_config.current.object_id
}

resource "azurecaf_name" "service_plan" {
  for_each = local.function_instances

  name          = var.project_name
  resource_type = "azurerm_app_service_plan"
  suffixes      = [var.environment]
  clean_input   = true
}

resource "azurecaf_name" "collector_identity" {
  for_each = local.function_instances

  name          = var.project_name
  resource_type = "azurerm_user_assigned_identity"
  suffixes      = [var.environment]
  clean_input   = true
}

resource "azurecaf_name" "log_analytics" {
  for_each = local.function_instances

  name          = var.project_name
  resource_type = "azurerm_log_analytics_workspace"
  suffixes      = [var.environment]
  clean_input   = true
}

resource "azurecaf_name" "application_insights" {
  for_each = local.function_instances

  name          = var.project_name
  resource_type = "azurerm_application_insights"
  suffixes      = [var.environment]
  clean_input   = true
}

resource "azurerm_storage_account" "function_runtime" {
  for_each = local.function_instances

  name                            = var.function_runtime_storage_account_name
  resource_group_name             = azurerm_resource_group.environment.name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  account_kind                    = "StorageV2"
  access_tier                     = "Hot"
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = true
  shared_access_key_enabled       = false
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true

  blob_properties {
    delete_retention_policy {
      days = 7
    }
    container_delete_retention_policy {
      days = 7
    }
  }

  tags = var.tags
}

resource "azurerm_storage_container" "function_deployment" {
  for_each = local.function_instances

  name                  = "function-releases"
  storage_account_id    = azurerm_storage_account.function_runtime[each.key].id
  container_access_type = "private"
}

resource "azurerm_network_security_perimeter_association" "function_runtime_storage" {
  for_each = var.network_security_perimeter_enabled ? local.function_instances : {}

  name                                  = "function-runtime-storage"
  network_security_perimeter_profile_id = azurerm_network_security_perimeter_profile.storage["storage"].id
  resource_id                           = azurerm_storage_account.function_runtime[each.key].id
  access_mode                           = var.network_security_perimeter_access_mode

  depends_on = [
    azurerm_storage_container.function_deployment,
  ]
}

resource "azurerm_user_assigned_identity" "collector" {
  for_each = local.function_instances

  name                = azurecaf_name.collector_identity[each.key].result
  resource_group_name = azurerm_resource_group.environment.name
  location            = var.location
  tags                = var.tags
}

resource "azurerm_role_assignment" "collector_subscription_reader" {
  for_each = var.deploy_function && var.collector_management_group_id == "" ? var.collector_subscription_reader_ids : toset([])

  scope                            = "/subscriptions/${each.value}"
  role_definition_name             = "Reader"
  principal_id                     = azurerm_user_assigned_identity.collector["collector"].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}

resource "azurerm_role_assignment" "collector_management_group_reader" {
  count = var.deploy_function && var.collector_management_group_id != "" ? 1 : 0

  scope                            = "/providers/Microsoft.Management/managementGroups/${var.collector_management_group_id}"
  role_definition_name             = "Reader"
  principal_id                     = azurerm_user_assigned_identity.collector["collector"].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}

resource "azurerm_role_assignment" "runtime_blob_owner" {
  for_each = local.function_instances

  scope              = azurerm_storage_account.function_runtime[each.key].id
  role_definition_id = local.role_definition_ids.storage_blob_data_owner
  principal_id       = azurerm_user_assigned_identity.collector[each.key].principal_id
  principal_type     = "ServicePrincipal"
}

resource "azurerm_role_assignment" "runtime_blob_contributor" {
  for_each = local.function_instances

  scope              = azurerm_storage_account.function_runtime[each.key].id
  role_definition_id = local.role_definition_ids.storage_blob_data_contributor
  principal_id       = azurerm_user_assigned_identity.collector[each.key].principal_id
  principal_type     = "ServicePrincipal"
}

resource "azurerm_role_assignment" "runtime_queue_contributor" {
  for_each = local.function_instances

  scope              = azurerm_storage_account.function_runtime[each.key].id
  role_definition_id = local.role_definition_ids.storage_queue_data_contributor
  principal_id       = azurerm_user_assigned_identity.collector[each.key].principal_id
  principal_type     = "ServicePrincipal"
}

resource "azurerm_role_assignment" "runtime_table_contributor" {
  for_each = local.function_instances

  scope              = azurerm_storage_account.function_runtime[each.key].id
  role_definition_id = local.role_definition_ids.storage_table_data_contributor
  principal_id       = azurerm_user_assigned_identity.collector[each.key].principal_id
  principal_type     = "ServicePrincipal"
}

resource "azurerm_role_assignment" "history_blob_contributor" {
  for_each = local.function_instances

  scope              = azurerm_storage_account.history.id
  role_definition_id = local.role_definition_ids.storage_blob_data_contributor
  principal_id       = azurerm_user_assigned_identity.collector[each.key].principal_id
  principal_type     = "ServicePrincipal"
}

resource "azurerm_log_analytics_workspace" "function" {
  for_each = local.function_instances

  name                = azurecaf_name.log_analytics[each.key].result
  resource_group_name = azurerm_resource_group.environment.name
  location            = var.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = var.tags
}

resource "azurerm_application_insights" "function" {
  for_each = local.function_instances

  name                = azurecaf_name.application_insights[each.key].result
  resource_group_name = azurerm_resource_group.environment.name
  location            = var.location
  workspace_id        = azurerm_log_analytics_workspace.function[each.key].id
  application_type    = "web"
  tags                = var.tags
}

resource "azurerm_role_assignment" "monitoring_metrics_publisher" {
  for_each = local.function_instances

  scope              = azurerm_application_insights.function[each.key].id
  role_definition_id = local.role_definition_ids.monitoring_metrics_publisher
  principal_id       = azurerm_user_assigned_identity.collector[each.key].principal_id
  principal_type     = "ServicePrincipal"
}

resource "azurerm_service_plan" "function" {
  for_each = local.function_instances

  name                = azurecaf_name.service_plan[each.key].result
  resource_group_name = azurerm_resource_group.environment.name
  location            = var.location
  os_type             = "Linux"
  sku_name            = "FC1"
  tags                = var.tags
}

resource "azurerm_function_app_flex_consumption" "collector" {
  for_each = local.function_instances

  name                = var.function_app_name
  resource_group_name = azurerm_resource_group.environment.name
  location            = var.location
  service_plan_id     = azurerm_service_plan.function[each.key].id

  storage_container_type                         = "blobContainer"
  storage_container_endpoint                     = "${azurerm_storage_account.function_runtime[each.key].primary_blob_endpoint}${azurerm_storage_container.function_deployment[each.key].name}"
  storage_authentication_type                    = "UserAssignedIdentity"
  storage_user_assigned_identity_id              = azurerm_user_assigned_identity.collector[each.key].id
  runtime_name                                   = "python"
  runtime_version                                = "3.12"
  maximum_instance_count                         = 1
  instance_memory_in_mb                          = var.function_instance_memory_in_mb
  https_only                                     = true
  public_network_access_enabled                  = true
  webdeploy_publish_basic_authentication_enabled = false

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.collector[each.key].id]
  }

  site_config {
    application_insights_connection_string = azurerm_application_insights.function[each.key].connection_string
    minimum_tls_version                    = "1.2"
    scm_minimum_tls_version                = "1.2"
  }

  app_settings = {
    "APP_MODE"                         = var.app_mode
    "AUTH_MODE"                        = "managed_identity"
    "AZURE_CLIENT_ID"                  = azurerm_user_assigned_identity.collector[each.key].client_id
    "AZURE_MANAGEMENT_GROUP_ID"        = var.collector_management_group_id
    "AzureWebJobsFeatureFlags"         = "EnableWorkerIndexing"
    "COLLECTOR_VERSION"                = var.function_version
    "AzureWebJobsStorage__accountName" = azurerm_storage_account.function_runtime[each.key].name
    "AzureWebJobsStorage__clientId"    = azurerm_user_assigned_identity.collector[each.key].client_id
    "AzureWebJobsStorage__credential"  = "managedidentity"
    "COLLECTION_SCHEDULE"              = var.collection_schedule
    "DEFENDER_API_BASE_URL"            = "https://api.security.microsoft.com"
    "ENABLE_EXPERIMENTAL_ENDPOINTS"    = tostring(var.enable_experimental_endpoints)
    "FULL_ENRICHMENT_WEEKDAY"          = tostring(var.full_enrichment_weekday)
    "RECOMMENDATION_ENRICHMENT_MODE"   = var.recommendation_enrichment_mode
    "STORAGE_ACCOUNT_NAME"             = azurerm_storage_account.history.name
    "STORAGE_CONTAINER_NAME"           = azurerm_storage_container.history.name
    "STORAGE_CURRENT_CONTAINER_NAME"   = azurerm_storage_container.current.name
  }

  lifecycle {
    ignore_changes = [app_settings["COLLECTOR_VERSION"]]
  }

  tags = merge(var.tags, {
    "hidden-link: /app-insights-resource-id" = replace(
      azurerm_application_insights.function[each.key].id,
      "Microsoft.Insights",
      "microsoft.insights"
    )
  })

  depends_on = [
    azurerm_network_security_perimeter_association.function_runtime_storage,
    azurerm_network_security_perimeter_association.history_storage,
    azurerm_role_assignment.runtime_blob_owner,
    azurerm_role_assignment.runtime_blob_contributor,
    azurerm_role_assignment.runtime_queue_contributor,
    azurerm_role_assignment.runtime_table_contributor,
    azurerm_role_assignment.history_blob_contributor,
    azurerm_role_assignment.collector_subscription_reader,
    azurerm_role_assignment.collector_management_group_reader,
  ]
}

resource "azurerm_monitor_diagnostic_setting" "function" {
  for_each = local.function_instances

  name                       = "send-to-log-analytics"
  target_resource_id         = azurerm_function_app_flex_consumption.collector[each.key].id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.function[each.key].id

  enabled_log {
    category_group = "allLogs"
  }

  enabled_metric {
    category = "AllMetrics"
  }
}

data "azuread_service_principal" "defender" {
  count = var.deploy_function ? 1 : 0

  client_id = "fc780465-2017-40d4-a0c5-307022471b92"
}

data "azuread_service_principal" "microsoft_graph" {
  count = var.deploy_function ? 1 : 0

  client_id = "00000003-0000-0000-c000-000000000000"
}

locals {
  defender_role_names = toset([
    "Machine.Read.All",
    "SecurityRecommendation.Read.All",
    "Vulnerability.Read.All",
  ])
  defender_app_roles = var.deploy_function ? {
    for role in data.azuread_service_principal.defender[0].app_roles :
    role.value => role.id
    if contains(local.defender_role_names, role.value) && contains(role.allowed_member_types, "Application")
  } : {}
  graph_security_events_role_id = var.deploy_function ? one([
    for role in data.azuread_service_principal.microsoft_graph[0].app_roles :
    role.id
    if role.value == "SecurityEvents.Read.All" && contains(role.allowed_member_types, "Application")
  ]) : null
}

resource "azuread_app_role_assignment" "defender" {
  for_each = local.defender_app_roles

  app_role_id         = each.value
  principal_object_id = azurerm_user_assigned_identity.collector["collector"].principal_id
  resource_object_id  = data.azuread_service_principal.defender[0].object_id
}

resource "azuread_app_role_assignment" "security_events" {
  count = var.deploy_function ? 1 : 0

  app_role_id         = local.graph_security_events_role_id
  principal_object_id = azurerm_user_assigned_identity.collector["collector"].principal_id
  resource_object_id  = data.azuread_service_principal.microsoft_graph[0].object_id
}

resource "azuread_application" "dashboard" {
  count = var.deploy_web_app ? 1 : 0

  display_name     = var.dashboard_entra_application_name
  sign_in_audience = "AzureADMyOrg"

  app_role {
    allowed_member_types = ["User"]
    description          = "Allows assigned users and groups to open the DVM Viewer dashboard."
    display_name         = "Dashboard Viewer"
    enabled              = true
    id                   = "8d0f4d06-b074-4b7f-93f8-28c06ec15a80"
    value                = "Dashboard.Viewer"
  }

  app_role {
    allowed_member_types = ["User"]
    description          = "Allows assigned users and groups to inspect curated dashboard evidence."
    display_name         = "Data Evidence Reader"
    enabled              = true
    id                   = "9985ad32-23ea-4d13-bcd7-79e744469941"
    value                = "Data.Evidence.Reader"
  }

  app_role {
    allowed_member_types = ["User"]
    description          = "Allows assigned users and groups to update shared recommendation workflow status."
    display_name         = "Recommendation Tracker"
    enabled              = true
    id                   = "68a85f59-c190-405e-82e4-c2d66280eece"
    value                = "Recommendation.Tracker"
  }

  web {
    homepage_url  = "https://${var.web_app_name}.azurewebsites.net/"
    logout_url    = "https://${var.web_app_name}.azurewebsites.net/.auth/logout"
    redirect_uris = ["https://${var.web_app_name}.azurewebsites.net/.auth/login/aad/callback"]

    implicit_grant {
      access_token_issuance_enabled = false
      id_token_issuance_enabled     = true
    }
  }
}

resource "azuread_service_principal" "dashboard" {
  count = var.deploy_web_app ? 1 : 0

  client_id                    = azuread_application.dashboard[0].client_id
  app_role_assignment_required = true
}

resource "time_rotating" "dashboard_auth" {
  count = var.deploy_web_app ? 1 : 0

  rotation_days = 365
}

resource "azuread_application_password" "dashboard" {
  count = var.deploy_web_app ? 1 : 0

  application_id = azuread_application.dashboard[0].id
  display_name   = "App Service Easy Auth"
  end_date       = timeadd(time_rotating.dashboard_auth[0].rfc3339, "17520h")
  rotate_when_changed = {
    rotation = time_rotating.dashboard_auth[0].id
  }
}

resource "azurerm_user_assigned_identity" "dashboard" {
  for_each = local.web_app_instances

  name                = var.web_app_identity_name
  resource_group_name = azurerm_resource_group.environment.name
  location            = var.location
  tags                = var.tags
}

resource "azurerm_role_assignment" "dashboard_history_reader" {
  for_each = local.web_app_instances

  scope              = azurerm_storage_account.history.id
  role_definition_id = local.role_definition_ids.storage_blob_data_reader
  principal_id       = azurerm_user_assigned_identity.dashboard[each.key].principal_id
  principal_type     = "ServicePrincipal"
}

resource "azurerm_role_assignment" "dashboard_workflow_contributor" {
  count = var.deploy_web_app ? 1 : 0

  scope              = azurerm_storage_container.dashboard_workflow[0].id
  role_definition_id = local.role_definition_ids.storage_blob_data_contributor
  principal_id       = azurerm_user_assigned_identity.dashboard["dashboard"].principal_id
  principal_type     = "ServicePrincipal"
}

resource "azurerm_service_plan" "dashboard" {
  for_each = local.web_app_instances

  name                = var.web_app_service_plan_name
  resource_group_name = azurerm_resource_group.environment.name
  location            = var.location
  os_type             = "Linux"
  sku_name            = var.web_app_sku_name
  tags                = var.tags
}

resource "azurerm_linux_web_app" "dashboard" {
  for_each = local.web_app_instances

  name                                           = var.web_app_name
  resource_group_name                            = azurerm_resource_group.environment.name
  location                                       = var.location
  service_plan_id                                = azurerm_service_plan.dashboard[each.key].id
  https_only                                     = true
  ftp_publish_basic_authentication_enabled       = false
  webdeploy_publish_basic_authentication_enabled = false

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.dashboard[each.key].id]
  }

  site_config {
    always_on                = true
    app_command_line         = "python -m uvicorn vulnerability_view.dashboard_server:app --host 0.0.0.0 --port 8000"
    ftps_state               = "Disabled"
    minimum_tls_version      = "1.2"
    scm_minimum_tls_version  = "1.2"
    remote_debugging_enabled = false
    application_stack {
      python_version = "3.12"
    }
  }

  auth_settings_v2 {
    auth_enabled           = true
    default_provider       = "azureactivedirectory"
    require_authentication = true
    require_https          = true
    unauthenticated_action = "RedirectToLoginPage"

    active_directory_v2 {
      client_id                  = azuread_application.dashboard[0].client_id
      client_secret_setting_name = "MICROSOFT_PROVIDER_AUTHENTICATION_SECRET"
      tenant_auth_endpoint       = "https://login.microsoftonline.com/${var.tenant_id}/v2.0"
      allowed_audiences = [
        azuread_application.dashboard[0].client_id,
        "api://${azuread_application.dashboard[0].client_id}",
      ]
    }

    login {
      token_store_enabled = true
    }
  }

  app_settings = {
    "AUTH_MODE"                                   = "managed_identity"
    "AZURE_CLIENT_ID"                             = azurerm_user_assigned_identity.dashboard[each.key].client_id
    "DASHBOARD_AUTH_ENABLED"                      = "true"
    "DASHBOARD_CACHE_SECONDS"                     = tostring(var.dashboard_cache_seconds)
    "DASHBOARD_VERSION"                           = var.dashboard_version
    "DASHBOARD_DATA_BROWSER_ENABLED"              = tostring(var.dashboard_data_browser_enabled)
    "DASHBOARD_DATA_BROWSER_ROLE"                 = var.dashboard_data_browser_enabled ? "Data.Evidence.Reader" : ""
    "DASHBOARD_DATA_SOURCE"                       = "azure"
    "DASHBOARD_RECOMMENDATION_TRACKING_CONTAINER" = var.dashboard_recommendation_tracking_container
    "DASHBOARD_RECOMMENDATION_TRACKING_ENABLED"   = tostring(var.dashboard_recommendation_tracking_enabled)
    "DASHBOARD_RECOMMENDATION_TRACKING_ROLE"      = "Recommendation.Tracker"
    "DASHBOARD_STATIC_DIR"                        = "dashboard"
    "MICROSOFT_PROVIDER_AUTHENTICATION_SECRET"    = azuread_application_password.dashboard[0].value
    "SCM_DO_BUILD_DURING_DEPLOYMENT"              = "true"
    "STORAGE_ACCOUNT_NAME"                        = azurerm_storage_account.history.name
    "STORAGE_CONTAINER_NAME"                      = azurerm_storage_container.history.name
    "STORAGE_CURRENT_CONTAINER_NAME"              = azurerm_storage_container.current.name
  }

  lifecycle {
    ignore_changes = [app_settings["DASHBOARD_VERSION"]]
  }

  tags = var.tags

  depends_on = [
    azurerm_network_security_perimeter_association.history_storage,
    azurerm_role_assignment.dashboard_history_reader,
    azurerm_role_assignment.dashboard_workflow_contributor,
  ]
}
