output "resource_group_name" {
  value = azurerm_resource_group.environment.name
}

output "deployer_principal_object_id" {
  value = data.azurerm_client_config.current.object_id
}

output "history_storage_account_name" {
  value = azurerm_storage_account.history.name
}

output "history_container_name" {
  value = azurerm_storage_container.history.name
}

output "history_immutability_days" {
  value = azurerm_storage_container_immutability_policy.history.immutability_period_in_days
}

output "history_immutability_locked" {
  value = coalesce(azurerm_storage_container_immutability_policy.history.locked, false)
}

output "current_container_name" {
  value = azurerm_storage_container.current.name
}

output "function_app_name" {
  value = try(azurerm_function_app_flex_consumption.collector["collector"].name, null)
}

output "function_app_default_hostname" {
  value = try(azurerm_function_app_flex_consumption.collector["collector"].default_hostname, null)
}

output "collector_identity_client_id" {
  value = try(azurerm_user_assigned_identity.collector["collector"].client_id, null)
}

output "collector_identity_principal_id" {
  value = try(azurerm_user_assigned_identity.collector["collector"].principal_id, null)
}

output "collector_subscription_reader_scopes" {
  value = sort([for assignment in azurerm_role_assignment.collector_subscription_reader : assignment.scope])
}

output "function_runtime_storage_account_name" {
  value = try(azurerm_storage_account.function_runtime["collector"].name, null)
}

output "web_app_name" {
  value = try(azurerm_linux_web_app.dashboard["dashboard"].name, null)
}

output "web_app_default_hostname" {
  value = try(azurerm_linux_web_app.dashboard["dashboard"].default_hostname, null)
}

output "dashboard_identity_client_id" {
  value = try(azurerm_user_assigned_identity.dashboard["dashboard"].client_id, null)
}

output "dashboard_identity_principal_id" {
  value = try(azurerm_user_assigned_identity.dashboard["dashboard"].principal_id, null)
}

output "dashboard_entra_client_id" {
  value = try(azuread_application.dashboard[0].client_id, null)
}

output "dashboard_enterprise_application_name" {
  value = var.deploy_web_app ? var.dashboard_entra_application_name : null
}

output "dashboard_enterprise_application_object_id" {
  value = try(azuread_service_principal.dashboard[0].object_id, null)
}

output "dashboard_access_group_object_id" {
  value = local.dashboard_access_group_object_id
}

output "dashboard_access_group_name" {
  value = var.deploy_web_app ? (
    var.dashboard_access_group_object_id == ""
    ? azuread_group.dashboard_access[0].display_name
    : "Existing group"
  ) : null
}

output "dashboard_url" {
  value = try("https://${azurerm_linux_web_app.dashboard["dashboard"].default_hostname}", null)
}
