variable "subscription_id" {
  description = "Azure subscription for the greenfield deployment."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F-]{36}$", var.subscription_id))
    error_message = "subscription_id must be an Azure subscription GUID."
  }
}

variable "tenant_id" {
  description = "Microsoft Entra tenant containing Defender and the managed identity."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F-]{36}$", var.tenant_id))
    error_message = "tenant_id must be a Microsoft Entra tenant GUID."
  }
}

variable "collector_subscription_reader_ids" {
  description = "Azure subscription IDs where Terraform grants the collector managed identity Reader so the named subscription inventory includes subscriptions with zero findings."
  type        = set(string)
  default     = []

  validation {
    condition     = alltrue([for subscription_id in var.collector_subscription_reader_ids : can(regex("^[0-9a-fA-F-]{36}$", subscription_id))])
    error_message = "Every collector_subscription_reader_ids value must be an Azure subscription GUID."
  }
}

variable "resource_group_name" {
  description = "New resource group for this environment."
  type        = string
}

variable "location" {
  description = "Azure region supported by Flex Consumption."
  type        = string
}

variable "project_name" {
  description = "Short CAF-compatible project name."
  type        = string
  default     = "dvmviewer"
}

variable "environment" {
  description = "Environment suffix used in names and tags."
  type        = string
  default     = "test"
}

variable "history_storage_account_name" {
  description = "Globally unique ADLS Gen2 account for immutable DVM history and the current pointer."
  type        = string
}

variable "history_storage_replication_type" {
  description = "Replication for retained DVM history."
  type        = string
  default     = "LRS"

  validation {
    condition     = contains(["LRS", "ZRS", "GRS", "GZRS"], var.history_storage_replication_type)
    error_message = "Use LRS, ZRS, GRS, or GZRS."
  }
}

variable "history_container_name" {
  description = "Append-only history container."
  type        = string
  default     = "dvm-history"
}

variable "current_container_name" {
  description = "Container holding only the replaceable current manifest pointer."
  type        = string
  default     = "dvm-current"
}

variable "storage_soft_delete_days" {
  description = "Recovery window for accidentally deleted blobs or containers."
  type        = number
  default     = 30

  validation {
    condition     = var.storage_soft_delete_days >= 7 && var.storage_soft_delete_days <= 365
    error_message = "storage_soft_delete_days must be between 7 and 365."
  }
}

variable "history_immutability_days" {
  description = "Minimum WORM retention period for blobs in the history container."
  type        = number
  default     = 365

  validation {
    condition     = var.history_immutability_days >= 1 && var.history_immutability_days <= 146000
    error_message = "history_immutability_days must be between 1 and 146000."
  }
}

variable "lock_history_immutability_policy" {
  description = "Permanently lock the history WORM policy. Once locked, it cannot be removed or shortened."
  type        = bool
  default     = false
}

variable "grant_deployer_history_access" {
  description = "Grant the identity running Terraform Storage Blob Data Contributor on the history account for local status, restore, backfill, and synthetic seeding."
  type        = bool
  default     = true
}

variable "deploy_function" {
  description = "Create the collector Function, runtime storage, identity, monitoring, RBAC, and API permissions."
  type        = bool
  default     = false
}

variable "deploy_web_app" {
  description = "Create the B1 Linux dashboard Web App, read-only identity, Easy Auth application, and group assignments."
  type        = bool
  default     = false
}

variable "web_app_name" {
  description = "Globally unique Linux Web App name."
  type        = string
}

variable "web_app_service_plan_name" {
  description = "App Service plan name for the dashboard."
  type        = string
}

variable "web_app_identity_name" {
  description = "User-assigned managed identity name used by the dashboard to read curated storage."
  type        = string
}

variable "web_app_sku_name" {
  description = "Linux App Service SKU for the dashboard."
  type        = string
  default     = "B1"
}

variable "dashboard_entra_application_name" {
  description = "Display name for the dashboard app registration and Enterprise Application."
  type        = string
  default     = "DVM Viewer"
}

variable "dashboard_data_browser_enabled" {
  description = "Enable the hidden read-only Data evidence URI and assign its app role to the dashboard access group."
  type        = bool
  default     = false
}

variable "dashboard_recommendation_tracking_enabled" {
  description = "Display shared recommendation workflow tracking and enable its API; infrastructure remains provisioned when false."
  type        = bool
  default     = false
}

variable "dashboard_recommendation_tracking_container" {
  description = "Private append-only event container used for shared recommendation workflow state."
  type        = string
  default     = "dvm-workflow"
}

variable "dashboard_cache_seconds" {
  description = "Seconds each Web App process caches the verified Azure current bundle."
  type        = number
  default     = 300

  validation {
    condition     = var.dashboard_cache_seconds >= 0
    error_message = "dashboard_cache_seconds must be zero or greater."
  }
}

variable "function_runtime_storage_account_name" {
  description = "Globally unique storage account used only by the Functions host."
  type        = string
}

variable "function_app_name" {
  description = "Globally unique Function App name."
  type        = string
}

variable "function_instance_memory_in_mb" {
  description = "Memory allocated to each Flex Consumption Function instance."
  type        = number
  default     = 2048

  validation {
    condition     = contains([2048, 4096], var.function_instance_memory_in_mb)
    error_message = "function_instance_memory_in_mb must be 2048 or 4096."
  }
}

variable "collection_schedule" {
  description = "Azure Functions NCRONTAB schedule in UTC."
  type        = string
  default     = "0 0 5 * * *"
}

variable "app_mode" {
  description = "Published data mode. Use live for production or combined to retain labeled synthetic test history beside live data."
  type        = string
  default     = "live"

  validation {
    condition     = contains(["live", "combined"], var.app_mode)
    error_message = "app_mode must be live or combined for the deployed collector."
  }
}

variable "recommendation_enrichment_mode" {
  description = "Recommendation-to-machine enrichment strategy."
  type        = string
  default     = "auto"

  validation {
    condition     = contains(["auto", "targeted", "full", "none"], var.recommendation_enrichment_mode)
    error_message = "recommendation_enrichment_mode must be auto, targeted, full, or none."
  }
}

variable "enable_experimental_endpoints" {
  description = "Enable undocumented Defender compatibility probes. Keep false unless explicitly testing tenant support."
  type        = bool
  default     = false
}

variable "full_enrichment_weekday" {
  description = "Weekly full enrichment day, Monday 0 through Sunday 6."
  type        = number
  default     = 6

  validation {
    condition     = var.full_enrichment_weekday >= 0 && var.full_enrichment_weekday <= 6
    error_message = "full_enrichment_weekday must be from 0 through 6."
  }
}

variable "tags" {
  description = "Common Azure resource tags."
  type        = map(string)
  default = {
    application = "dvmviewer"
    environment = "test"
    managed-by  = "terraform"
  }
}
