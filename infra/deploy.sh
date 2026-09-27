#!/usr/bin/env bash
# Author: Kevin Tigges
# Last modified: 2026-09-27
# Purpose: Plan, deploy, verify, and invoke the protected Azure collector and dashboard stages.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="$ROOT_DIR/infra/terraform"
TF_VARS="$TF_DIR/main.tfvars.json"

require_tf_vars() {
  # Stops deployment commands when the ignored customer values file is absent.
  if [[ ! -f "$TF_VARS" ]]; then
    echo "Terraform values are missing: $TF_VARS" >&2
    echo "Copy main.tfvars.example.json to main.tfvars.json and replace every customer value." >&2
    exit 1
  fi
}

require_command() {
  # Fails with a direct message when a required local executable is unavailable.
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    exit 1
  fi
}

tf_output() {
  # Reads one raw value from the active Terraform state.
  terraform -chdir="$TF_DIR" output -raw "$1"
}

show_dashboard_access_details() {
  # Prints the exact Enterprise Application and group used for user assignment.
  cat <<EOF
Enterprise Application: $(tf_output dashboard_enterprise_application_name)
Application (client) ID: $(tf_output dashboard_entra_client_id)
Enterprise Application object ID: $(tf_output dashboard_enterprise_application_object_id)
Assigned group: $(tf_output dashboard_access_group_name)
Assigned group object ID: $(tf_output dashboard_access_group_object_id)
Assignment location: Microsoft Entra admin center > Enterprise applications > $(tf_output dashboard_enterprise_application_name) > Users and groups
EOF
}

tf_init() {
  # Initializes providers and validates the Terraform configuration.
  require_command terraform
  terraform -chdir="$TF_DIR" init -input=false
  terraform -chdir="$TF_DIR" validate
}

tf_plan() {
  # Creates a reviewed plan for one cumulative infrastructure stage.
  local stage="${1:-}"
  require_tf_vars
  case "$stage" in
    foundation)
      if terraform -chdir="$TF_DIR" output -raw function_app_name 2>/dev/null | grep -qv '^null$' \
        || terraform -chdir="$TF_DIR" output -raw web_app_name 2>/dev/null | grep -qv '^null$'; then
        echo "Application stages already exist. Use the highest deployed cumulative stage instead of 'foundation'." >&2
        exit 1
      fi
      tf_init
      terraform -chdir="$TF_DIR" plan \
        -input=false \
        -var-file="$TF_VARS" \
        -var="deploy_function=false" \
        -out=foundation.tfplan
      ;;
    function)
      if terraform -chdir="$TF_DIR" output -raw web_app_name 2>/dev/null | grep -qv '^null$'; then
        echo "The Web App is already deployed. Use 'tfplan webapp' so the cumulative plan preserves it." >&2
        exit 1
      fi
      tf_init
      terraform -chdir="$TF_DIR" plan \
        -input=false \
        -var-file="$TF_VARS" \
        -var="deploy_function=true" \
        -var="deploy_web_app=false" \
        -out=function.tfplan
      ;;
    webapp)
      tf_init
      terraform -chdir="$TF_DIR" plan \
        -input=false \
        -var-file="$TF_VARS" \
        -var="deploy_function=true" \
        -var="deploy_web_app=true" \
        -out=webapp.tfplan
      ;;
    *)
      echo "Usage: ./infra/deploy.sh tfplan <foundation|function|webapp>" >&2
      exit 1
      ;;
  esac
}

tf_apply() {
  # Applies only a previously reviewed stage plan.
  local stage="${1:-}"
  case "$stage" in
    foundation)
      terraform -chdir="$TF_DIR" apply foundation.tfplan
      ;;
    function)
      terraform -chdir="$TF_DIR" apply function.tfplan
      ;;
    webapp)
      terraform -chdir="$TF_DIR" apply webapp.tfplan
      show_dashboard_access_details
      ;;
    *)
      echo "Usage: ./infra/deploy.sh tfapply <foundation|function|webapp>" >&2
      exit 1
      ;;
  esac
}

tf_destroy() {
  # Removes only replaceable Function resources and preserves protected data and any Web App.
  local stage="${1:-}"
  require_tf_vars
  if [[ "$stage" != "function" ]]; then
    echo "Only the replaceable Function stage can be destroyed by this helper." >&2
    echo "Protected history storage and its resource group are never destroy targets." >&2
    exit 1
  fi
  if [[ "${CONFIRM_TF_DESTROY_FUNCTION:-}" != "yes" ]]; then
    echo "Set CONFIRM_TF_DESTROY_FUNCTION=yes to remove only the Function stage." >&2
    exit 1
  fi

  tf_init
  terraform -chdir="$TF_DIR" plan \
    -input=false \
    -var-file="$TF_VARS" \
    -var="deploy_function=false" \
    -var="deploy_web_app=$(terraform -chdir="$TF_DIR" output -raw web_app_name 2>/dev/null | grep -qv '^null$' && echo true || echo false)" \
    -out=destroy-function.tfplan
  terraform -chdir="$TF_DIR" show destroy-function.tfplan
  terraform -chdir="$TF_DIR" apply destroy-function.tfplan
}

tf_deploy() {
  # Packages and publishes application code to the selected existing compute resource.
  local stage="${1:-}"
  require_tf_vars
  require_command az
  require_command zip

  local resource_group package
  resource_group="$(tf_output resource_group_name)"
  case "$stage" in
    function)
      require_command jq
      local function_app
      function_app="$(tf_output function_app_name 2>/dev/null || true)"
      package="$ROOT_DIR/function-source.zip"
      if [[ -z "$function_app" ]]; then
        echo "Function infrastructure is not present. Run tfplan function and tfapply function first." >&2
        exit 1
      fi

      rm -f "$package"
      (
        cd "$ROOT_DIR"
        zip -q -r "$package" function_app.py host.json requirements.txt pyproject.toml src config/sla-policies.json \
          -x '*/__pycache__/*' '*.pyc'
      )

      # AzureRM currently injects a legacy setting that overrides identity-based host storage.
      az functionapp config appsettings delete \
        --resource-group "$resource_group" \
        --name "$function_app" \
        --setting-names AzureWebJobsStorage \
        --output none
      az functionapp restart \
        --resource-group "$resource_group" \
        --name "$function_app"

      echo "Waiting 45 seconds for managed-identity storage settings and RBAC to propagate..."
      sleep 45

      az functionapp deployment source config-zip \
        --resource-group "$resource_group" \
        --name "$function_app" \
        --src "$package" \
        --build-remote true \
        --timeout 600 \
        --output none

      az rest \
        --method post \
        --url "https://management.azure.com/subscriptions/$(jq -r .subscription_id "$TF_VARS")/resourceGroups/$resource_group/providers/Microsoft.Web/sites/$function_app/syncfunctiontriggers?api-version=2024-04-01" \
        --output none
      ;;
    webapp)
      local web_app
      web_app="$(tf_output web_app_name 2>/dev/null || true)"
      package="$ROOT_DIR/webapp-source.zip"
      if [[ -z "$web_app" ]]; then
        echo "Web App infrastructure is not present. Run tfplan webapp and tfapply webapp first." >&2
        exit 1
      fi

      rm -f "$package"
      (
        cd "$ROOT_DIR"
        zip -q -r "$package" dashboard requirements.txt pyproject.toml src \
          -x '*/__pycache__/*' '*.pyc' 'dashboard/data/*'
      )

      az webapp deploy \
        --resource-group "$resource_group" \
        --name "$web_app" \
        --src-path "$package" \
        --type zip \
        --clean true \
        --restart true \
        --timeout 600 \
        --output none
      ;;
    *)
      echo "Usage: ./infra/deploy.sh tfdeploy <function|webapp>" >&2
      exit 1
      ;;
  esac
}

tf_verify() {
  # Reports the deployed stage identity, endpoint, and current data status.
  local stage="${1:-}"
  require_command az

  local function_app history_account resource_group
  history_account="$(tf_output history_storage_account_name)"
  resource_group="$(tf_output resource_group_name)"
  case "$stage" in
    foundation)
      az storage container list \
        --account-name "$history_account" \
        --auth-mode login \
        --query '[].name' \
        --output table
      ;;
    function)
      function_app="$(tf_output function_app_name)"
      az functionapp keys list \
        --resource-group "$resource_group" \
        --name "$function_app" \
        --query 'keys(@)' \
        --output table
      az functionapp function list \
        --resource-group "$resource_group" \
        --name "$function_app" \
        --query '[].{Name:name,Schedule:config.bindings[0].schedule}' \
        --output table
      (
        cd "$ROOT_DIR"
        STORAGE_ACCOUNT_NAME="$history_account" \
          STORAGE_CONTAINER_NAME="$(tf_output history_container_name)" \
          STORAGE_CURRENT_CONTAINER_NAME="$(tf_output current_container_name)" \
          .venv/bin/vulnerability-view status --azure
      )
      ;;
    webapp)
      local web_app web_url
      web_app="$(tf_output web_app_name)"
      web_url="$(tf_output dashboard_url)"
      az webapp show \
        --resource-group "$resource_group" \
        --name "$web_app" \
        --query '{Name:name,State:state,Host:defaultHostName,HttpsOnly:httpsOnly}' \
        --output table
      curl --silent --show-error --head --output /dev/null \
        --write-out 'Authentication redirect check: HTTP %{http_code} -> %{redirect_url}\n' \
        "$web_url/"
      show_dashboard_access_details
      ;;
    *)
      echo "Usage: ./infra/deploy.sh tfverify <foundation|function|webapp>" >&2
      exit 1
      ;;
  esac
}

tf_preflight() {
  # Checks source API access with the signed-in local Azure identity.
  (
    cd "$ROOT_DIR"
    .venv/bin/vulnerability-view preflight
  )
}

tf_invoke() {
  # Explicitly starts one live collector run after a destructive-write acknowledgement.
  local stage="${1:-}"
  if [[ "$stage" != "function" ]]; then
    echo "Usage: ./infra/deploy.sh tfinvoke function" >&2
    exit 1
  fi
  if [[ "${CONFIRM_LIVE_COLLECTION:-}" != "yes" ]]; then
    echo "Set CONFIRM_LIVE_COLLECTION=yes to acknowledge that this writes a new immutable live run." >&2
    exit 1
  fi

  local function_app host_key resource_group
  function_app="$(tf_output function_app_name)"
  resource_group="$(tf_output resource_group_name)"
  host_key="$(
    az functionapp keys list \
      --resource-group "$resource_group" \
      --name "$function_app" \
      --query masterKey \
      --output tsv
  )"
  curl --fail-with-body --silent --show-error \
    --request POST \
    --header "x-functions-key: $host_key" \
    --header "Content-Type: application/json" \
    --data '{"input":null}' \
    "https://$function_app.azurewebsites.net/admin/functions/dataprep_snapshot"
}

usage() {
  cat <<'EOF'
Usage: ./infra/deploy.sh <command>

  tfplan foundation    Plan the resource group and protected history storage.
  tfapply foundation   Apply the reviewed foundation.tfplan.
  tfverify foundation  Verify the signed-in deployer can list history containers.
  tfplan function      Plan the Function, identity, RBAC, API roles, and monitoring.
  tfapply function     Apply the reviewed function.tfplan.
  tfdeploy function    Build and publish the Python Function package.
  tfverify function    Check host readiness, trigger discovery, and stored data.
  tfplan webapp        Plan the cumulative Function and authenticated B1 Web App stage.
  tfapply webapp       Apply the reviewed webapp.tfplan.
  tfdeploy webapp      Build and publish the FastAPI dashboard package.
  tfverify webapp      Check the Web App and Easy Auth redirect.
  tfpreflight          Check Defender API access using the signed-in local identity.
  tfinvoke function    Run one live collection; requires CONFIRM_LIVE_COLLECTION=yes.
  tfdestroy function   Remove only the Function stage; requires
                       CONFIRM_TF_DESTROY_FUNCTION=yes.

The Web App plan creates dashboard_access_group_name unless an existing
dashboard_access_group_object_id is supplied in main.tfvars.json.
EOF
}

case "${1:-}" in
  tfplan) tf_plan "${2:-}" ;;
  tfapply) tf_apply "${2:-}" ;;
  tfdestroy) tf_destroy "${2:-}" ;;
  tfdeploy) tf_deploy "${2:-}" ;;
  tfverify) tf_verify "${2:-}" ;;
  tfpreflight) tf_preflight ;;
  tfinvoke) tf_invoke "${2:-}" ;;
  *) usage; exit 1 ;;
esac
