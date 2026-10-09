#!/usr/bin/env bash
# Author: Kevin Tigges
# Last modified: 2026-10-08
# Purpose: Plan, version, deploy, verify, and invoke the protected Azure collector and dashboard stages.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="$ROOT_DIR/infra/terraform"
TF_VARS="$TF_DIR/main.tfvars.json"

require_tf_vars() {
  # Stops deployment commands when the ignored environment values file is absent.
  if [[ ! -f "$TF_VARS" ]]; then
    echo "Terraform values are missing: $TF_VARS" >&2
    echo "Copy main.tfvars.example.json to main.tfvars.json and replace every environment value." >&2
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
  # Prints the Enterprise Application used for manual user and group assignment.
  cat <<EOF
Enterprise Application: $(tf_output dashboard_enterprise_application_name)
Application (client) ID: $(tf_output dashboard_entra_client_id)
Enterprise Application object ID: $(tf_output dashboard_enterprise_application_object_id)
Assignment location: Microsoft Entra admin center > Enterprise applications > $(tf_output dashboard_enterprise_application_name) > Users and groups
Required role: Dashboard Viewer
Optional roles: Data Evidence Reader, Recommendation Tracker
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

validate_function_runtime_storage_auth() {
  local resource_group function_app settings legacy account client credential
  require_command az
  require_command jq
  resource_group="$(tf_output resource_group_name)"
  function_app="$(tf_output function_app_name)"
  settings="$(
    az functionapp config appsettings list \
      --resource-group "$resource_group" \
      --name "$function_app" \
      --output json
  )"
  legacy="$(jq -r '.[] | select(.name == "AzureWebJobsStorage") | .name' <<<"$settings")"
  account="$(jq -r '.[] | select(.name == "AzureWebJobsStorage__accountName") | .value' <<<"$settings")"
  client="$(jq -r '.[] | select(.name == "AzureWebJobsStorage__clientId") | .value' <<<"$settings")"
  credential="$(jq -r '.[] | select(.name == "AzureWebJobsStorage__credential") | .value' <<<"$settings")"
  if [[ -n "$legacy" ]]; then
    echo "Legacy AzureWebJobsStorage overrides managed-identity runtime storage." >&2
    return 1
  fi
  if [[ -z "$account" || -z "$client" || "$credential" != "managedidentity" ]]; then
    echo "Function runtime storage managed-identity settings are incomplete." >&2
    return 1
  fi
}

reconcile_function_runtime_storage_auth() {
  local resource_group function_app legacy
  require_command az
  resource_group="$(tf_output resource_group_name)"
  function_app="$(tf_output function_app_name)"
  legacy="$(
    az functionapp config appsettings list \
      --resource-group "$resource_group" \
      --name "$function_app" \
      --query "[?name=='AzureWebJobsStorage'].name | [0]" \
      --output tsv
  )"
  if [[ -n "$legacy" ]]; then
    echo "Removing legacy AzureWebJobsStorage setting injected during infrastructure apply..."
    az functionapp config appsettings delete \
      --resource-group "$resource_group" \
      --name "$function_app" \
      --setting-names AzureWebJobsStorage \
      --output none
    az functionapp restart \
      --resource-group "$resource_group" \
      --name "$function_app" \
      --output none
    echo "Waiting 45 seconds for managed-identity runtime storage to become ready..."
    sleep 45
  fi
  validate_function_runtime_storage_auth
}

tf_apply() {
  # Applies only a previously reviewed stage plan.
  local stage="${1:-}"
  local plan_file
  case "$stage" in
    foundation)
      plan_file="foundation.tfplan"
      ;;
    function)
      plan_file="function.tfplan"
      ;;
    webapp)
      plan_file="webapp.tfplan"
      ;;
    *)
      echo "Usage: ./infra/deploy.sh tfapply <foundation|function|webapp>" >&2
      exit 1
      ;;
  esac

  require_command terraform
  if [[ ! -f "$TF_DIR/$plan_file" ]]; then
    echo "Reviewed Terraform plan not found: $TF_DIR/$plan_file" >&2
    echo "Run './infra/deploy.sh tfplan $stage', review the saved plan, then run tfapply." >&2
    exit 1
  fi

  terraform -chdir="$TF_DIR" apply "$plan_file"
  if [[ "$stage" == "function" || "$stage" == "webapp" ]]; then
    reconcile_function_runtime_storage_auth
  fi
  if [[ "$stage" == "webapp" ]]; then
    show_dashboard_access_details
  fi
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
      require_command git
      local configured_function_version function_app function_version version_file
      function_app="$(tf_output function_app_name 2>/dev/null || true)"
      configured_function_version="$(jq -r '.function_version // empty' "$TF_VARS")"
      function_version="${FUNCTION_VERSION:-${configured_function_version:-$(git -C "$ROOT_DIR" describe --tags --always --dirty)}}"
      function_version="${function_version//[^A-Za-z0-9._+-]/-}"
      version_file="$ROOT_DIR/build-version.json"
      package="$ROOT_DIR/function-source.zip"
      if [[ -z "$function_app" ]]; then
        echo "Function infrastructure is not present. Run tfplan function and tfapply function first." >&2
        exit 1
      fi

      rm -f "$package" "$version_file"
      jq -n \
        --arg version "$function_version" \
        --arg deployedUtc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg commit "$(git -C "$ROOT_DIR" rev-parse HEAD)" \
        '{version:$version,deployedUtc:$deployedUtc,commit:$commit}' > "$version_file"
      (
        cd "$ROOT_DIR"
        zip -q -r "$package" function_app.py host.json requirements.txt pyproject.toml build-version.json src config/sla-policies.json \
          -x '*/__pycache__/*' '*.pyc'
      )
      rm -f "$version_file"

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

      az functionapp config appsettings set \
        --resource-group "$resource_group" \
        --name "$function_app" \
        --settings "COLLECTOR_VERSION=$function_version" \
        --output none

      az rest \
        --method post \
        --url "https://management.azure.com/subscriptions/$(jq -r .subscription_id "$TF_VARS")/resourceGroups/$resource_group/providers/Microsoft.Web/sites/$function_app/syncfunctiontriggers?api-version=2024-04-01" \
        --output none
      echo "Function collector version deployed: $function_version"
      ;;
    webapp)
      local dashboard_version web_app
      web_app="$(tf_output web_app_name 2>/dev/null || true)"
      dashboard_version="${DASHBOARD_VERSION:-$(jq -r '.dashboard_version // "unversioned"' "$TF_VARS")}"
      dashboard_version="${dashboard_version//[^A-Za-z0-9._+-]/-}"
      package="$ROOT_DIR/webapp-source.zip"
      if [[ -z "$web_app" ]]; then
        echo "Web App infrastructure is not present. Run tfplan webapp and tfapply webapp first." >&2
        exit 1
      fi

      rm -f "$package"
      (
        cd "$ROOT_DIR"
        zip -q -r "$package" dashboard requirements.txt pyproject.toml src \
          -x '*/__pycache__/*' '*.pyc' 'dashboard/data/*' 'dashboard/calculator.html' 'dashboard/tools/*'
      )

      require_command python3
      local asset_version revised_package ui_revision
      ui_revision="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
      asset_version="${ui_revision//[-:TZ]/}"
      revised_package="$package.revised"
      python3 - "$package" "$revised_package" "$dashboard_version" "$ui_revision" "$asset_version" <<'PY'
import re
import sys
import zipfile

source_path, destination_path, version, revision, asset_version = sys.argv[1:]
with zipfile.ZipFile(source_path, "r") as source, zipfile.ZipFile(destination_path, "w") as destination:
    for entry in source.infolist():
        content = source.read(entry.filename)
        if entry.filename == "dashboard/config.js":
            text = content.decode("utf-8")
            text, version_replacements = re.subn(
                r'version: "[^"]+"',
                f'version: "{version}"',
                text,
                count=1,
            )
            text, revision_replacements = re.subn(
                r'revision: "[^"]+"',
                f'revision: "{revision}"',
                text,
                count=1,
            )
            if version_replacements != 1 or revision_replacements != 1:
                raise RuntimeError("Could not stamp dashboard/config.js with the deployment version and revision")
            content = text.encode("utf-8")
        elif entry.filename == "dashboard/index.html":
            text = content.decode("utf-8")
            text, replacements = re.subn(
                r'((?:styles\.css|config\.js|app\.js)\?v=)[^"]+',
                rf"\g<1>{asset_version}",
                text,
            )
            if replacements != 3:
                raise RuntimeError("Could not stamp all dashboard asset versions")
            content = text.encode("utf-8")
        destination.writestr(entry, content)
PY
      mv "$revised_package" "$package"
      echo "Packaged dashboard version $dashboard_version, UI revision $ui_revision"

      local previous_deployment_id deploy_exit latest_deployment deployment_id deployment_status
      previous_deployment_id="$(
        az webapp log deployment list \
          --resource-group "$resource_group" \
          --name "$web_app" \
          --query 'sort_by(@,&start_time)[-1].id' \
          --output tsv 2>/dev/null || true
      )"
      set +e
      az webapp deploy \
        --resource-group "$resource_group" \
        --name "$web_app" \
        --src-path "$package" \
        --type zip \
        --clean true \
        --restart false \
        --track-status false \
        --timeout 600 \
        --output none
      deploy_exit=$?
      set -e

      if (( deploy_exit != 0 )); then
        echo "The deployment request returned an error. Checking Kudu for the final asynchronous result..."
        for _ in {1..40}; do
          latest_deployment="$(
            az webapp log deployment list \
              --resource-group "$resource_group" \
              --name "$web_app" \
              --query 'sort_by(@,&start_time)[-1].[id,status]' \
              --output tsv 2>/dev/null || true
          )"
          read -r deployment_id deployment_status <<<"$latest_deployment"
          if [[ -n "$deployment_id" && "$deployment_id" != "$previous_deployment_id" ]]; then
            if [[ "$deployment_status" == "4" ]]; then
              echo "Kudu completed deployment $deployment_id successfully after the client error."
              deploy_exit=0
              break
            fi
            if [[ "$deployment_status" == "3" ]]; then
              echo "Kudu confirmed deployment $deployment_id failed." >&2
              break
            fi
          fi
          sleep 15
        done
        if (( deploy_exit != 0 )); then
          echo "Kudu did not report a successful replacement deployment." >&2
          echo "Run: az webapp log deployment show -n $web_app -g $resource_group" >&2
          return "$deploy_exit"
        fi
      fi
      az webapp config appsettings set \
        --resource-group "$resource_group" \
        --name "$web_app" \
        --settings "DASHBOARD_VERSION=$dashboard_version" \
        --output none
      az webapp start \
        --resource-group "$resource_group" \
        --name "$web_app" \
        --output none
      echo "Dashboard version deployed: $dashboard_version"
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
  if [[ "$stage" == "function" || "$stage" == "webapp" ]]; then
    validate_function_runtime_storage_auth
  fi
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
      local collector_version
      collector_version="$(az functionapp config appsettings list \
        --resource-group "$resource_group" \
        --name "$function_app" \
        --query "[?name=='COLLECTOR_VERSION'].value | [0]" \
        --output tsv)"
      echo "Function collector version: ${collector_version:-not stamped}"
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
      local dashboard_version
      dashboard_version="$(az webapp config appsettings list \
        --resource-group "$resource_group" \
        --name "$web_app" \
        --query "[?name=='DASHBOARD_VERSION'].value | [0]" \
        --output tsv)"
      echo "Dashboard version: ${dashboard_version:-not stamped}"
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
  # Explicitly starts one live collector run after an immutable-publication acknowledgement.
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
  echo
  echo "Function trigger accepted. This does not confirm collection success."
  echo "Verify execution and immutable publication with: ./infra/check-runs.sh 10 --progress"
}

usage() {
  cat <<'EOF'
Usage: ./infra/deploy.sh <command>

Terraform workflow:
  - Do not run terraform init manually before tfplan.
  - tfplan runs terraform init and terraform validate automatically, then
    writes a saved <stage>.tfplan file. It does not apply infrastructure.
  - Review the saved plan with:
      terraform -chdir=infra/terraform show <stage>.tfplan
  - tfapply applies only that existing saved plan. It does not create or
    refresh the plan automatically.
  - tfdeploy publishes application code to infrastructure that already exists.
    It does not run terraform init, plan, or apply.
  - Function deployments stamp COLLECTOR_VERSION. The normal value comes from
    function_version in main.tfvars.json. FUNCTION_VERSION can override it once;
    otherwise deploy.sh falls back to the Git tag/commit and dirty-worktree marker.

For an existing Web App infrastructure change, run in this order:
  ./infra/deploy.sh tfplan webapp
  terraform -chdir=infra/terraform show webapp.tfplan
  ./infra/deploy.sh tfapply webapp
  ./infra/deploy.sh tfdeploy webapp
  ./infra/deploy.sh tfverify webapp

For a dashboard code-only change, run only:
  ./infra/deploy.sh tfdeploy webapp
  ./infra/deploy.sh tfverify webapp

For the first deployment after cloning the repository:
  1. Create and complete infra/terraform/main.tfvars.json.
  2. Run tfplan foundation first. It performs terraform init automatically.
  3. Review foundation.tfplan, then run tfapply and tfverify foundation.
  4. Repeat plan, review, apply, deploy, and verify for function.
  5. Repeat plan, review, apply, deploy, and verify for webapp.

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

The Web App plan creates an assignment-required Enterprise Application but
does not create groups or assign users. Assign authorized users or groups in
Microsoft Entra after apply.
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
