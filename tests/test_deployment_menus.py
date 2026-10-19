from pathlib import Path


SHELL_MENU = Path("infra/deployment-menu.sh")
POWERSHELL_MENU = Path("infra/deployment-menu.ps1")
SHELL_TEARDOWN = Path("infra/destroy-application.sh")
POWERSHELL_TEARDOWN = Path("infra/destroy-application.ps1")
SHELL_FULL_TEARDOWN = Path("infra/destroy-test-environment.sh")
POWERSHELL_FULL_TEARDOWN = Path("infra/destroy-test-environment.ps1")
SHELL_DEPLOY = Path("infra/deploy.sh")
SHELL_FUNCTION_LOGS = Path("infra/check-function-logs.sh")
SHELL_GITHUB_WORKFLOW = Path("infra/github-workflow-menu.sh")
POWERSHELL_GITHUB_WORKFLOW = Path("infra/github-workflow-menu.ps1")


def menu_sources() -> tuple[str, str]:
    return SHELL_MENU.read_text(encoding="utf-8"), POWERSHELL_MENU.read_text(encoding="utf-8")


def test_deployment_menus_expose_matching_options_and_confirmations():
    shell, powershell = menu_sources()
    options = (
        "1) Complete initial deployment or update: infrastructure, Function, and Web App",
        "2) Plan, review, and apply Web App infrastructure",
        "3) Deploy and verify Function code",
        "4) Deploy and verify Web App code",
        "5) Invoke a live collection and verify Function",
        "6) Verify Function and Web App",
        "7) Operations and diagnostics",
        "8) Show saved Web App plan",
        "9) Exit",
    )

    for option in options:
        assert option in shell
        assert option in powershell
    for confirmation in ("APPLY", "COLLECT"):
        assert confirmation in shell
        assert confirmation in powershell
    cumulative_message = "Planning the cumulative Web App stage: foundation, Function, and Web App infrastructure."
    assert cumulative_message in shell
    assert cumulative_message in powershell
    for identity_notice in (
        "commands run as the identity currently signed in to Azure CLI",
        "do not store the signed-in user's credentials",
        "Entra application/service principal and managed identities",
    ):
        assert identity_notice in shell
        assert identity_notice in powershell
    assert "\n  clear\n" in shell
    assert "Clear-Host" in powershell


def test_deployment_menus_wrap_the_same_operations():
    shell, powershell = menu_sources()
    equivalent_calls = (
        ("run_cli deployment-preflight", "Invoke-OperationsCli deployment-preflight"),
        ("run_cli configure-webapp-sku", "Invoke-OperationsCli configure-webapp-sku"),
        ("run_cli plan webapp", "Invoke-OperationsCli plan webapp"),
        ("run_cli show webapp", "Invoke-OperationsCli show webapp"),
        ("run_cli apply webapp", "Invoke-OperationsCli apply webapp"),
        ("deploy_verify function", "Invoke-DeployVerify -Stage function"),
        ("deploy_verify webapp", "Invoke-DeployVerify -Stage webapp"),
        ("args=(invoke function --confirm)", "Invoke-OperationsCli invoke function --confirm"),
        ('args+=(--full)', "Invoke-OperationsCli invoke function --confirm --full"),
        (
            "run_cli check-function-logs --hours 1 --limit 3 --status-only",
            "Invoke-OperationsCli check-function-logs --hours 1 --limit 3 --status-only",
        ),
        ("verify_all", "Invoke-VerifyAll"),
        ("run_cli check-runs --limit 5 --progress", "Invoke-OperationsCli check-runs --limit 5 --progress"),
        ("run_cli check-runs --limit 10", "Invoke-OperationsCli check-runs --limit 10"),
        (
            "run_cli check-function-logs --hours 24 --limit 10",
            "Invoke-OperationsCli check-function-logs --hours 24 --limit 10",
        ),
        (
            "run_cli check-function-logs --hours 72 --limit 25",
            "Invoke-OperationsCli check-function-logs --hours 72 --limit 25",
        ),
        (
            "run_cli export-function-logs --hours 24",
            "Invoke-OperationsCli export-function-logs --hours 24",
        ),
        (
            "run_cli check-function-logs --hours 168 --limit 25",
            "Invoke-OperationsCli check-function-logs --hours 168 --limit 25",
        ),
        (
            "run_cli export-function-logs --hours 168",
            "Invoke-OperationsCli export-function-logs --hours 168",
        ),
    )

    for shell_call, powershell_call in equivalent_calls:
        assert shell_call in shell
        assert powershell_call in powershell


def test_deployment_menus_expose_matching_operations_submenu():
    shell, powershell = menu_sources()
    options = (
        "Operations and diagnostics",
        "1) Show current collector activity",
        "2) Show active progress and latest 5 published runs",
        "3) Show latest 10 published runs",
        "4) Show detailed Function diagnostics for the last 24 hours",
        "5) Show extended Function diagnostics for the last 72 hours",
        "6) Pull sanitized collector logs for the last 24 hours",
        "7) Verify Function and Web App",
        "8) Force full vulnerability and relationship reconciliation",
        "9) Return to deployment menu",
        "10) Show Function execution, host, and deployment logs for the last 7 days",
        "11) Pull sanitized Function logs for the last 7 days",
    )

    for option in options:
        assert option in shell
        assert option in powershell


def test_deployment_menus_do_not_expose_destructive_operations():
    shell, powershell = menu_sources()

    assert " destroy " not in f" {shell.lower()} "
    assert " destroy " not in f" {powershell.lower()} "


def test_powershell_menu_preserves_python_executable_as_one_value():
    _, powershell = menu_sources()

    assert "[pscustomobject]@{ Executable = $py.Source; Prefix = @($version) }" in powershell
    assert "$executable = $PythonCommand.Executable" in powershell
    assert "$prefix = @($PythonCommand.Prefix)" in powershell
    assert "$PythonCommand[0]" not in powershell
    assert '$env:PYTHONPATH = if ($previousPythonPath)' in powershell
    assert '$sourcePath = Join-Path $RootDirectory "src"' in powershell


def test_deployment_menus_show_version_and_revision_in_title():
    shell, powershell = menu_sources()

    assert 'DEPLOYMENT_MENU_VERSION="2026.10.19.1"' in shell
    assert 'Vulnerability View deployment menu %s (revision %s)' in shell
    assert '$DeploymentMenuVersion = "2026.10.19.1"' in powershell
    assert "Vulnerability View deployment menu $DeploymentMenuVersion (revision $GitRevision)" in powershell
    assert 'PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"' in shell


def test_github_workflow_menus_offer_single_publish_and_promote_action():
    shell = SHELL_GITHUB_WORKFLOW.read_text(encoding="utf-8")
    powershell = POWERSHELL_GITHUB_WORKFLOW.read_text(encoding="utf-8")

    for source in (shell, powershell):
        assert "3) Test once, publish main, and promote latest" in source
        assert "4) Validate customer release readiness" in source
        assert "5) Exit" in source
        assert "publish-and-promote" in source
        assert "Type RELEASE" not in source


def test_powershell_menu_bootstraps_clean_windows_clone():
    _, powershell = menu_sources()

    assert 'foreach ($version in @("-3.14", "-3.12", "-3"))' in powershell
    assert "if (Test-PythonCommand -Command $command)" in powershell
    assert "sys.version_info >= (3, 12)" in powershell
    assert 'if ($isWindowsHost) { ".venv-win" } else { ".venv" }' in powershell
    assert 'if ($isWindowsHost) { "Scripts\\python.exe" } else { "bin/python" }' in powershell
    assert "-m venv $virtualEnvironment" in powershell
    assert '-m pip install --disable-pip-version-check -e "${RootDirectory}[dev]"' in powershell
    assert "importlib.util.find_spec('vulnerability_view.operations_cli')" in powershell
    assert "Vulnerability View is not importable" in powershell
    assert '$RequiredAzureCliExtensions = @("log-analytics")' in powershell
    assert "Get-Command az -ErrorAction SilentlyContinue" in powershell
    assert "extension show --name $extension --output none" in powershell
    assert "extension add --name $extension --allow-preview true --yes" in powershell
    assert "Azure CLI extension '$extension' is not available after installation." in powershell
    assert "Initialize-AzureCliExtensions" in powershell


def test_manual_collection_uses_flex_compatible_trigger_and_monitoring():
    deploy = SHELL_DEPLOY.read_text(encoding="utf-8")
    function_logs = SHELL_FUNCTION_LOGS.read_text(encoding="utf-8")

    assert "/admin/functions/dataprep_manual_snapshot" in deploy
    assert "/admin/functions/dataprep_snapshot" not in deploy
    for function_name in (
        "dataprep_snapshot",
        "dataprep_manual_snapshot",
        "dataprep_full_snapshot",
    ):
        assert function_name in function_logs


def test_deployment_operations_do_not_use_operator_storage_data_plane():
    operations = Path("src/vulnerability_view/operations_cli.py").read_text(encoding="utf-8")
    check_runs = SHELL_FUNCTION_LOGS.with_name("check-runs.sh").read_text(encoding="utf-8")
    deploy = SHELL_DEPLOY.read_text(encoding="utf-8")
    terraform = Path("infra/terraform/main.tf").read_text(encoding="utf-8")
    example_values = Path("infra/terraform/main.tfvars.example.json").read_text(encoding="utf-8")

    for source in (operations, check_runs, deploy):
        assert "--auth-mode\", \"login" not in source
        assert "--auth-mode login" not in source
        assert "az storage blob" not in source
    assert 'resource "azurerm_role_assignment" "history_blob_contributor_deployer"' not in terraform
    assert "principal_id       = data.azurerm_client_config.current.object_id" not in terraform
    assert '"grant_deployer_history_access": false' in example_values


def test_application_teardown_scripts_require_four_confirmations_and_preserve_history():
    shell = SHELL_TEARDOWN.read_text(encoding="utf-8")
    powershell = POWERSHELL_TEARDOWN.read_text(encoding="utf-8")

    for command in ("deployment-preflight", "teardown-plan", "teardown-show", "teardown-apply"):
        assert f"run_cli {command}" in shell
        assert f"Invoke-OperationsCli {command}" in powershell
    for confirmation in (
        "REVIEWED PLAN",
        "REMOVE REPLACEABLE APPLICATION",
        "Confirmation 1 of 4",
        "Confirmation 2 of 4",
        "Confirmation 3 of 4",
        "Confirmation 4 of 4",
    ):
        assert confirmation in shell
        assert confirmation in powershell
    for retained in (
        "Protected history account",
        "History container",
        "Current-pointer container",
        "Protected workflow container",
        "local Terraform state",
    ):
        assert retained in shell
        assert retained in powershell
    for forbidden in ("az group delete", "terraform destroy", "-destroy"):
        assert forbidden not in shell.lower()
        assert forbidden not in powershell.lower()


def test_full_test_teardown_scripts_require_four_confirmations_and_delete_exact_group():
    shell = SHELL_FULL_TEARDOWN.read_text(encoding="utf-8")
    powershell = POWERSHELL_FULL_TEARDOWN.read_text(encoding="utf-8")

    for command in (
        "deployment-preflight",
        "teardown-plan --allow-empty",
        "teardown-show --allow-empty",
        "teardown-apply --allow-empty",
    ):
        assert f"run_cli {command}" in shell
        assert f"Invoke-OperationsCli {command}" in powershell
    for confirmation in (
        "DELETE TEST ENVIRONMENT",
        "PERMANENTLY DELETE",
        "Confirmation 1 of 4",
        "Confirmation 2 of 4",
        "Confirmation 3 of 4",
        "Confirmation 4 of 4",
    ):
        assert confirmation in shell
        assert confirmation in powershell
    assert 'az group delete --subscription "$subscription_id" --name "$resource_group" --yes' in shell
    assert "az group delete --subscription $SubscriptionId --name $ResourceGroup --yes" in powershell
    assert "az group exists" in shell
    assert "az group exists" in powershell
    assert "terraform destroy" not in shell.lower()
    assert "terraform destroy" not in powershell.lower()
