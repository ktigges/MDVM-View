from pathlib import Path


SHELL_MENU = Path("infra/deployment-menu.sh")
POWERSHELL_MENU = Path("infra/deployment-menu.ps1")


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
        "6) Verify Function and Web App",
        "7) Force full vulnerability and relationship reconciliation",
        "8) Return to deployment menu",
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
