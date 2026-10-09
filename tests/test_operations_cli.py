"""Last modified: 2026-10-08.
Purpose: Verify cross-platform operations parsing, versioning, packaging, and safety behavior.
"""

import json
import subprocess
from datetime import datetime
from pathlib import Path
from zipfile import ZipFile

from vulnerability_view import operations_cli


def test_local_timestamp_uses_machine_time_zone():
    value = "2026-10-09T18:00:00Z"

    assert operations_cli._local_timestamp(value) == (
        datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    )


def test_parser_exposes_identical_cross_platform_commands():
    assert operations_cli.build_parser().parse_args(["deploy", "function"]).stage == "function"
    assert operations_cli.build_parser().parse_args(["show", "foundation"]).stage == "foundation"
    assert operations_cli.build_parser().parse_args(["output", "function_app_name"]).name == "function_app_name"
    assert operations_cli.build_parser().parse_args(["check-runs", "--limit", "5", "--progress"]).progress is True
    assert operations_cli.build_parser().parse_args(["invoke", "function", "--confirm"]).confirm is True


def test_log_query_has_bounded_timeout(monkeypatch):
    captured: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def fake_az(*args, **kwargs):
        captured.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout="[]")

    monkeypatch.setattr(operations_cli, "_az", fake_az)

    assert operations_cli._log_query("workspace-id", "subscription-id", "AppTraces | take 1") == []
    assert captured[0] == (
        ("extension", "show", "--name", "log-analytics", "--output", "none"),
        {"check": False, "capture": True},
    )
    assert captured[1][1] == {"capture": True, "timeout": 90}


def test_log_query_reports_missing_extension(monkeypatch):
    monkeypatch.setattr(
        operations_cli,
        "_az",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 1, stdout=""),
    )

    try:
        operations_cli._log_query("workspace-id", "subscription-id", "AppTraces | take 1")
    except RuntimeError as error:
        assert "az extension add --name log-analytics --allow-preview true --yes" in str(error)
    else:
        raise AssertionError("missing log-analytics extension should fail explicitly")


def test_function_status_distinguishes_failed_execution_from_success(monkeypatch, capsys):
    monkeypatch.setattr(
        operations_cli,
        "_workspace_context",
        lambda: ({"function_app_name": "func-test", "subscription_id": "sub-test"}, "workspace-test"),
    )
    monkeypatch.setattr(
        operations_cli,
        "_log_query",
        lambda *args: [{
            "InvocationId": "failed-invocation",
            "StartedUtc": "2026-10-09T18:09:57Z",
            "CompletedUtc": "2026-10-09T18:09:58Z",
            "CompletionStatus": "Failed",
        }],
    )

    assert operations_cli.check_function_logs(1, 3, True) == "FAILED"
    output = capsys.readouterr().out
    assert "FAILED - no durable run was published" in output
    assert "Completed local:" in output


def test_require_prefers_repository_local_terraform_exe(monkeypatch, tmp_path: Path):
    terraform = tmp_path / "terraform.exe"
    terraform.write_bytes(b"local terraform")
    monkeypatch.setattr(operations_cli, "ROOT", tmp_path)
    monkeypatch.setattr(
        operations_cli.shutil,
        "which",
        lambda command: (_ for _ in ()).throw(AssertionError(f"PATH lookup should not run for {command}")),
    )

    assert operations_cli._require("terraform") == str(terraform)


def test_function_version_prefers_override_then_values(monkeypatch):
    monkeypatch.setenv("FUNCTION_VERSION", "release/one")
    assert operations_cli._function_version({"function_version": "values-version"}) == "release-one"
    monkeypatch.delenv("FUNCTION_VERSION")
    assert operations_cli._function_version({"function_version": "2026.10.08.1"}) == "2026.10.08.1"


def test_zip_tree_excludes_generated_dashboard_data(monkeypatch, tmp_path: Path):
    root = tmp_path / "repo"
    dashboard = root / "dashboard"
    dashboard.mkdir(parents=True)
    (dashboard / "index.html").write_text("dashboard")
    (dashboard / "data").mkdir()
    (dashboard / "data/current.json").write_text(json.dumps({"secret": "not-packaged"}))
    destination = root / "webapp.zip"
    monkeypatch.setattr(operations_cli, "ROOT", root)

    operations_cli._zip_tree(destination, [dashboard], {"dashboard/data"})

    with ZipFile(destination) as archive:
        assert archive.namelist() == ["dashboard/index.html"]


def test_web_package_stamps_version_revision_and_cache_keys(tmp_path: Path):
    package = tmp_path / "webapp.zip"
    with ZipFile(package, "w") as archive:
        archive.writestr("dashboard/config.js", 'version: "old", revision: "old"')
        archive.writestr(
            "dashboard/index.html",
            '<link href="styles.css?v=old"><script src="config.js?v=old"></script><script src="app.js?v=old"></script>',
        )

    operations_cli._stamp_web_package(package, "2026.10.08.2", "2026-10-08T15:00:00Z")

    with ZipFile(package) as archive:
        configuration = archive.read("dashboard/config.js").decode()
        html = archive.read("dashboard/index.html").decode()
    assert 'version: "2026.10.08.2"' in configuration
    assert 'revision: "2026-10-08T15:00:00Z"' in configuration
    assert html.count("?v=20261008150000") == 3


def test_webapp_deployment_restarts_only_after_kudu_completes(monkeypatch, tmp_path: Path):
    calls: list[tuple[object, ...]] = []

    def fake_az(*args, **kwargs):
        calls.append(args)
        stdout = "previous-deployment\n" if args[:4] == ("webapp", "log", "deployment", "list") else ""
        return subprocess.CompletedProcess(args, 0, stdout=stdout)

    monkeypatch.setattr(operations_cli, "ROOT", tmp_path)
    monkeypatch.setattr(operations_cli, "_values", lambda: {"dashboard_version": "2026.10.09.3"})
    monkeypatch.setattr(
        operations_cli,
        "_tf_output",
        lambda name: {"resource_group_name": "rg-test", "web_app_name": "app-test"}[name],
    )
    monkeypatch.setattr(operations_cli, "_zip_tree", lambda *args, **kwargs: None)
    monkeypatch.setattr(operations_cli, "_stamp_web_package", lambda *args, **kwargs: None)
    monkeypatch.setattr(operations_cli, "_az", fake_az)

    operations_cli.deploy_webapp()

    deploy_index = next(index for index, call in enumerate(calls) if call[:2] == ("webapp", "deploy"))
    settings_index = next(
        index for index, call in enumerate(calls)
        if call[:4] == ("webapp", "config", "appsettings", "set")
    )
    start_index = next(index for index, call in enumerate(calls) if call[:2] == ("webapp", "start"))
    assert calls[deploy_index][calls[deploy_index].index("--restart") + 1] == "false"
    assert deploy_index < settings_index < start_index


def test_web_app_uses_configurable_worker_processes():
    terraform = Path("infra/terraform/main.tf").read_text()
    variables = Path("infra/terraform/variables.tf").read_text()
    example = json.loads(Path("infra/terraform/main.tfvars.example.json").read_text())

    assert "--workers ${var.web_app_worker_processes}" in terraform
    assert 'variable "web_app_worker_processes"' in variables
    assert example["web_app_worker_processes"] == 1


def test_webapp_apply_reconciles_function_storage_before_access(monkeypatch, tmp_path: Path):
    calls: list[str] = []
    plan = tmp_path / "webapp.tfplan"
    plan.write_text("reviewed")
    monkeypatch.setattr(operations_cli, "TF_DIR", tmp_path)
    monkeypatch.setattr(operations_cli, "_tf", lambda *args: calls.append("apply"))
    monkeypatch.setattr(
        operations_cli,
        "_reconcile_function_runtime_storage_auth",
        lambda: calls.append("storage"),
    )
    monkeypatch.setattr(operations_cli, "_dashboard_access", lambda: calls.append("access"))

    operations_cli.apply("webapp")

    assert calls == ["apply", "storage", "access"]


def test_function_storage_reconciliation_removes_legacy_setting(monkeypatch):
    settings = [
        {"name": "AzureWebJobsStorage", "value": "AccountKey="},
        {"name": "AzureWebJobsStorage__accountName", "value": "runtime"},
        {"name": "AzureWebJobsStorage__clientId", "value": "client"},
        {"name": "AzureWebJobsStorage__credential", "value": "managedidentity"},
    ]
    az_calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        operations_cli,
        "_tf_output",
        lambda name: {"resource_group_name": "rg-test", "function_app_name": "func-test"}[name],
    )
    monkeypatch.setattr(operations_cli, "_az_json", lambda *args: settings)

    def fake_az(*args, **kwargs):
        az_calls.append(args)
        if "delete" in args:
            settings.pop(0)
        return subprocess.CompletedProcess(args, 0, stdout="")

    monkeypatch.setattr(operations_cli, "_az", fake_az)
    monkeypatch.setattr(operations_cli.time, "sleep", lambda seconds: None)

    operations_cli._reconcile_function_runtime_storage_auth()

    assert any("delete" in call for call in az_calls)
    assert any("restart" in call for call in az_calls)


def test_shell_apply_reconciles_function_storage_authentication():
    deployment = Path("infra/deploy.sh").read_text()

    assert "reconcile_function_runtime_storage_auth" in deployment
    assert 'if [[ "$stage" == "function" || "$stage" == "webapp" ]]' in deployment
    assert "--setting-names AzureWebJobsStorage" in deployment
    assert "validate_function_runtime_storage_auth" in deployment


def test_invoke_requires_platform_neutral_confirmation(monkeypatch):
    monkeypatch.delenv("CONFIRM_LIVE_COLLECTION", raising=False)

    try:
        operations_cli.invoke()
    except RuntimeError as error:
        assert "--confirm" in str(error)
    else:
        raise AssertionError("invoke should require explicit confirmation")


def test_invoke_distinguishes_trigger_acceptance_from_collection_success(monkeypatch, capsys):
    class AcceptedResponse:
        status_code = 202

        @staticmethod
        def raise_for_status():
            return None

    monkeypatch.setattr(
        operations_cli,
        "_tf_output",
        lambda name: {"resource_group_name": "rg-test", "function_app_name": "func-test"}[name],
    )
    monkeypatch.setattr(
        operations_cli,
        "_az",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout="host-key\n"),
    )
    monkeypatch.setattr(operations_cli.requests, "post", lambda *args, **kwargs: AcceptedResponse())

    operations_cli.invoke(True)

    output = capsys.readouterr().out
    assert "trigger accepted" in output
    assert "does not confirm collection success" in output
    assert "check-runs --limit 10 --progress" in output


def test_verify_function_allows_greenfield_before_first_run(monkeypatch, capsys):
    outputs = {
        "resource_group_name": "rg-test",
        "function_app_name": "func-test",
        "history_storage_account_name": "historytest",
        "history_container_name": "dvm-history",
        "current_container_name": "dvm-current",
    }
    monkeypatch.setattr(operations_cli, "_tf_output", lambda name: outputs[name])
    monkeypatch.setattr(
        operations_cli,
        "_az",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout="2026.10.08.1\n"),
    )
    monkeypatch.setattr(
        operations_cli,
        "_az_json",
        lambda *args: [
            {"name": "AzureWebJobsStorage__accountName", "value": "runtime"},
            {"name": "AzureWebJobsStorage__clientId", "value": "client"},
            {"name": "AzureWebJobsStorage__credential", "value": "managedidentity"},
        ] if args[:4] == ("functionapp", "config", "appsettings", "list") else {"exists": False},
    )
    monkeypatch.setattr(
        operations_cli,
        "_run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("status should not run without a manifest")),
    )

    operations_cli.verify("function")

    assert "No current manifest is published yet" in capsys.readouterr().out
