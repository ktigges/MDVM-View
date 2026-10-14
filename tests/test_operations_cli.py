"""Last modified: 2026-10-08.
Purpose: Verify cross-platform operations parsing, versioning, packaging, and safety behavior.
"""

import json
import subprocess
from datetime import datetime
from pathlib import Path
from zipfile import ZipFile

import pytest

from vulnerability_view import operations_cli


def test_values_missing_file_explains_initial_configuration(monkeypatch, tmp_path):
    missing = tmp_path / "main.tfvars.json"
    monkeypatch.setattr(operations_cli, "TF_DIR", tmp_path)
    monkeypatch.setattr(operations_cli, "TF_VARS", missing)

    with pytest.raises(RuntimeError) as error:
        operations_cli._values()

    message = str(error.value)
    assert str(missing) in message
    assert "main.tfvars.example.json" in message
    assert "replace every example value" in message


def test_local_timestamp_uses_machine_time_zone():
    value = "2026-10-09T18:00:00Z"

    assert operations_cli._local_timestamp(value) == (
        datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    )


def test_parser_exposes_identical_cross_platform_commands():
    assert operations_cli.build_parser().parse_args(["deploy", "function"]).stage == "function"
    assert operations_cli.build_parser().parse_args(["show", "foundation"]).stage == "foundation"
    assert operations_cli.build_parser().parse_args(["output", "function_app_name"]).name == "function_app_name"
    assert operations_cli.build_parser().parse_args(["configure-webapp-sku"]).command == "configure-webapp-sku"
    assert operations_cli.build_parser().parse_args(["check-runs", "--limit", "5", "--progress"]).progress is True
    assert operations_cli.build_parser().parse_args(["invoke", "function", "--confirm"]).confirm is True
    assert operations_cli.build_parser().parse_args(["invoke", "function", "--confirm", "--full"]).full is True


def test_configure_webapp_sku_keeps_configured_sku_with_quota(monkeypatch):
    values = {
        "subscription_id": "subscription-test",
        "resource_group_name": "rg-test",
        "web_app_service_plan_name": "plan-test",
        "web_app_sku_name": "B2",
        "location": "eastus2",
    }
    responses = iter([
        [],
        {"value": [{"name": {"value": "B2"}, "currentValue": 0, "limit": 1}]},
    ])
    monkeypatch.setattr(operations_cli, "_values", lambda: values)
    monkeypatch.setattr(operations_cli, "_azure_json", lambda *args: next(responses))
    monkeypatch.setattr("builtins.input", lambda *args: (_ for _ in ()).throw(AssertionError("unexpected prompt")))

    operations_cli.configure_webapp_sku()

    assert values["web_app_sku_name"] == "B2"


def test_configure_webapp_sku_requires_explicit_available_fallback(monkeypatch, tmp_path):
    values_file = tmp_path / "main.tfvars.json"
    values = {
        "subscription_id": "subscription-test",
        "resource_group_name": "rg-test",
        "web_app_service_plan_name": "plan-test",
        "web_app_sku_name": "B2",
        "location": "eastus2",
    }
    values_file.write_text(json.dumps(values), encoding="utf-8")
    responses = iter([
        [],
        {
            "value": [
                {"name": {"value": "B1"}, "currentValue": 0, "limit": 0},
                {"name": {"value": "B2"}, "currentValue": 0, "limit": 0},
                {"name": {"value": "P0v3"}, "currentValue": 0, "limit": 2},
            ],
        },
    ])
    answers = iter(["1", "eastus2/P0v3"])
    monkeypatch.setattr(operations_cli, "TF_VARS", values_file)
    monkeypatch.setattr(operations_cli, "_values", lambda: dict(values))
    monkeypatch.setattr(operations_cli, "_azure_json", lambda *args: next(responses))
    monkeypatch.setattr("builtins.input", lambda *args: next(answers))

    operations_cli.configure_webapp_sku()

    updated = json.loads(values_file.read_text(encoding="utf-8"))
    assert updated["web_app_location"] == "eastus2"
    assert updated["web_app_sku_name"] == "P0v3"


def test_configure_webapp_sku_preserves_existing_plan_without_spare_quota(monkeypatch):
    values = {
        "subscription_id": "subscription-test",
        "resource_group_name": "rg-test",
        "web_app_service_plan_name": "plan-test",
        "web_app_sku_name": "B2",
        "location": "eastus2",
    }
    monkeypatch.setattr(operations_cli, "_values", lambda: values)
    monkeypatch.setattr(
        operations_cli,
        "_azure_json",
        lambda *args: [{"name": "plan-test", "resourceGroup": "rg-test", "sku": {"name": "B2"}}],
    )
    monkeypatch.setattr("builtins.input", lambda *args: (_ for _ in ()).throw(AssertionError("unexpected prompt")))

    operations_cli.configure_webapp_sku()


def test_configure_webapp_sku_reports_all_supported_zero_quotas(monkeypatch, capsys):
    values = {
        "subscription_id": "subscription-test",
        "resource_group_name": "rg-test",
        "web_app_service_plan_name": "plan-test",
        "web_app_sku_name": "B2",
        "location": "eastus2",
    }
    responses = iter([
        [],
        {
            "value": [
                {"name": {"value": sku}, "currentValue": 0, "limit": 0}
                for sku in operations_cli.SUPPORTED_WEB_APP_SKUS
            ],
        },
    ])
    monkeypatch.setattr(operations_cli, "_values", lambda: values)
    monkeypatch.setattr(operations_cli, "_azure_json", lambda *args: next(responses))
    monkeypatch.setattr("builtins.input", lambda *args: "")

    with pytest.raises(RuntimeError, match="No supported App Service SKU"):
        operations_cli.configure_webapp_sku()

    output = capsys.readouterr().out
    for sku in operations_cli.SUPPORTED_WEB_APP_SKUS:
        assert f"  {sku}" in output
    assert output.count("available=0") == len(operations_cli.SUPPORTED_WEB_APP_SKUS)


def test_configure_webapp_sku_can_select_premium_v4_in_another_region(monkeypatch, tmp_path):
    values_file = tmp_path / "main.tfvars.json"
    values = {
        "subscription_id": "subscription-test",
        "resource_group_name": "rg-test",
        "web_app_service_plan_name": "plan-test",
        "web_app_sku_name": "B2",
        "location": "eastus2",
    }
    values_file.write_text(json.dumps(values), encoding="utf-8")
    responses = iter([
        [],
        {"value": [{"name": {"value": "B2"}, "currentValue": 0, "limit": 0}]},
        {"value": [{"name": {"value": "P0v4"}, "currentValue": 0, "limit": 30}]},
    ])
    answers = iter(["East US", "1", "eastus/P0v4"])
    monkeypatch.setattr(operations_cli, "TF_VARS", values_file)
    monkeypatch.setattr(operations_cli, "_values", lambda: dict(values))
    monkeypatch.setattr(operations_cli, "_azure_json", lambda *args: next(responses))
    monkeypatch.setattr("builtins.input", lambda *args: next(answers))

    operations_cli.configure_webapp_sku()

    updated = json.loads(values_file.read_text(encoding="utf-8"))
    assert updated["web_app_location"] == "eastus"
    assert updated["web_app_sku_name"] == "P0v4"


def test_configure_webapp_sku_preserves_existing_plan_configuration(monkeypatch, tmp_path):
    values_file = tmp_path / "main.tfvars.json"
    values = {
        "subscription_id": "subscription-test",
        "resource_group_name": "rg-test",
        "web_app_service_plan_name": "plan-test",
        "web_app_sku_name": "B2",
        "location": "eastus2",
    }
    values_file.write_text(json.dumps(values), encoding="utf-8")
    monkeypatch.setattr(operations_cli, "TF_VARS", values_file)
    monkeypatch.setattr(operations_cli, "_values", lambda: dict(values))
    monkeypatch.setattr(
        operations_cli,
        "_azure_json",
        lambda *args, **kwargs: [{
            "name": "plan-test",
            "resourceGroup": "rg-test",
            "location": "East US",
            "sku": {"name": "P0v4"},
        }],
    )

    operations_cli.configure_webapp_sku()

    updated = json.loads(values_file.read_text(encoding="utf-8"))
    assert updated["web_app_location"] == "eastus"
    assert updated["web_app_sku_name"] == "P0v4"


def test_webapp_location_does_not_move_foundation_or_managed_identity():
    terraform = (operations_cli.TF_DIR / "main.tf").read_text(encoding="utf-8")

    assert "web_app_location   = trimspace(var.web_app_location)" in terraform
    assert terraform.count("location            = local.web_app_location") == 1
    assert terraform.count("location                                       = local.web_app_location") == 1
    dashboard_identity = terraform.split(
        'resource "azurerm_user_assigned_identity" "dashboard" {',
        maxsplit=1,
    )[1].split("}", maxsplit=1)[0]
    assert "location            = var.location" in dashboard_identity


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


def test_log_query_applies_explicit_timespan(monkeypatch):
    captured: list[tuple[object, ...]] = []

    def fake_az(*args, **kwargs):
        captured.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="[]")

    monkeypatch.setattr(operations_cli, "_az", fake_az)

    operations_cli._log_query("workspace-id", "subscription-id", "AppRequests | take 1", timespan="PT1H")

    assert captured[1][captured[1].index("--timespan") + 1] == "PT1H"


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
        lambda *args, **kwargs: [{
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


def test_function_status_does_not_treat_accepted_request_as_completed(monkeypatch, capsys):
    monkeypatch.setattr(
        operations_cli,
        "_workspace_context",
        lambda: ({"function_app_name": "func-test", "subscription_id": "sub-test"}, "workspace-test"),
    )
    responses = iter([
        [{
            "InvocationId": "completed-invocation",
            "StartedUtc": "2026-10-11T18:20:49Z",
            "CompletedUtc": None,
            "CompletionStatus": None,
        }],
        [{
            "RequestStartedUtc": "2026-10-11T18:20:50Z",
            "Success": True,
            "DurationMs": 977000,
            "ResultCode": "0",
        }],
        [],
    ])
    monkeypatch.setattr(operations_cli, "_log_query", lambda *args, **kwargs: next(responses))

    assert operations_cli.check_function_logs(1, 3, True) == "INDETERMINATE"
    output = capsys.readouterr().out
    assert "trigger request accepted" in output
    assert "Execution and publication are not confirmed" in output


def test_function_status_uses_request_when_start_trace_is_missing(monkeypatch, capsys):
    monkeypatch.setattr(
        operations_cli,
        "_workspace_context",
        lambda: ({"function_app_name": "func-test", "subscription_id": "sub-test"}, "workspace-test"),
    )
    responses = iter([
        [],
        [{
            "TimeGenerated": "2026-10-14T04:59:59Z",
            "Success": True,
            "DurationMs": None,
            "ResultCode": "0",
            "OperationId": "request-operation",
            "FunctionName": "dataprep_snapshot",
        }],
        [],
    ])
    monkeypatch.setattr(operations_cli, "_log_query", lambda *args, **kwargs: next(responses))

    assert operations_cli.check_function_logs(24, 3, True) == "INDETERMINATE"
    output = capsys.readouterr().out
    assert "request-operation" in output
    assert "dataprep_snapshot" in output
    assert "No invocation was found" not in output
    assert "trigger request accepted" in output


def test_telemetry_value_accepts_aliases_case_insensitively():
    row = {"timegenerated": "2026-10-14T04:59:59Z"}

    assert operations_cli._telemetry_value(row, "TimeGenerated", "RequestStartedUtc") == "2026-10-14T04:59:59Z"
    assert operations_cli._telemetry_value(row, "DurationMs") is None


def test_detailed_function_diagnostics_show_execution_evidence(monkeypatch, capsys):
    monkeypatch.setattr(
        operations_cli,
        "_workspace_context",
        lambda: ({"function_app_name": "func-test", "subscription_id": "sub-test"}, "workspace-test"),
    )
    request = {
        "RequestStartedUtc": "2026-10-14T04:59:59Z",
        "TimeGenerated": "2026-10-14T04:59:59Z",
        "Success": True,
        "DurationMs": None,
        "DurationSeconds": None,
        "ResultCode": "0",
        "OperationId": "request-operation",
        "FunctionName": "dataprep_snapshot",
        "Name": "dataprep_snapshot",
    }
    responses = iter([
        [],
        [request],
        [{
            "TimeGenerated": "2026-10-14T05:10:00Z",
            "OperationId": "request-operation",
            "RunId": "live-test",
            "SnapshotUtc": "2026-10-14T04:59:59Z",
            "PublicationStatus": "Success",
            "Findings": 19638,
            "Files": 115,
            "ReportedIssues": 0,
        }],
        [request],
        [{
            "TimeGenerated": "2026-10-14T05:10:00Z",
            "Kind": "Trace",
            "Detail": "[publication] runId=live-test status=Success",
        }],
    ])
    monkeypatch.setattr(operations_cli, "_log_query", lambda *args, **kwargs: next(responses))

    operations_cli.check_function_logs(24, 3, False)

    output = capsys.readouterr().out
    assert "Result:            Success" in output
    assert "Run ID:            live-test" in output
    assert "Findings:          19638" in output
    assert "Published files:   115" in output
    assert "Reported issues:   0" in output
    assert "Duration:  unavailable" in output
    assert "Collector execution evidence:" in output
    assert "[publication] runId=live-test status=Success" in output


def test_check_runs_allows_empty_history_before_first_publication(monkeypatch, capsys):
    monkeypatch.setattr(operations_cli, "_tf_output", lambda name: f"{name}-test")
    monkeypatch.setattr(
        operations_cli,
        "_az",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "function-key\n", ""),
    )
    monkeypatch.setattr(
        operations_cli.requests,
        "get",
        lambda *args, **kwargs: type(
            "Response",
            (),
            {"status_code": 404, "json": lambda self: {"published": False, "reason": "No current manifest"}},
        )(),
    )
    monkeypatch.setattr(
        operations_cli,
        "_workspace_context",
        lambda: ({"subscription_id": "subscription-test"}, "workspace-test"),
    )
    monkeypatch.setattr(operations_cli, "_log_query", lambda *args, **kwargs: [])

    operations_cli.check_runs(5, False)

    assert "No managed-identity publication telemetry was found" in capsys.readouterr().out


def test_check_runs_uses_management_plane_telemetry(monkeypatch, capsys):
    monkeypatch.setattr(operations_cli, "_tf_output", lambda name: f"{name}-test")
    monkeypatch.setattr(
        operations_cli,
        "_az",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "function-key\n", ""),
    )
    monkeypatch.setattr(
        operations_cli.requests,
        "get",
        lambda *args, **kwargs: type(
            "Response",
            (),
            {
                "status_code": 200,
                "json": lambda self: {
                    "published": True,
                    "runId": "live-20261013T200000Z",
                    "snapshotTimeUtc": "2026-10-13T20:00:00Z",
                    "status": "Success",
                    "findings": 9235,
                    "publishedFiles": 115,
                    "reportedIssues": 0,
                },
            },
        )(),
    )
    monkeypatch.setattr(
        operations_cli,
        "_workspace_context",
        lambda: ({"subscription_id": "subscription-test"}, "workspace-test"),
    )
    monkeypatch.setattr(
        operations_cli,
        "_log_query",
        lambda *args, **kwargs: [{
            "TimeGenerated": "2026-10-13T20:00:00Z",
            "RunId": "live-20261013T200000Z",
            "SnapshotUtc": "2026-10-13T20:00:00Z",
            "Status": "Success",
            "Findings": 9235,
            "Files": 115,
            "ReportedIssues": 0,
        }],
    )
    monkeypatch.setattr(
        operations_cli,
        "_az_json",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("unexpected Storage data-plane call")),
    )

    operations_cli.check_runs(5, False)

    output = capsys.readouterr().out
    assert "live-20261013T200000Z" in output
    assert "Findings:         9235" in output
    assert "Published files:  115" in output


def test_check_runs_surfaces_authoritative_status_failure(monkeypatch):
    monkeypatch.setattr(operations_cli, "_tf_output", lambda name: f"{name}-test")
    monkeypatch.setattr(
        operations_cli,
        "_az",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "function-key\n", ""),
    )
    monkeypatch.setattr(
        operations_cli.requests,
        "get",
        lambda *args, **kwargs: type(
            "Response",
            (),
            {
                "status_code": 500,
                "json": lambda self: {"published": False, "reason": "Status lookup failed"},
            },
        )(),
    )

    with pytest.raises(RuntimeError, match="Function publication-status lookup failed: Status lookup failed"):
        operations_cli.check_runs(5, False)


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


def test_values_reject_template_identity_and_naming_placeholders(monkeypatch, tmp_path):
    values = tmp_path / "main.tfvars.json"
    values.write_text(
        json.dumps({
            "subscription_id": "00000000-0000-0000-0000-000000000000",
            "tenant_id": "customer-tenant",
            "collector_management_group_id": "customer-management-group-id",
            "history_storage_account_name": "stdvmhistreplace123",
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(operations_cli, "TF_DIR", tmp_path)
    monkeypatch.setattr(operations_cli, "TF_VARS", values)

    with pytest.raises(RuntimeError) as error:
        operations_cli._values()

    message = str(error.value)
    assert "subscription_id" in message
    assert "collector_management_group_id" in message
    assert "history_storage_account_name" in message
    assert "tenant_id" not in message


def test_values_reject_all_example_naming_placeholders(monkeypatch):
    example = Path("infra/terraform/main.tfvars.example.json")
    monkeypatch.setattr(operations_cli, "TF_VARS", example)

    with pytest.raises(RuntimeError) as error:
        operations_cli._values()

    message = str(error.value)
    for setting in (
        "resource_group_name",
        "project_name",
        "history_storage_account_name",
        "function_runtime_storage_account_name",
        "function_app_name",
        "web_app_name",
        "web_app_service_plan_name",
        "web_app_identity_name",
        "dashboard_entra_application_name",
    ):
        assert setting in message


def test_action_allowed_combines_contributor_and_role_administrator_permissions():
    permissions = [
        {
            "actions": ["*"],
            "notActions": ["Microsoft.Authorization/*/Write"],
        },
        {
            "actions": ["Microsoft.Authorization/roleAssignments/write"],
            "notActions": [],
        },
    ]

    assert operations_cli._action_allowed(permissions, "Microsoft.Web/sites/write")
    assert operations_cli._action_allowed(
        permissions,
        "Microsoft.Authorization/roleAssignments/write",
    )
    assert not operations_cli._action_allowed(
        permissions[:1],
        "Microsoft.Authorization/roleAssignments/write",
    )


def test_deployment_preflight_validates_context_permissions_and_directory_role(monkeypatch, capsys):
    values = {
        "tenant_id": "tenant-id",
        "subscription_id": "subscription-id",
        "collector_management_group_id": "management-group-id",
    }
    calls = []

    def fake_azure_json(label, *args):
        calls.append(args)
        if args[:2] == ("account", "show"):
            return {
                "tenantId": "tenant-id",
                "id": "subscription-id",
                "user": {"name": "operator@example.com"},
            }
        if args[:3] == ("account", "management-group", "show"):
            return {"name": "management-group-id"}
        if "graph.microsoft.com" in args[-1]:
            return {"value": [{"displayName": "Privileged Role Administrator"}]}
        return {"value": [{"actions": ["*"], "notActions": []}]}

    monkeypatch.setattr(operations_cli, "_values", lambda: values)
    monkeypatch.setattr(operations_cli, "_azure_json", fake_azure_json)

    operations_cli.deployment_preflight()

    output = capsys.readouterr().out
    assert "Deployment permission preflight passed for operator@example.com." in output
    assert any("management-group-id" in call for call in calls)


def test_deployment_preflight_rejects_missing_management_group_role_write(monkeypatch):
    values = {
        "tenant_id": "tenant-id",
        "subscription_id": "subscription-id",
        "collector_management_group_id": "management-group-id",
    }

    def fake_azure_json(label, *args):
        if args[:2] == ("account", "show"):
            return {
                "tenantId": "tenant-id",
                "id": "subscription-id",
                "user": {"name": "operator@example.com"},
            }
        if args[:3] == ("account", "management-group", "show"):
            return {"name": "management-group-id"}
        if "managementGroups" in args[-1]:
            return {"value": [{"actions": ["*/read"], "notActions": []}]}
        return {"value": [{"actions": ["*"], "notActions": []}]}

    monkeypatch.setattr(operations_cli, "_values", lambda: values)
    monkeypatch.setattr(operations_cli, "_azure_json", fake_azure_json)

    with pytest.raises(RuntimeError, match="roleAssignments/write"):
        operations_cli.deployment_preflight()


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


def test_webapp_deployment_restarts_only_after_onedeploy_completes(monkeypatch, tmp_path: Path):
    calls: list[tuple[object, ...]] = []
    statuses = iter([
        ({"deploymentId": "previous-deployment", "status": "RuntimeSuccessful"}, ""),
        ({"deploymentId": "new-deployment", "status": "BuildSuccessful"}, ""),
    ])

    def fake_az(*args, **kwargs):
        calls.append(args)
        stdout = "/subscriptions/test/resourceGroups/rg-test/providers/Microsoft.Web/sites/app-test\n" \
            if args[:2] == ("webapp", "show") else ""
        return subprocess.CompletedProcess(args, 0, stdout=stdout)

    monkeypatch.setattr(operations_cli, "ROOT", tmp_path)
    monkeypatch.setattr(operations_cli, "_values", lambda: {"dashboard_version": "2026.10.09.3"})
    monkeypatch.setattr(operations_cli, "_dashboard_source_version", lambda: "2026.10.09.3")
    monkeypatch.setattr(
        operations_cli,
        "_tf_output",
        lambda name: {"resource_group_name": "rg-test", "web_app_name": "app-test"}[name],
    )
    monkeypatch.setattr(operations_cli, "_zip_tree", lambda *args, **kwargs: None)
    monkeypatch.setattr(operations_cli, "_stamp_web_package", lambda *args, **kwargs: None)
    monkeypatch.setattr(operations_cli, "_az", fake_az)
    monkeypatch.setattr(operations_cli, "_webapp_onedeploy_status", lambda *args: next(statuses))

    operations_cli.deploy_webapp()

    deploy_index = next(index for index, call in enumerate(calls) if call[:2] == ("webapp", "deploy"))
    settings_index = next(
        index for index, call in enumerate(calls)
        if call[:4] == ("webapp", "config", "appsettings", "set")
    )
    start_index = next(index for index, call in enumerate(calls) if call[:2] == ("webapp", "start"))
    assert calls[deploy_index][calls[deploy_index].index("--restart") + 1] == "false"
    assert calls[deploy_index][calls[deploy_index].index("--async") + 1] == "true"
    assert calls[deploy_index][calls[deploy_index].index("--track-status") + 1] == "true"
    assert deploy_index < settings_index < start_index
    assert not any(call[:4] == ("webapp", "log", "deployment", "list") for call in calls)


def test_webapp_deployment_reports_onedeploy_failure(monkeypatch):
    statuses = iter([
        ({"deploymentId": "previous-deployment", "status": "RuntimeSuccessful"}, ""),
        ({"deploymentId": "new-deployment", "status": "BuildFailed", "errors": ["build error"]}, ""),
    ])
    monkeypatch.setattr(operations_cli, "_webapp_onedeploy_status", lambda *args: next(statuses))

    previous, _ = operations_cli._webapp_onedeploy_status("resource-id")
    with pytest.raises(RuntimeError, match="BuildFailed"):
        operations_cli._wait_for_webapp_deployment("resource-id", previous["deploymentId"])


def test_webapp_deployment_rejects_mismatched_source_version(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(operations_cli, "ROOT", tmp_path)
    monkeypatch.setattr(operations_cli, "_values", lambda: {"dashboard_version": "2026.10.11.3"})
    monkeypatch.setattr(operations_cli, "_dashboard_source_version", lambda: "2026.10.11.6")
    monkeypatch.setattr(
        operations_cli,
        "_tf_output",
        lambda name: {"resource_group_name": "rg-test", "web_app_name": "app-test"}[name],
    )

    with pytest.raises(RuntimeError, match="Dashboard version mismatch"):
        operations_cli.deploy_webapp()


def test_web_app_uses_configurable_worker_processes():
    terraform = Path("infra/terraform/main.tf").read_text()
    variables = Path("infra/terraform/variables.tf").read_text()
    example = json.loads(Path("infra/terraform/main.tfvars.example.json").read_text())

    assert "--workers ${var.web_app_worker_processes}" in terraform
    assert 'variable "web_app_worker_processes"' in variables
    assert example["web_app_worker_processes"] == 1


def test_function_telemetry_preserves_operational_evidence():
    host = json.loads(Path("host.json").read_text(encoding="utf-8"))
    excluded = host["logging"]["applicationInsights"]["samplingSettings"]["excludedTypes"].split(";")

    assert {"Request", "Trace", "Exception"} <= set(excluded)


def test_workflow_container_is_part_of_protected_foundation():
    terraform = Path("infra/terraform/main.tf").read_text()

    workflow = terraform.split('resource "azurerm_storage_container" "dashboard_workflow" {', 1)[1].split(
        'resource "azurerm_network_security_perimeter_association" "history_storage" {',
        1,
    )[0]
    assert "count = 1" in workflow
    assert "prevent_destroy = true" in workflow


def test_application_teardown_plan_allows_only_replaceable_deletes(monkeypatch, tmp_path: Path):
    plan = tmp_path / "application-teardown.tfplan"
    plan.write_text("reviewed")
    plan_json = {
        "resource_changes": [
            {
                "address": 'azurerm_linux_web_app.dashboard["dashboard"]',
                "change": {"actions": ["delete"]},
            },
            {
                "address": "azurerm_storage_account.history",
                "change": {"actions": ["no-op"]},
            },
        ],
    }
    monkeypatch.setattr(operations_cli, "APPLICATION_TEARDOWN_PLAN", plan)
    monkeypatch.setattr(
        operations_cli,
        "_tf",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout=json.dumps(plan_json)),
    )

    assert operations_cli._validate_application_teardown_plan() == [
        'azurerm_linux_web_app.dashboard["dashboard"]'
    ]


def test_application_teardown_plan_rejects_foundation_change(monkeypatch, tmp_path: Path):
    plan = tmp_path / "application-teardown.tfplan"
    plan.write_text("reviewed")
    plan_json = {
        "resource_changes": [
            {
                "address": "azurerm_storage_account.history",
                "change": {"actions": ["delete"]},
            },
        ],
    }
    monkeypatch.setattr(operations_cli, "APPLICATION_TEARDOWN_PLAN", plan)
    monkeypatch.setattr(
        operations_cli,
        "_tf",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout=json.dumps(plan_json)),
    )

    with pytest.raises(RuntimeError, match="outside the replaceable application allowlist"):
        operations_cli._validate_application_teardown_plan()


def test_application_teardown_plan_can_allow_empty_for_full_test_deletion(monkeypatch, tmp_path: Path):
    plan = tmp_path / "application-teardown.tfplan"
    plan.write_text("reviewed")
    monkeypatch.setattr(operations_cli, "APPLICATION_TEARDOWN_PLAN", plan)
    monkeypatch.setattr(
        operations_cli,
        "_tf",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args,
            0,
            stdout=json.dumps({"resource_changes": []}),
        ),
    )

    assert operations_cli._validate_application_teardown_plan(allow_empty=True) == []
    with pytest.raises(RuntimeError, match="contains no replaceable application resources"):
        operations_cli._validate_application_teardown_plan()


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
    requests = []
    monkeypatch.setattr(
        operations_cli.requests,
        "post",
        lambda *args, **kwargs: requests.append((args, kwargs)) or AcceptedResponse(),
    )

    operations_cli.invoke(True)

    output = capsys.readouterr().out
    assert requests[0][0][0].endswith("/admin/functions/dataprep_manual_snapshot")
    assert requests[0][1]["json"] == {"input": None}
    assert "trigger accepted" in output
    assert "does not confirm collection success" in output
    assert "check-runs --limit 10 --progress" in output


def test_full_invoke_targets_manual_full_reconciliation_function(monkeypatch):
    class AcceptedResponse:
        status_code = 202

        @staticmethod
        def raise_for_status():
            return None

    requests = []
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
    monkeypatch.setattr(
        operations_cli.requests,
        "post",
        lambda *args, **kwargs: requests.append((args, kwargs)) or AcceptedResponse(),
    )

    operations_cli.invoke(True, full=True)

    assert requests[0][0][0].endswith("/admin/functions/dataprep_full_snapshot")
    assert requests[0][1]["json"] == {"input": "full"}


def test_verify_function_does_not_block_on_published_data_status(monkeypatch, capsys):
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
        ],
    )

    operations_cli.verify("function")

    output = capsys.readouterr().out
    assert "Function verification complete" in output
    assert "check-runs --progress" in output


def test_verify_webapp_bounds_azure_calls_and_checks_browser_redirect(monkeypatch, capsys):
    outputs = {
        "resource_group_name": "rg-test",
        "function_app_name": "func-test",
        "web_app_name": "app-test",
        "dashboard_url": "https://app-test.example/",
        "dashboard_enterprise_application_name": "DVM Viewer",
        "dashboard_entra_client_id": "client-id",
        "dashboard_enterprise_application_object_id": "object-id",
    }
    azure_calls = []

    class RedirectResponse:
        status_code = 302
        headers = {"location": "https://login.microsoftonline.com/example"}

        @staticmethod
        def close():
            return None

    def fake_az(*args, **kwargs):
        azure_calls.append((args, kwargs))
        stdout = "2026.10.11.2\n" if args[:4] == ("webapp", "config", "appsettings", "list") else ""
        return subprocess.CompletedProcess(args, 0, stdout=stdout)

    get_calls = []

    def fake_get(*args, **kwargs):
        get_calls.append((args, kwargs))
        return RedirectResponse()

    monkeypatch.setattr(operations_cli, "_tf_output", lambda name: outputs[name])
    monkeypatch.setattr(operations_cli, "_validate_function_runtime_storage_auth", lambda *args: None)
    monkeypatch.setattr(operations_cli, "_az", fake_az)
    monkeypatch.setattr(operations_cli.requests, "get", fake_get)

    operations_cli.verify("webapp")

    assert all(kwargs["timeout"] == 60 for _, kwargs in azure_calls)
    assert get_calls == [
        (("https://app-test.example/",), {"allow_redirects": False, "stream": True, "timeout": (10, 30)})
    ]
    output = capsys.readouterr().out
    assert "Reading Web App deployment version" in output
    assert "Authentication gate check: HTTP 302" in output
    assert "Web App verification passed" in output


def test_verify_webapp_accepts_easy_auth_bearer_challenge(monkeypatch, capsys):
    outputs = {
        "resource_group_name": "rg-test",
        "function_app_name": "func-test",
        "web_app_name": "app-test",
        "dashboard_url": "https://app-test.example/",
        "dashboard_enterprise_application_name": "DVM Viewer",
        "dashboard_entra_client_id": "client-id",
        "dashboard_enterprise_application_object_id": "object-id",
    }

    class ChallengeResponse:
        status_code = 401
        headers = {"www-authenticate": 'Bearer realm="app-test.example"'}

        @staticmethod
        def close():
            return None

    monkeypatch.setattr(operations_cli, "_tf_output", lambda name: outputs[name])
    monkeypatch.setattr(operations_cli, "_validate_function_runtime_storage_auth", lambda *args: None)
    monkeypatch.setattr(
        operations_cli,
        "_az",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout="2026.10.11.2\n"),
    )
    monkeypatch.setattr(operations_cli.requests, "get", lambda *args, **kwargs: ChallengeResponse())

    operations_cli.verify("webapp")

    output = capsys.readouterr().out
    assert "Authentication gate check: HTTP 401 -> Bearer" in output
    assert "Web App verification passed" in output


def test_webapp_startup_retries_transient_response(monkeypatch, capsys):
    class Response:
        def __init__(self, status_code, headers=None):
            self.status_code = status_code
            self.headers = headers or {}

        def close(self):
            return None

    responses = [
        Response(503),
        Response(302, {"location": "https://login.microsoftonline.com/example"}),
    ]
    sleeps = []
    monkeypatch.setattr(operations_cli.requests, "get", lambda *args, **kwargs: responses.pop(0))
    monkeypatch.setattr(operations_cli.time, "sleep", sleeps.append)

    response = operations_cli._get_webapp_response_with_retry(
        "https://app-test.example/",
        attempts=3,
        delay_seconds=2,
    )

    assert response.status_code == 302
    assert sleeps == [2]
    assert "Web App is still starting (HTTP 503)" in capsys.readouterr().out


def test_webapp_startup_reports_persistent_unavailability(monkeypatch):
    class Response:
        status_code = 503
        headers = {}

        @staticmethod
        def close():
            return None

    monkeypatch.setattr(operations_cli.requests, "get", lambda *args, **kwargs: Response())
    monkeypatch.setattr(operations_cli.time, "sleep", lambda *_: None)

    with pytest.raises(RuntimeError, match="remained unavailable after 6 seconds"):
        operations_cli._get_webapp_response_with_retry(
            "https://app-test.example/",
            attempts=3,
            delay_seconds=2,
        )
