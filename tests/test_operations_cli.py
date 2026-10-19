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
    assert operations_cli.build_parser().parse_args(["version"]).command == "version"
    assert operations_cli.build_parser().parse_args(["check-runs", "--limit", "5", "--progress"]).progress is True
    assert operations_cli.build_parser().parse_args(["export-function-logs", "--hours", "72"]).hours == 72
    assert operations_cli.build_parser().parse_args(["invoke", "function", "--confirm"]).confirm is True
    assert operations_cli.build_parser().parse_args(["invoke", "function", "--confirm", "--full"]).full is True


@pytest.mark.parametrize("command", ["check-function-logs", "export-function-logs"])
@pytest.mark.parametrize("arguments, expected_hours", [
    ([], 24),
    (["--hours", "48"], 48),
    (["--days", "2"], 48),
    (["--days", "7"], 168),
])
def test_log_commands_accept_days_or_hours(monkeypatch, command, arguments, expected_hours):
    calls = []
    monkeypatch.setattr(operations_cli, "check_function_logs", lambda hours, *args: calls.append(hours))
    monkeypatch.setattr(operations_cli, "export_function_logs", lambda hours: calls.append(hours))

    assert operations_cli.main([command, *arguments]) == 0
    assert calls == [expected_hours]


@pytest.mark.parametrize("command", ["check-function-logs", "export-function-logs"])
@pytest.mark.parametrize("arguments", [
    ["--days", "0"],
    ["--days", "-1"],
    ["--days", "1.5"],
    ["--days", "abc"],
    ["--hours", "0"],
    ["--days", "2", "--hours", "48"],
])
def test_log_commands_reject_invalid_or_conflicting_lookbacks(command, arguments):
    with pytest.raises(SystemExit) as error:
        operations_cli.build_parser().parse_args([command, *arguments])
    assert error.value.code == 2


def test_version_reports_cli_source(capsys):
    assert operations_cli.main(["version"]) == 0

    output = capsys.readouterr().out
    assert f"Operations CLI version: {operations_cli.OPERATIONS_CLI_VERSION}" in output
    assert str(Path(operations_cli.__file__).resolve()) in output


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
    assert captured[1][1] == {"capture": True, "check": False, "timeout": 90}


def test_log_query_surfaces_captured_azure_error(monkeypatch):
    responses = iter([
        subprocess.CompletedProcess((), 0, stdout=""),
        subprocess.CompletedProcess((), 1, stdout="", stderr="BadArgumentError: invalid KQL column"),
    ])
    monkeypatch.setattr(operations_cli, "_az", lambda *args, **kwargs: next(responses))

    with pytest.raises(RuntimeError, match="BadArgumentError: invalid KQL column"):
        operations_cli._log_query("workspace-id", "subscription-id", "AppTraces | take 1")


def test_log_query_rejects_missing_output(monkeypatch):
    monkeypatch.setattr(
        operations_cli, "_az",
        lambda *args, **kwargs: subprocess.CompletedProcess((), 0, stdout=""),
    )

    with pytest.raises(RuntimeError, match="returned no JSON"):
        operations_cli._log_query("workspace-id", "subscription-id", "AppTraces | take 1")


def test_function_telemetry_scopes_raw_cli_rows_locally(monkeypatch, capsys):
    queries = []
    rows = [
        {
            "TimeGenerated": "2026-10-19T17:14:41.7449352Z",
            "SourceTable": "AppTraces",
            "AppRoleName": "func-test",
            "OperationId": "",
            "Message": "[storage] uploaded 156/156 durable run files (100.0%)",
        },
        {
            "TimeGenerated": "2026-10-19T17:14:42Z",
            "SourceTable": "AppTraces",
            "AppRoleName": "",
            "_ResourceId": "/INSIGHTS/LINKED-TEST",
            "Properties": '{"deploymentId":"deployment-test"}',
            "Message": "Deployment logs were not retained after instance recycling.",
        },
        {
            "TimeGenerated": "2026-10-19T17:14:43Z",
            "SourceTable": "FunctionAppLogs",
            "_ResourceId": (
                "/subscriptions/sub-test/resourceGroups/rg-test/"
                "providers/Microsoft.Web/sites/func-test"
            ),
            "Message": "Starting host",
        },
        {
            "TimeGenerated": "2026-10-19T17:14:44Z",
            "SourceTable": "AppTraces",
            "AppRoleName": "another-app",
            "_ResourceId": "/insights/linked-test",
            "Message": "Unrelated application",
        },
        {
            "TimeGenerated": "2026-10-19T17:14:45Z",
            "SourceTable": "AppTraces",
            "_ResourceId": "/insights/another-app",
            "Message": "Unrelated role-less deployment",
        },
    ]

    def fake_query(workspace, subscription, query, *, timespan):
        queries.append((workspace, subscription, query, timespan))
        if "extend TelemetryRole" in query:
            return []
        return rows

    monkeypatch.setattr(operations_cli, "_log_query", fake_query)
    values = {
        "subscription_id": "sub-test",
        "resource_group_name": "rg-test",
        "function_app_name": "func-test",
        "_application_insights_resource_id": "/insights/linked-test",
    }

    assert operations_cli._function_telemetry_rows(values, "workspace-test", 168, 500) == rows[2::-1]
    workspace, subscription, query, timespan = queries[0]
    assert (workspace, subscription, timespan) == ("workspace-test", "sub-test", "PT168H")
    assert "union isfuzzy=true withsource=SourceTable" in query
    for table in ("AppTraces", "AppExceptions", "AppDependencies", "FunctionAppLogs", "AzureDiagnostics"):
        assert table in query
    assert "OperationId in" not in query
    assert "Message startswith" not in query
    assert "| where" not in query
    assert "| extend" not in query
    assert '"' not in query
    assert "\n" not in query
    assert "take 5000" in query
    assert "Workspace telemetry scanned: 5; matching Function records: 3" in capsys.readouterr().out


def test_application_request_rows_sort_and_limit_raw_cli_results(monkeypatch):
    rows = [
        {"TimeGenerated": "2026-10-18T05:00:00Z", "Name": "dataprep_snapshot"},
        {"TimeGenerated": "2026-10-17T05:00:00Z", "Name": "dataprep_snapshot"},
        {"TimeGenerated": "2026-10-19T05:00:00Z", "Name": "dataprep_snapshot"},
    ]
    monkeypatch.setattr(operations_cli, "_log_query", lambda *args, **kwargs: rows)

    assert operations_cli._application_request_rows("workspace-test", "sub-test", 168, 2) == [
        rows[2], rows[0],
    ]


def test_log_query_applies_explicit_timespan(monkeypatch):
    captured: list[tuple[object, ...]] = []

    def fake_az(*args, **kwargs):
        captured.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="[]")

    monkeypatch.setattr(operations_cli, "_az", fake_az)

    operations_cli._log_query("workspace-id", "subscription-id", "AppRequests | take 1", timespan="PT1H")

    assert captured[1][captured[1].index("--timespan") + 1] == "PT1H"


def test_log_query_rejects_unexpected_cli_json_shape(monkeypatch):
    responses = iter([
        subprocess.CompletedProcess((), 0, stdout=""),
        subprocess.CompletedProcess((), 0, stdout='{"tables": []}'),
    ])
    monkeypatch.setattr(operations_cli, "_az", lambda *args, **kwargs: next(responses))

    with pytest.raises(RuntimeError, match="unexpected Log Analytics JSON shape"):
        operations_cli._log_query("workspace-id", "subscription-id", "AppRequests | take 1")


def test_workspace_context_uses_application_insights_workspace(monkeypatch):
    monkeypatch.delenv("LOG_ANALYTICS_WORKSPACE_NAME", raising=False)
    monkeypatch.setattr(
        operations_cli,
        "_values",
        lambda: {
            "subscription_id": "subscription-test",
            "resource_group_name": "resource-group-test",
            "function_app_name": "function-test",
        },
    )
    json_calls = []

    def fake_az_json(*args):
        json_calls.append(args)
        if args[:2] == ("functionapp", "show"):
            return {
                "tags": {
                    "hidden-link: /app-insights-resource-id": (
                        "/subscriptions/subscription-test/resourceGroups/resource-group-test/"
                        "providers/microsoft.insights/components/insights-test"
                    ),
                },
            }
        return {
            "properties": {
                "WorkspaceResourceId": (
                    "/subscriptions/subscription-test/resourceGroups/resource-group-test/"
                    "providers/Microsoft.OperationalInsights/workspaces/workspace-test"
                ),
            },
        }

    monkeypatch.setattr(operations_cli, "_az_json", fake_az_json)
    captured = []

    def fake_az(*args, **kwargs):
        captured.append(args)
        return subprocess.CompletedProcess(args, 0, "workspace-customer-id\n", "")

    monkeypatch.setattr(operations_cli, "_az", fake_az)

    values, workspace_id = operations_cli._workspace_context()

    assert values["function_app_name"] == "function-test"
    assert workspace_id == "workspace-customer-id"
    assert values["_application_insights_resource_id"].endswith("/insights-test")
    assert json_calls[0][:2] == ("functionapp", "show")
    assert json_calls[1][:2] == ("resource", "show")
    assert "microsoft.insights/components/insights-test" in json_calls[1][json_calls[1].index("--ids") + 1]
    assert "--ids" in captured[0]
    assert "Microsoft.OperationalInsights/workspaces/workspace-test" in captured[0][captured[0].index("--ids") + 1]


def test_workspace_context_requires_linked_application_insights(monkeypatch):
    monkeypatch.delenv("LOG_ANALYTICS_WORKSPACE_NAME", raising=False)
    monkeypatch.setattr(
        operations_cli,
        "_values",
        lambda: {
            "subscription_id": "subscription-test",
            "resource_group_name": "resource-group-test",
            "function_app_name": "function-test",
        },
    )
    monkeypatch.setattr(operations_cli, "_az_json", lambda *args: {"tags": {}})

    with pytest.raises(RuntimeError, match="linked Application Insights"):
        operations_cli._workspace_context()


@pytest.mark.parametrize("workspace_id", ["workspace-test", ""])
def test_workspace_override_preserves_link_for_roleless_deployment_logs(monkeypatch, workspace_id):
    monkeypatch.setenv("LOG_ANALYTICS_WORKSPACE_NAME", "log-test")
    monkeypatch.setattr(operations_cli, "_values", lambda: {
        "subscription_id": "sub-test",
        "resource_group_name": "rg-test",
        "function_app_name": "func-test",
    })
    monkeypatch.setattr(operations_cli, "_az_json", lambda *args: {
        "tags": {"hidden-link: /app-insights-resource-id": "/insights/test"},
    })
    calls = []

    def fake_az(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=workspace_id)

    monkeypatch.setattr(operations_cli, "_az", fake_az)
    if workspace_id:
        values, resolved_id = operations_cli._workspace_context()
        assert resolved_id == workspace_id
        assert values["_application_insights_resource_id"] == "/insights/test"
        assert calls[0][calls[0].index("--workspace-name") + 1] == "log-test"
    else:
        with pytest.raises(RuntimeError, match="selected Log Analytics workspace has no customer ID"):
            operations_cli._workspace_context()


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
    monkeypatch.setattr(operations_cli, "_function_publication_status", lambda: {"published": False})
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
    monkeypatch.setattr(operations_cli, "_function_publication_status", lambda: {"published": False})
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
            "Name": "dataprep_manual_snapshot",
        }],
        [],
    ])
    monkeypatch.setattr(operations_cli, "_log_query", lambda *args, **kwargs: next(responses))

    assert operations_cli.check_function_logs(1, 3, True) == "INDETERMINATE"
    output = capsys.readouterr().out
    assert "trigger request accepted" in output
    assert "Execution and publication are not confirmed" in output


def test_function_status_uses_request_when_start_trace_is_missing(monkeypatch, capsys):
    monkeypatch.setattr(operations_cli, "_function_publication_status", lambda: {"published": False})
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


def test_function_status_ignores_status_endpoint_requests(monkeypatch, capsys):
    monkeypatch.setattr(operations_cli, "_function_publication_status", lambda: {"published": False})
    monkeypatch.setattr(
        operations_cli,
        "_workspace_context",
        lambda: ({"function_app_name": "func-test", "subscription_id": "sub-test"}, "workspace-test"),
    )
    responses = iter([
        [],
        [
            {
                "TimeGenerated": "2026-10-14T21:14:16Z",
                "Success": True,
                "OperationId": "status-request",
                "Name": "dataprep_status",
            },
            {
                "TimeGenerated": "2026-10-14T21:13:00Z",
                "Success": True,
                "OperationId": "collector-request",
                "Name": "dataprep_manual_snapshot",
            },
        ],
        [],
    ])
    monkeypatch.setattr(operations_cli, "_log_query", lambda *args, **kwargs: next(responses))

    assert operations_cli.check_function_logs(1, 3, True) == "INDETERMINATE"

    output = capsys.readouterr().out
    assert "collector-request" in output
    assert "dataprep_manual_snapshot" in output
    assert "status-request" not in output
    assert "dataprep_status" not in output


def test_telemetry_value_accepts_aliases_case_insensitively():
    row = {"timegenerated": "2026-10-14T04:59:59Z"}

    assert operations_cli._telemetry_value(row, "TimeGenerated", "RequestStartedUtc") == "2026-10-14T04:59:59Z"
    assert operations_cli._telemetry_value(row, "DurationMs") is None


def test_detailed_function_diagnostics_show_execution_evidence(monkeypatch, capsys):
    monkeypatch.setattr(operations_cli, "_function_publication_status", lambda: {"published": False})
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
            "SourceTable": "AppTraces",
            "AppRoleName": "func-test",
            "Message": "[publication] runId=live-test status=Success",
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
    assert "Result:    0" in output
    assert "Function telemetry (execution, host, and deployment):" in output
    assert "[publication] runId=live-test status=Success" in output
    assert "Telemetry records shown: 1" in output


def test_detailed_logs_render_host_errors_without_invocation_or_operation_id(monkeypatch, capsys):
    values = {"function_app_name": "func-test", "subscription_id": "sub-test"}
    responses = iter([[], [], [], []])
    monkeypatch.setattr(operations_cli, "_workspace_context", lambda: (values, "workspace-test"))
    monkeypatch.setattr(operations_cli, "_function_publication_status", lambda: {"published": False})
    monkeypatch.setattr(operations_cli, "_log_query", lambda *args, **kwargs: next(responses))
    monkeypatch.setattr(operations_cli, "_function_telemetry_rows", lambda *args: [
        {
            "TimeGenerated": "2026-10-19T12:00:00Z",
            "SourceTable": "AppExceptions",
            "ExceptionType": "ModuleNotFoundError",
            "OuterMessage": "No module named 'example'",
            "Details": '[{"rawStack":"worker startup stack"}]',
            "OperationId": "",
        },
        {
            "TimeGenerated": "2026-10-19T12:00:01Z",
            "SourceTable": "FunctionAppLogs",
            "Message": "Worker failed to index functions",
        },
    ])

    operations_cli.check_function_logs(168, 25, False)

    output = capsys.readouterr().out
    assert "No invocation was found" in output
    assert "No collector request records" in output
    assert "ModuleNotFoundError" in output
    assert "No module named 'example'" in output
    assert "worker startup stack" in output
    assert "Worker failed to index functions" in output
    assert "workspace-test" in output
    assert "sub-test" in output


def test_detailed_requests_use_raw_durations_and_newest_first_order(monkeypatch, capsys):
    values = {"function_app_name": "func-test", "subscription_id": "sub-test"}
    rows = [
        {
            "TimeGenerated": "2026-10-18T05:00:00Z",
            "Name": "dataprep_snapshot",
            "Success": "True",
            "DurationMs": "360751",
            "ResultCode": "0",
        },
        {
            "TimeGenerated": "2026-10-19T05:00:00Z",
            "Name": "dataprep_snapshot",
            "Success": "True",
            "DurationMs": "74",
            "ResultCode": 0,
        },
    ]
    queries = []

    def fake_query(workspace, subscription, query, *, timespan):
        queries.append(query)
        return rows if query.startswith("AppRequests") else []

    monkeypatch.setattr(operations_cli, "_workspace_context", lambda: (values, "workspace-test"))
    monkeypatch.setattr(operations_cli, "_function_publication_status", lambda: {"published": False})
    monkeypatch.setattr(operations_cli, "_log_query", fake_query)
    monkeypatch.setattr(operations_cli, "_function_telemetry_rows", lambda *args: [])

    operations_cli.check_function_logs(168, 25, False)

    output = capsys.readouterr().out
    assert output.index("UTC:       2026-10-19T05:00:00Z") < output.index("UTC:       2026-10-18T05:00:00Z")
    assert "Duration:  360.8s" in output
    assert "Duration:  0.1s" in output
    assert "Result:    0" in output
    assert all("DurationSeconds" not in query for query in queries if query.startswith("AppRequests"))


def test_function_telemetry_reports_unfiltered_scan_and_display_limits(monkeypatch, capsys):
    values = {
        "subscription_id": "sub-test",
        "function_app_name": "func-test",
    }
    row = {
        "TimeGenerated": "2026-10-19T05:00:00Z",
        "AppRoleName": "func-test",
        "Message": "Worker initialized",
    }
    monkeypatch.setattr(operations_cli, "_log_query", lambda *args, **kwargs: [row] * 5000)

    assert len(operations_cli._function_telemetry_rows(values, "workspace-test", 168, 2)) == 2
    output = capsys.readouterr().out
    assert "Workspace telemetry scanned: 5000; matching Function records: 5000" in output
    assert "older matching records may be omitted" in output

    monkeypatch.setattr(operations_cli, "_log_query", lambda *args, **kwargs: [])
    assert operations_cli._function_telemetry_rows(values, "workspace-test", 168, 2) == []
    assert "Azure returned zero rows for the unfiltered telemetry query:" in capsys.readouterr().out


def test_function_status_prefers_newer_authoritative_publication(monkeypatch, capsys):
    monkeypatch.setattr(
        operations_cli,
        "_workspace_context",
        lambda: ({"function_app_name": "func-test", "subscription_id": "sub-test"}, "workspace-test"),
    )
    responses = iter([
        [],
        [{
            "TimeGenerated": "2026-10-13T23:35:56Z",
            "Success": True,
            "OperationId": "stale-request",
            "FunctionName": "dataprep_manual_snapshot",
        }],
        [],
    ])
    monkeypatch.setattr(operations_cli, "_log_query", lambda *args, **kwargs: next(responses))
    monkeypatch.setattr(
        operations_cli,
        "_function_publication_status",
        lambda: {
            "published": True,
            "runId": "live-20261014T171922Z",
            "snapshotTimeUtc": "2026-10-14T17:19:22Z",
            "status": "Success",
            "findings": 19638,
            "publishedFiles": 113,
            "reportedIssues": 0,
        },
    )

    assert operations_cli.check_function_logs(1, 3, True) == "SUCCEEDED"

    output = capsys.readouterr().out
    assert "live-20261014T171922Z" in output
    assert "State:             IDLE - no collector is currently running" in output
    assert "Snapshot UTC:      2026-10-14T17:19:22Z" in output
    assert "Findings:          19638" in output
    assert "Published files:   113" in output
    assert "Reported issues:   0" in output
    assert "stale-request" not in output


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

    assert "No retained [publication] trace history was found" in capsys.readouterr().out


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
    monkeypatch.setattr(
        operations_cli,
        "_workspace_context",
        lambda: ({"subscription_id": "subscription-test"}, "workspace-test"),
    )
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


def test_check_runs_reuses_workspace_and_publication_status_for_progress(monkeypatch):
    context = ({"subscription_id": "subscription-test"}, "workspace-test")
    publication_status = {"published": False, "reason": "No current manifest"}
    context_calls = []
    status_calls = []
    progress_calls = []
    monkeypatch.setattr(
        operations_cli,
        "_workspace_context",
        lambda: context_calls.append(True) or context,
    )
    monkeypatch.setattr(
        operations_cli,
        "_function_publication_status",
        lambda: status_calls.append(True) or publication_status,
    )
    monkeypatch.setattr(
        operations_cli,
        "check_function_logs",
        lambda *args, **kwargs: progress_calls.append((args, kwargs)) or "NONE",
    )
    monkeypatch.setattr(operations_cli, "_log_query", lambda *args, **kwargs: [])

    operations_cli.check_runs(5, True)

    assert context_calls == [True]
    assert status_calls == [True]
    assert progress_calls == [(
        (1, 1, True),
        {
            "workspace_context": context,
            "publication_status": publication_status,
        },
    )]


def test_export_function_logs_writes_timestamped_diagnostics(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(operations_cli, "ROOT", tmp_path)
    monkeypatch.setattr(
        operations_cli,
        "_workspace_context",
        lambda: ({
            "subscription_id": "subscription-test",
            "resource_group_name": "resource-group-test",
            "function_app_name": "function-test",
            "tenant_id": "11111111-2222-3333-4444-555555555555",
        }, "workspace-test"),
    )
    telemetry = [{
        "TimeGenerated": "2026-10-14T21:14:47Z",
        "TableName": "AppRequests",
        "Name": "dataprep_manual_snapshot",
        "Success": False,
        "ResultCode": "500",
        "OperationId": "0123456789abcdef0123456789abcdef",
        "Message": (
            "user@example.com called https://function-test.azurewebsites.net/api "
            "from 192.0.2.10 in tenant 11111111-2222-3333-4444-555555555555"
        ),
    }]
    request_response = [{
            "TimeGenerated": "2026-10-14T21:15:00Z",
            "OperationId": "status-operation",
            "Name": "dataprep_status",
            "Success": True,
            "ResultCode": "200",
        }, *telemetry]
    telemetry_responses = iter([
        request_response,
        request_response,
        [],
    ])
    monkeypatch.setattr(
        operations_cli,
        "_log_query",
        lambda workspace, subscription, query, timespan=None: next(telemetry_responses),
    )
    monkeypatch.setattr(
        operations_cli,
        "_az",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "/function/id\n", ""),
    )
    monkeypatch.setattr(
        operations_cli,
        "_az_json",
        lambda *args: [{
            "eventTimestamp": "2026-10-14T21:14:47Z",
            "caller": "user@example.com",
            "operationName": {"value": "Microsoft.Web/sites/functions/action"},
            "status": {"value": "Failed"},
            "properties": {
                "statusCode": "InternalServerError",
                "statusMessage": "function-test failed from 192.0.2.10",
            },
        }],
    )

    output_directory = operations_cli.export_function_logs(24)

    assert output_directory.parent == tmp_path / "output" / "diagnostics"
    telemetry_text = (output_directory / "collector-sanitized-logs.json").read_text()
    platform_text = (output_directory / "collector-sanitized-platform-failures.json").read_text()
    assert "[REDACTED_EMAIL]" in telemetry_text
    assert "[REDACTED_URL]" in telemetry_text
    assert "[REDACTED_IP]" in telemetry_text
    assert "[REDACTED_ID]" in telemetry_text
    assert "[REDACTED_RESOURCE]" in platform_text
    assert "caller" not in platform_text
    assert "dataprep_status" not in telemetry_text
    for sensitive_value in (
        "user@example.com",
        "function-test",
        "192.0.2.10",
        "11111111-2222-3333-4444-555555555555",
        "0123456789abcdef0123456789abcdef",
    ):
        assert sensitive_value not in telemetry_text
        assert sensitive_value not in platform_text
    output = capsys.readouterr().out
    assert "collector-sanitized-logs.json" in output
    assert "collector-sanitized-platform-failures.json" in output
    assert "Collector records exported: 1 (1 requests, 0 execution/host/deployment records)" in output
    assert "Application request records scanned: 2" in output


def test_export_uses_proven_manual_query_shape_and_filters_locally(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(operations_cli, "ROOT", tmp_path)
    monkeypatch.setattr(
        operations_cli,
        "_workspace_context",
        lambda: ({
            "subscription_id": "subscription-test",
            "resource_group_name": "resource-group-test",
            "function_app_name": "function-test",
        }, "workspace-test"),
    )
    request_rows = [
        {
            "TimeGenerated": f"2026-10-14T{index:02d}:00:00Z",
            "OperationId": f"operation-{index}",
            "Name": "dataprep_manual_snapshot" if index % 2 else "dataprep_snapshot",
            "Success": "True",
            "ResultCode": "202",
            "DurationMs": "10",
        }
        for index in range(18)
    ]
    queries: list[tuple[str, str | None]] = []

    def fake_log_query(workspace, subscription, query, timespan=None):
        queries.append((query, timespan))
        if query == (
            "AppRequests | project TimeGenerated, AppRoleName, Name, Success, ResultCode "
            "| order by TimeGenerated desc | take 20"
        ):
            return request_rows
        if query == (
            "AppRequests | project TimeGenerated, AppRoleName, Name, Success, ResultCode, "
            "OperationId, DurationMs | order by TimeGenerated desc | take 500"
        ):
            return request_rows
        return []

    monkeypatch.setattr(operations_cli, "_log_query", fake_log_query)
    monkeypatch.setattr(
        operations_cli,
        "_az",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "/function/id\n", ""),
    )
    monkeypatch.setattr(operations_cli, "_az_json", lambda *args: [])

    output_directory = operations_cli.export_function_logs(24)

    exported = json.loads(
        (output_directory / "collector-sanitized-logs.json").read_text(encoding="utf-8")
    )
    assert len(exported) == 18
    request_query, timespan = queries[0]
    assert request_query == (
        "AppRequests | project TimeGenerated, AppRoleName, Name, Success, ResultCode "
        "| order by TimeGenerated desc | take 20"
    )
    assert "ago(" not in request_query
    assert "DurationMs" not in request_query
    assert "OperationId" not in request_query
    assert timespan == "PT24H"
    correlation_query, correlation_timespan = queries[1]
    assert "OperationId, DurationMs" in correlation_query
    assert correlation_timespan == "PT24H"
    output = capsys.readouterr().out
    assert "Collector records exported: 18 (18 requests, 0 execution/host/deployment records)" in output
    assert "Application request records scanned: 18" in output


def test_export_refuses_silent_empty_when_apprequests_count_is_nonzero(monkeypatch, tmp_path):
    monkeypatch.setattr(operations_cli, "ROOT", tmp_path)
    monkeypatch.setattr(
        operations_cli,
        "_workspace_context",
        lambda: ({
            "subscription_id": "subscription-test",
            "resource_group_name": "resource-group-test",
            "function_app_name": "function-test",
        }, "workspace-test"),
    )

    def fake_log_query(workspace, subscription, query, timespan=None):
        if "summarize AppRequestCount=count()" in query:
            return [{"AppRequestCount": "18"}]
        return []

    monkeypatch.setattr(operations_cli, "_log_query", fake_log_query)

    with pytest.raises(
        RuntimeError,
        match=r"AppRequests verification found 18 record\(s\).*proven request query returned zero",
    ):
        operations_cli.export_function_logs(24)

    assert list((tmp_path / "output" / "diagnostics").glob("*/collector-sanitized-logs.json")) == []


def test_export_keeps_uncorrelated_logs_when_no_request_was_recorded(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(operations_cli, "ROOT", tmp_path)
    monkeypatch.setattr(operations_cli, "_workspace_context", lambda: ({
        "subscription_id": "subscription-test",
        "resource_group_name": "resource-group-test",
        "function_app_name": "function-test",
    }, "workspace-test"))
    responses = iter([[], [{"AppRequestCount": "0"}]])
    monkeypatch.setattr(operations_cli, "_log_query", lambda *args, **kwargs: next(responses))
    telemetry_calls = []

    def telemetry(values, workspace, hours, limit):
        telemetry_calls.append((workspace, hours, limit))
        return [
            {
                "TimeGenerated": "2026-10-13T23:41:56Z",
                "SourceTable": "AppTraces",
                "OperationId": "",
                "AppRoleName": "",
                "Message": "[storage] uploaded 156/156 durable run files (100.0%)",
            },
            {
                "TimeGenerated": "2026-10-19T12:00:00Z",
                "SourceTable": "AppExceptions",
                "Details": [{"rawStack": "Worker failed for user@example.com"}],
            },
        ]

    monkeypatch.setattr(operations_cli, "_function_telemetry_rows", telemetry)
    monkeypatch.setattr(
        operations_cli, "_az",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout="/function/id"),
    )
    monkeypatch.setattr(operations_cli, "_az_json", lambda *args: [])

    output_directory = operations_cli.export_function_logs(168)

    records = json.loads((output_directory / "collector-sanitized-logs.json").read_text())
    assert len(records) == 2
    assert records[0]["Message"].startswith("[storage] uploaded 156/156")
    assert records[0]["OperationId"] == ""
    assert records[1]["Details"] == [{"rawStack": "Worker failed for [REDACTED_EMAIL]"}]
    assert telemetry_calls == [("workspace-test", 168, 5000)]
    assert "0 requests, 2 execution/host/deployment records" in capsys.readouterr().out


def test_detailed_logs_explain_empty_results_and_record_limits(capsys):
    operations_cli._print_function_telemetry([], 100)
    output = capsys.readouterr().out
    assert "not a health check success" in output
    assert "choose a longer custom lookback" in output
    assert "Telemetry records shown: 0" in output

    operations_cli._print_function_telemetry([{
        "TimeGenerated": "2026-10-19T12:00:00Z",
        "SourceTable": "AppTraces",
        "SeverityLevel": "0",
        "Message": "Starting worker",
    }], 1)
    output = capsys.readouterr().out
    assert "level=0" in output
    assert "Record limit reached" in output


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


@pytest.mark.parametrize("reverse", [False, True])
def test_webapp_onedeploy_normalizes_numeric_history_and_selects_newest(monkeypatch, reverse):
    payload = {
        "value": [
            {"properties": {
                "id": "older-active-deployment",
                "status": 4,
                "active": True,
                "complete": True,
                "start_time": "2026-10-13T23:32:28.2137438Z",
            }},
            {"properties": {
                "id": "new-deployment",
                "status": 4,
                "active": False,
                "complete": True,
                "start_time": "2026-10-19T17:35:44.6548457Z",
                "end_time": "2026-10-19T17:36:15.2034945Z",
                "build_summary": {"errors": [], "warnings": []},
            }},
        ],
    }
    if reverse:
        payload["value"].reverse()
    monkeypatch.setattr(
        operations_cli, "_az",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout=json.dumps(payload)),
    )

    deployment, error = operations_cli._webapp_onedeploy_status("/resource/id")

    assert error == ""
    assert deployment["deploymentId"] == "new-deployment"
    assert deployment["status"] == "BuildSuccessful"
    assert deployment["end_time"] == "2026-10-19T17:36:15.2034945Z"
    assert deployment["errors"] == []


@pytest.mark.parametrize("status, expected", [
    (0, "Pending"), (1, "Building"), (2, "Deploying"),
    (3, "BuildFailed"), (4, "BuildSuccessful"), ("4", "BuildSuccessful"),
    ("PostBuildRestartRequired", "PostBuildRestartRequired"),
    ("RuntimeSuccessful", "RuntimeSuccessful"),
])
def test_webapp_onedeploy_normalizes_status_without_claiming_runtime_success(monkeypatch, status, expected):
    payload = {"properties": {
        "id": "deployment-test",
        "status": status,
        "build_summary": {"errors": ["example build error"]},
    }}
    monkeypatch.setattr(
        operations_cli, "_az",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout=json.dumps(payload)),
    )

    deployment, error = operations_cli._webapp_onedeploy_status("/resource/id")

    assert error == ""
    assert deployment["deploymentId"] == "deployment-test"
    assert deployment["status"] == expected
    assert deployment["errors"] == ["example build error"]


@pytest.mark.parametrize("payload", [
    None,
    {"value": "not a list"},
    {"value": [{}]},
    {"value": [{"properties": {"id": "deployment-test", "status": 4, "complete": False}}]},
])
def test_webapp_onedeploy_reports_invalid_response_shapes(monkeypatch, payload):
    monkeypatch.setattr(
        operations_cli, "_az",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout=json.dumps(payload)),
    )

    deployment, error = operations_cli._webapp_onedeploy_status("/resource/id")

    assert deployment == {}
    assert error


def test_webapp_onedeploy_allows_empty_history_before_first_deployment(monkeypatch):
    monkeypatch.setattr(
        operations_cli, "_az",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout='{"value":[]}'),
    )

    assert operations_cli._webapp_onedeploy_status("/resource/id") == ({}, "")


@pytest.mark.parametrize("replacement_status", [None, 3, 4])
def test_webapp_deployment_restarts_only_after_onedeploy_completes(monkeypatch, tmp_path: Path, replacement_status):
    calls: list[tuple[object, ...]] = []
    responses = iter([
        None if replacement_status is None else {"value": [{"properties": {
            "id": "previous-deployment", "status": 4, "complete": True,
            "start_time": "2026-10-13T23:32:28Z",
        }}]},
        {"value": [{"properties": {
            "id": "new-deployment", "status": replacement_status, "complete": True,
            "start_time": "2026-10-19T17:35:44Z",
        }}]},
    ])

    def fake_az(*args, **kwargs):
        calls.append(args)
        if args[0] == "rest":
            stdout = json.dumps(next(responses))
        else:
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
    monkeypatch.setattr(operations_cli.time, "sleep", lambda *args: pytest.fail("Completed numeric deployment must not keep polling"))

    if replacement_status is None:
        with pytest.raises(RuntimeError, match="Could not inspect the previous Web App deployment"):
            operations_cli.deploy_webapp()
        assert not any(call[:2] == ("webapp", "deploy") for call in calls)
        return
    if replacement_status == 3:
        with pytest.raises(RuntimeError, match="BuildFailed"):
            operations_cli.deploy_webapp()
        assert not any(call[:2] in {("webapp", "restart"), ("webapp", "start")} for call in calls)
        assert not any(call[:4] == ("webapp", "config", "appsettings", "set") for call in calls)
        return

    operations_cli.deploy_webapp()

    deploy_index = next(index for index, call in enumerate(calls) if call[:2] == ("webapp", "deploy"))
    settings_index = next(
        index for index, call in enumerate(calls)
        if call[:4] == ("webapp", "config", "appsettings", "set")
    )
    restart_index = next(index for index, call in enumerate(calls) if call[:2] == ("webapp", "restart"))
    assert calls[deploy_index][calls[deploy_index].index("--restart") + 1] == "false"
    assert calls[deploy_index][calls[deploy_index].index("--async") + 1] == "true"
    assert calls[deploy_index][calls[deploy_index].index("--track-status") + 1] == "false"
    assert calls[deploy_index][calls[deploy_index].index("--timeout") + 1] == "600000"
    status_indexes = [index for index, call in enumerate(calls) if call[0] == "rest"]
    assert status_indexes[0] < deploy_index < status_indexes[1] < settings_index < restart_index
    assert not any(call[:2] == ("webapp", "start") for call in calls)
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


@pytest.mark.parametrize("debug,full,expected", [
    (True, False, "dataprep_debug_page"),
    (False, False, "dataprep_manual_snapshot"),
    (False, True, "dataprep_full_snapshot"),
])
def test_manual_invoke_forwards_page_size_to_correct_trigger(monkeypatch, debug, full, expected):
    calls = []
    monkeypatch.setattr(operations_cli, "_tf_output", lambda name: {"resource_group_name": "rg-test", "function_app_name": "func-test"}[name])
    monkeypatch.setattr(operations_cli, "_az", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout="host-key\n"))
    class AcceptedResponse:
        status_code = 202

        def raise_for_status(self):
            pass

    monkeypatch.setattr(operations_cli.requests, "post", lambda url, **kwargs: calls.append((url, kwargs)) or AcceptedResponse())

    operations_cli.invoke(True, full=full, page_size=1, debug=debug)

    assert calls[0][0].endswith(f"/admin/functions/{expected}")
    expected_payload = {"pageSize": 1, "endpoint": "machine_vulnerabilities"} if debug else {"pageSize": 1}
    assert json.loads(calls[0][1]["json"]["input"]) == expected_payload


@pytest.mark.parametrize("value", ["0", "-1", "1001", "1.5", "abc"])
def test_invoke_parser_rejects_invalid_page_size(value):
    with pytest.raises(SystemExit):
        operations_cli.build_parser().parse_args(["invoke", "function", "--page-size", value])


def test_invoke_rejects_debug_with_full_before_azure_calls(monkeypatch):
    monkeypatch.setattr(operations_cli, "_tf_output", lambda *args: pytest.fail("Invalid mode must not call Azure"))
    with pytest.raises(ValueError):
        operations_cli.invoke(True, full=True, debug=True)


@pytest.mark.parametrize("page_size", [None, 1000])
def test_invoke_forwards_catalog_debug_selection(monkeypatch, page_size):
    calls = []
    monkeypatch.setattr(operations_cli, "_tf_output", lambda name: {"resource_group_name": "rg-test", "function_app_name": "func-test"}[name])
    monkeypatch.setattr(operations_cli, "_az", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout="host-key\n"))
    class AcceptedResponse:
        status_code = 202

        def raise_for_status(self):
            pass

    monkeypatch.setattr(operations_cli.requests, "post", lambda url, **kwargs: calls.append(kwargs) or AcceptedResponse())

    operations_cli.invoke(True, debug=True, page_size=page_size, endpoint="vulnerabilities")

    assert json.loads(calls[0]["json"]["input"]) == {"pageSize": 1000, "endpoint": "vulnerabilities"}


@pytest.mark.parametrize("configured,expected", [
    (None, "https://api-us3.securitycenter.microsoft.com"),
    ("https://us.api.security.microsoft.com/", "https://us.api.security.microsoft.com"),
])
def test_function_deploy_synchronizes_base_uri_from_terraform_values(monkeypatch, tmp_path, configured, expected):
    values = {"subscription_id": "subscription", "function_version": "2026.10.19.3"}
    if configured is not None:
        values["defender_api_base_url"] = configured
    calls = []
    monkeypatch.delenv("FUNCTION_VERSION", raising=False)
    monkeypatch.setattr(operations_cli, "ROOT", tmp_path)
    monkeypatch.setattr(operations_cli, "_values", lambda: values)
    monkeypatch.setattr(operations_cli, "_tf_output", lambda name: {"resource_group_name": "rg-test", "function_app_name": "func-test"}[name])
    monkeypatch.setattr(operations_cli, "_require", lambda name: name)
    monkeypatch.setattr(operations_cli, "_run", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout="commit\n"))
    monkeypatch.setattr(operations_cli, "_zip_tree", lambda *args: None)
    monkeypatch.setattr(operations_cli.time, "sleep", lambda *args: None)
    monkeypatch.setattr(operations_cli, "_az", lambda *args, **kwargs: calls.append(args) or subprocess.CompletedProcess(args, 0))

    operations_cli.deploy_function()

    settings = next(call for call in calls if call[:4] == ("functionapp", "config", "appsettings", "set"))
    assert f"DEFENDER_API_BASE_URL={expected}" in settings
    assert "COLLECTOR_VERSION=2026.10.19.3" in settings


def test_function_deploy_rejects_base_uri_containing_a_dataset_path(monkeypatch):
    monkeypatch.setattr(operations_cli, "_values", lambda: {"defender_api_base_url": "https://api-us3.securitycenter.microsoft.com/api/vulnerabilities?$top=10"})
    monkeypatch.setattr(operations_cli, "_az", lambda *args, **kwargs: pytest.fail("Invalid base URI must not modify Azure"))

    with pytest.raises(ValueError, match="without a path or query"):
        operations_cli.deploy_function()


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
