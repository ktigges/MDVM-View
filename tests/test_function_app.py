import json
import importlib
import inspect
import asyncio
from pathlib import Path
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from typing import get_type_hints
import subprocess
import sys

import pytest
import requests
from azure.core.exceptions import ResourceNotFoundError

import function_app
from vulnerability_view import collection_diagnostics


@pytest.fixture(autouse=True)
def local_manual_diagnostics(monkeypatch, tmp_path):
    recorder_type = collection_diagnostics.CollectionDiagnostics
    monkeypatch.setattr(
        collection_diagnostics, "CollectionDiagnostics",
        lambda identifier, settings: recorder_type(identifier, function_app.Settings(), root=tmp_path, flush_seconds=0.01),
    )


@pytest.fixture
def invocation_context():
    return Mock(spec=function_app.func.Context, invocation_id="11111111-2222-3333-4444-555555555555")


@pytest.fixture
def durable_client():
    return Mock(get_status=AsyncMock(return_value=None))


def async_handler(builder):
    return inspect.unwrap(builder._function.get_user_function())


def test_function_execution_timeout_is_four_hours():
    host = json.loads(Path(function_app.__file__).with_name("host.json").read_text())
    hours, minutes, seconds = map(int, host["functionTimeout"].split(":"))
    assert hours * 3600 + minutes * 60 + seconds == 14400


def test_host_logging_suppresses_coordination_noise_but_keeps_collection_progress():
    host = json.loads(Path(function_app.__file__).with_name("host.json").read_text())
    levels = host["logging"]["logLevel"]
    assert levels["default"] == "Information"
    assert levels["Function"] == "Information"
    for category in ("DurableTask", "Host.Triggers.DurableTask", "Azure"):
        assert levels[category] == "Warning"
    assert not any(
        category.startswith(("Function.", "DurableTask.", "Azure.", "Host.Triggers.DurableTask."))
        for category in levels
    )


def test_manual_context_annotations_match_azure_worker_contract():
    functions = function_app.app.get_functions()
    checked = set()
    for function in functions:
        if function.get_function_name() in {"dataprep_manual_snapshot", "dataprep_full_snapshot"}:
            signature = inspect.signature(function.get_user_function())
            assert signature.parameters["context"].annotation is function_app.func.Context
            checked.add(function.get_function_name())
    assert checked == {"dataprep_manual_snapshot", "dataprep_full_snapshot"}


def test_all_function_app_annotations_resolve_on_eager_annotation_runtimes():
    from azure.durable_functions.models.DurableOrchestrationStatus import DurableOrchestrationStatus

    assert get_type_hints(function_app._workflow_status)["workflow"] is DurableOrchestrationStatus
    for value in vars(function_app).values():
        if inspect.isfunction(value) and value.__module__ == function_app.__name__:
            get_type_hints(value)
    subprocess.run([
        sys.executable, "-c",
        "import function_app; from typing import get_type_hints; "
        "functions = function_app.app.get_functions(); "
        "assert len(functions) == 12; "
        "[get_type_hints(f.get_user_function()) for f in functions]",
    ], check=True, capture_output=True, text=True)


def test_function_runtime_version_comes_from_packaged_source_not_old_app_settings(monkeypatch):
    expected = json.loads(Path(function_app.__file__).with_name("function-version.json").read_text())["version"]
    monkeypatch.setenv("COLLECTOR_VERSION", "2026.10.11.2")
    monkeypatch.setenv("FUNCTION_VERSION", "2026.10.11.2")

    importlib.reload(function_app)

    assert function_app.COLLECTOR_VERSION == expected


def test_run_dataprep_uses_temporary_writable_workspace(monkeypatch):
    original_directory = Path.cwd()
    observed: dict[str, Path] = {}

    def fake_main(arguments: list[str]) -> int:
        observed["work_root"] = Path.cwd()
        assert arguments == ["collect-live", "--skip-local-exports", "--collection", "auto", "--enrichment", "auto", "--page-size", "2500"]
        assert observed["work_root"].parent == Path("/tmp").resolve()
        assert (observed["work_root"] / "config/sla-policies.json").is_file()
        output = observed["work_root"] / "output/raw/live-test"
        output.mkdir(parents=True)
        (output / "page.json").write_text("{}")
        return 0

    monkeypatch.setattr(function_app, "main", fake_main)

    assert function_app._run_dataprep() == 0
    assert Path.cwd() == original_directory
    assert not observed["work_root"].exists()


def test_run_dataprep_restores_directory_after_failure(monkeypatch):
    original_directory = Path.cwd()

    def failing_main(arguments: list[str]) -> int:
        assert arguments == ["collect-live", "--skip-local-exports", "--collection", "auto", "--enrichment", "auto", "--page-size", "2500"]
        raise RuntimeError("collection failed")

    monkeypatch.setattr(function_app, "main", failing_main)

    try:
        function_app._run_dataprep()
    except RuntimeError as error:
        assert str(error) == "collection failed"
    else:
        raise AssertionError("Expected collection failure")

    assert Path.cwd() == original_directory


def test_manual_full_trigger_forces_full_collection_and_enrichment(monkeypatch, invocation_context, durable_client):
    start = AsyncMock()
    monkeypatch.setattr(function_app, "start_collection", start)

    asyncio.run(async_handler(function_app.dataprep_full_snapshot)("full", invocation_context, durable_client))

    start.assert_awaited_once_with(durable_client, {"collection": "full", "enrichment": "full", "pageSize": 2500})


def test_manual_trigger_uses_scheduled_collection_policy(monkeypatch, invocation_context, durable_client):
    start = AsyncMock()
    monkeypatch.setattr(function_app, "start_collection", start)

    asyncio.run(async_handler(function_app.dataprep_manual_snapshot)("", invocation_context, durable_client))

    start.assert_awaited_once_with(durable_client, {"collection": "auto", "enrichment": "auto", "pageSize": 2500})


def test_manual_collection_accepts_2500_but_debug_stays_capped(monkeypatch, invocation_context, durable_client):
    start = AsyncMock()
    monkeypatch.setattr(function_app, "start_collection", start)
    asyncio.run(async_handler(function_app.dataprep_manual_snapshot)('{"pageSize":2500}', invocation_context, durable_client))
    asyncio.run(async_handler(function_app.dataprep_full_snapshot)('{"pageSize":2500}', invocation_context, durable_client))
    assert [call.args[1]["pageSize"] for call in start.await_args_list] == [2500, 2500]
    with pytest.raises(ValueError, match="1 to 1000"):
        function_app.dataprep_debug_page('{"pageSize":2500}')
    with pytest.raises(ValueError, match="1 to 2500"):
        asyncio.run(async_handler(function_app.dataprep_manual_snapshot)('{"pageSize":2501}', invocation_context, durable_client))


@pytest.mark.parametrize("page_size", [1, 100, 1000])
def test_manual_triggers_forward_per_run_page_size(monkeypatch, page_size, invocation_context, durable_client):
    calls = []
    monkeypatch.setattr(function_app, "_run_dataprep", lambda *args, **kwargs: calls.append((args, kwargs)) or 0)
    start = AsyncMock()
    monkeypatch.setattr(function_app, "start_collection", start)
    payload = json.dumps({"pageSize": page_size})

    asyncio.run(async_handler(function_app.dataprep_manual_snapshot)(payload, invocation_context, durable_client))
    asyncio.run(async_handler(function_app.dataprep_full_snapshot)(payload, invocation_context, durable_client))
    function_app.dataprep_debug_page(payload)

    assert calls == [
        ((), {"page_size": page_size, "debug": True, "debug_endpoint": "machine_vulnerabilities"}),
    ]
    assert [call.args[1]["pageSize"] for call in start.await_args_list] == [page_size, page_size]


@pytest.mark.parametrize("payload", ['{"pageSize":0}', '{"pageSize":1001}', '{"pageSize":true}', '{"pageSize":1.5}', "[]", "not-json"])
def test_manual_trigger_rejects_invalid_input_before_collection(monkeypatch, payload):
    monkeypatch.setattr(function_app, "_run_dataprep", lambda *args, **kwargs: pytest.fail("Invalid input must not collect"))

    with pytest.raises(ValueError):
        function_app.dataprep_debug_page(payload)


def test_debug_trigger_defaults_to_one_record(monkeypatch):
    calls = []
    monkeypatch.setattr(function_app, "_run_dataprep", lambda **kwargs: calls.append(kwargs) or 0)

    function_app.dataprep_debug_page("")

    assert calls == [{"page_size": 1, "debug": True, "debug_endpoint": "machine_vulnerabilities"}]


def test_debug_dataprep_bypasses_workspace_and_publication(monkeypatch):
    calls = []
    monkeypatch.setattr(function_app, "main", lambda args: calls.append(args) or 0)
    monkeypatch.setattr(function_app.tempfile, "TemporaryDirectory", lambda **kwargs: pytest.fail("Debug must not create a collection workspace"))

    assert function_app._run_dataprep(page_size=1, debug=True) == 0
    assert calls == [["probe-live", "--page-size", "1", "--endpoint", "machine_vulnerabilities"]]


def test_debug_function_logs_actual_successful_api_result(monkeypatch, caplog, capsys):
    from vulnerability_view import dataprep_cli

    class Credential:
        def get_token(self, scope):
            return type("Token", (), {"token": "not-a-real-token"})()

    caplog.set_level("INFO")
    monkeypatch.setattr(dataprep_cli.Settings, "load", lambda *args: function_app.Settings(defender_api_base_url="https://example.test"))
    monkeypatch.setattr(dataprep_cli, "_create_credential", lambda settings: Credential())
    result = requests.Response()
    result.status_code = 200
    result._content = b'{"value":[{"id":"finding"}]}'
    monkeypatch.setattr(requests.Session, "get", lambda *args, **kwargs: result)
    monkeypatch.setattr(function_app.tempfile, "TemporaryDirectory", lambda **kwargs: pytest.fail("Debug must not create a collection workspace"))

    function_app.dataprep_debug_page('{"endpoint":"vulnerabilities","pageSize":1}')

    assert "[debug] PASSED: API call returned HTTP 200" in caplog.text
    assert "endpoint=vulnerabilities; 1 rows received" in caplog.text
    assert '"Status": "PASSED"' in capsys.readouterr().out
    assert "not-a-real-token" not in caplog.text


@pytest.fixture
def http_debug_context(monkeypatch):
    class Credential:
        def get_token(self, scope):
            return type("Token", (), {"token": "not-a-real-token"})()

    calls = []
    result = requests.Response()
    result.status_code = 200
    result._content = b'{"value":[{"id":"finding","machineId":"device-1"}]}'
    monkeypatch.setattr(function_app.Settings, "load", lambda: function_app.Settings(defender_api_base_url="https://api-us3.securitycenter.microsoft.com"))
    monkeypatch.setattr(function_app, "create_credential", lambda *args: Credential())
    def get(self, url, **kwargs):
        calls.append((url, kwargs))
        if "/api/machines?" in url:
            inventory = requests.Response()
            inventory.status_code = 200
            inventory._content = b'{"value":[{"id":"device-1","computerDnsName":"debug-device"}]}'
            return inventory
        return result

    monkeypatch.setattr(requests.Session, "get", get)
    monkeypatch.setattr(function_app.tempfile, "TemporaryDirectory", lambda **kwargs: pytest.fail("Debug must not create a collection workspace"))
    monkeypatch.setattr(function_app, "download_current_manifest", lambda *args: pytest.fail("Debug must not access snapshot Storage"))
    return calls, result


@pytest.mark.parametrize("endpoint", ["machine_vulnerabilities", "vulnerabilities"])
@pytest.mark.parametrize("empty", [False, True])
def test_http_debug_returns_actual_api_result_without_logs_or_storage(http_debug_context, endpoint, empty):
    calls, result = http_debug_context
    if empty:
        result._content = b'{"value":[]}'
    request = function_app.func.HttpRequest(
        method="POST", url="https://func-test.azurewebsites.net/api/debug-page",
        body=json.dumps({"endpoint": endpoint, "pageSize": 1}).encode(),
    )

    response = function_app.dataprep_debug_http(request)

    report = json.loads(response.get_body())
    assert response.status_code == 200
    assert report["Status"] == "PASSED"
    assert report["HttpStatus"] == 200
    assert report["Endpoint"] == endpoint
    assert report["RowCount"] == (0 if empty else 1)
    assert report["CollectorVersion"] == function_app.COLLECTOR_VERSION
    assert len(calls) == (2 if endpoint == "machine_vulnerabilities" else 1)
    assert report["RequestCount"] == len(calls)
    assert report["RequestUrl"] == calls[-1][0]
    assert calls[0][1]["timeout"] == (10, 90)
    assert "not-a-real-token" not in response.get_body().decode()


@pytest.mark.parametrize("body", [b"not JSON", b"[]", b'{"pageSize":0}', b'{"pageSize":true}', b'{"endpoint":"invalid"}'])
def test_http_debug_rejects_invalid_input_without_calling_defender(http_debug_context, body):
    calls, _ = http_debug_context
    request = function_app.func.HttpRequest(method="POST", url="https://func-test/api/debug-page", body=body)

    response = function_app.dataprep_debug_http(request)

    assert response.status_code == 400
    assert json.loads(response.get_body())["Status"] == "FAILED"
    assert calls == []


@pytest.mark.parametrize("status", [401, 403, 429, 503])
def test_http_debug_reports_defender_failure_without_retrying(http_debug_context, status):
    calls, result = http_debug_context
    result.status_code = status
    request = function_app.func.HttpRequest(method="POST", url="https://func-test/api/debug-page", body=b'{"pageSize":1}')

    response = function_app.dataprep_debug_http(request)

    assert response.status_code == 502
    report = json.loads(response.get_body())
    assert report["Status"] == "FAILED"
    assert str(status) in report["Error"]
    assert len(calls) == 2


def test_http_debug_returns_timeout_as_failed_api_test(http_debug_context, monkeypatch):
    def get(*args, **kwargs):
        raise requests.ReadTimeout("Defender response timed out")

    monkeypatch.setattr(requests.Session, "get", get)
    request = function_app.func.HttpRequest(method="POST", url="https://func-test/api/debug-page", body=b'{"pageSize":1}')

    response = function_app.dataprep_debug_http(request)

    assert response.status_code == 504
    report = json.loads(response.get_body())
    assert report["Status"] == "FAILED"
    assert report["ErrorType"] == "ReadTimeout"


@pytest.mark.parametrize("endpoint", ["machine_vulnerabilities", "vulnerabilities"])
def test_debug_menu_receives_same_invocations_actual_api_result(http_debug_context, monkeypatch, capsys, endpoint):
    from vulnerability_view import operations_cli

    calls, _ = http_debug_context
    monkeypatch.setattr(operations_cli, "_tf_output", lambda name: {"resource_group_name": "rg-test", "function_app_name": "func-test"}[name])
    monkeypatch.setattr(operations_cli, "_az", lambda *args, **kwargs: type("Result", (), {"stdout": "host-key\n"})())
    monkeypatch.setattr(operations_cli, "_workspace_context", lambda: pytest.fail("Debug does not require Log Analytics access"))

    def post(url, **kwargs):
        assert url == "https://func-test.azurewebsites.net/api/debug-page"
        assert kwargs["headers"] == {"x-functions-key": "host-key"}
        request = function_app.func.HttpRequest(method="POST", url=url, body=json.dumps(kwargs["json"]).encode())
        response = function_app.dataprep_debug_http(request)
        result = requests.Response()
        result.status_code = response.status_code
        result._content = response.get_body()
        return result

    monkeypatch.setattr(requests, "post", post)

    operations_cli.invoke(True, debug=True, page_size=1, endpoint=endpoint)

    output = capsys.readouterr().out
    assert "DEBUG RESULT: PASSED" in output
    assert "Defender HTTP status: 200" in output
    assert "Rows returned: 1 (requested up to 1)" in output
    assert calls[-1][0] in output
    assert f"Function collector version: {function_app.COLLECTOR_VERSION}" in output
    assert len(calls) == (2 if endpoint == "machine_vulnerabilities" else 1)
    if endpoint == "machine_vulnerabilities":
        assert "Selected machine: debug-device (Defender ID: device-1)" in output
    assert "host-key" not in output


@pytest.mark.parametrize("payload", ['{"pageSize":1000,"endpoint":"vulnerabilities"}', '{"endpoint":"vulnerabilities"}'])
def test_debug_trigger_forwards_catalog_selection(monkeypatch, payload):
    calls = []
    monkeypatch.setattr(function_app, "_run_dataprep", lambda **kwargs: calls.append(kwargs) or 0)

    function_app.dataprep_debug_page(payload)

    assert calls == [{"page_size": 1000, "debug": True, "debug_endpoint": "vulnerabilities"}]


def test_debug_trigger_rejects_unknown_route(monkeypatch):
    monkeypatch.setattr(function_app, "_run_dataprep", lambda **kwargs: pytest.fail("Invalid endpoint must not execute"))

    with pytest.raises(ValueError, match="Debug endpoint"):
        function_app.dataprep_debug_page('{"pageSize":1,"endpoint":"not-a-route"}')


def test_current_run_status_summarizes_manifest(monkeypatch):
    monkeypatch.setattr(
        function_app.Settings,
        "load",
        lambda: function_app.Settings(storage_account_name="history-account"),
    )
    monkeypatch.setattr(function_app, "create_credential", lambda *args: "credential")
    monkeypatch.setattr(
        function_app,
        "download_current_manifest",
        lambda *args: {
            "runId": "live-20261014T163757Z",
            "snapshotTimeUtc": "2026-10-14T16:37:57Z",
            "endpointStatuses": [
                {"Endpoint": "machines", "Status": "Success"},
                {"Endpoint": "optional", "Status": "Skipped"},
            ],
            "files": [
                {"dataset": "findings", "rowCount": 19638},
                {"dataset": "recommendations", "rowCount": 147},
            ],
        },
    )

    assert function_app._current_run_status() == {
        "published": True,
        "runId": "live-20261014T163757Z",
        "snapshotTimeUtc": "2026-10-14T16:37:57Z",
        "status": "PartialSuccess",
        "findings": 19638,
        "publishedFiles": 2,
        "reportedIssues": 1,
    }


def test_status_endpoint_returns_not_found_before_first_publication(monkeypatch, durable_client):
    monkeypatch.setattr(
        function_app,
        "_current_run_status",
        lambda: (_ for _ in ()).throw(ResourceNotFoundError("missing")),
    )

    response = asyncio.run(async_handler(function_app.dataprep_status)(None, durable_client))

    assert response.status_code == 404
    assert json.loads(response.get_body()) == {
        "published": False,
        "reason": "No current manifest has been published",
    }


def test_status_endpoint_reports_lookup_failure_without_details(monkeypatch, caplog, durable_client):
    monkeypatch.setattr(
        function_app,
        "_current_run_status",
        lambda: (_ for _ in ()).throw(RuntimeError("sensitive failure")),
    )

    response = asyncio.run(async_handler(function_app.dataprep_status)(None, durable_client))

    assert response.status_code == 500
    assert json.loads(response.get_body()) == {
        "published": False,
        "reason": "Status lookup failed",
    }
    assert "Failed to read current publication status" in caplog.text


def test_status_reports_checkpointed_work_before_first_publication(monkeypatch, durable_client):
    now = datetime(2026, 10, 23, 16, tzinfo=UTC)
    durable_client.get_status.return_value = SimpleNamespace(
        instance_id="vulnerability-collection", runtime_status=SimpleNamespace(value="Running"),
        created_time=now, last_updated_time=now,
        custom_status={"phase": "process", "stage": "reconcile", "runId": "live-20261023T160000Z"},
    )

    def unpublished():
        raise ResourceNotFoundError("no current manifest")

    monkeypatch.setattr(function_app, "_current_run_status", unpublished)
    response = asyncio.run(async_handler(function_app.dataprep_status)(None, durable_client))
    body = json.loads(response.get_body())
    assert response.status_code == 404
    assert body["published"] is False
    assert body["workflow"]["state"] == "Running"
    assert body["workflow"]["progress"]["stage"] == "reconcile"


def test_timer_starts_bounded_workflow_instead_of_collecting_inline(monkeypatch, durable_client):
    start = AsyncMock()
    monkeypatch.setattr(function_app, "start_collection", start)
    monkeypatch.setattr(function_app, "_run_dataprep", lambda *args, **kwargs: pytest.fail("timer must not collect inline"))
    asyncio.run(async_handler(function_app.dataprep_snapshot)(None, durable_client))
    start.assert_awaited_once_with(
        durable_client, {"collection": "auto", "enrichment": "auto", "pageSize": 2500},
    )
