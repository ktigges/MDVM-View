import json
from pathlib import Path

import pytest
import requests
from azure.core.exceptions import ResourceNotFoundError

import function_app


def test_run_dataprep_uses_temporary_writable_workspace(monkeypatch):
    original_directory = Path.cwd()
    observed: dict[str, Path] = {}

    def fake_main(arguments: list[str]) -> int:
        observed["work_root"] = Path.cwd()
        assert arguments == ["collect-live", "--skip-local-exports", "--collection", "auto", "--enrichment", "auto", "--page-size", "1000"]
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
        assert arguments == ["collect-live", "--skip-local-exports", "--collection", "auto", "--enrichment", "auto", "--page-size", "1000"]
        raise RuntimeError("collection failed")

    monkeypatch.setattr(function_app, "main", failing_main)

    try:
        function_app._run_dataprep()
    except RuntimeError as error:
        assert str(error) == "collection failed"
    else:
        raise AssertionError("Expected collection failure")

    assert Path.cwd() == original_directory


def test_manual_full_trigger_forces_full_collection_and_enrichment(monkeypatch):
    calls = []
    monkeypatch.setattr(function_app, "_run_dataprep", lambda collection, enrichment, **kwargs: calls.append((collection, enrichment, kwargs)) or 0)

    function_app.dataprep_full_snapshot("full")

    assert calls == [("full", "full", {"page_size": 1000})]


def test_manual_trigger_uses_scheduled_collection_policy(monkeypatch):
    calls = []
    monkeypatch.setattr(function_app, "_run_dataprep", lambda **kwargs: calls.append(kwargs) or 0)

    function_app.dataprep_manual_snapshot("")

    assert calls == [{"page_size": 1000}]


@pytest.mark.parametrize("page_size", [1, 100, 1000])
def test_manual_triggers_forward_per_run_page_size(monkeypatch, page_size):
    calls = []
    monkeypatch.setattr(function_app, "_run_dataprep", lambda *args, **kwargs: calls.append((args, kwargs)) or 0)
    payload = json.dumps({"pageSize": page_size})

    function_app.dataprep_manual_snapshot(payload)
    function_app.dataprep_full_snapshot(payload)
    function_app.dataprep_debug_page(payload)

    assert calls == [
        ((), {"page_size": page_size}),
        (("full", "full"), {"page_size": page_size}),
        ((), {"page_size": page_size, "debug": True, "debug_endpoint": "machine_vulnerabilities"}),
    ]


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


def test_status_endpoint_returns_not_found_before_first_publication(monkeypatch):
    monkeypatch.setattr(
        function_app,
        "_current_run_status",
        lambda: (_ for _ in ()).throw(ResourceNotFoundError("missing")),
    )

    response = function_app.dataprep_status(None)

    assert response.status_code == 404
    assert json.loads(response.get_body()) == {
        "published": False,
        "reason": "No current manifest has been published",
    }


def test_status_endpoint_reports_lookup_failure_without_details(monkeypatch, caplog):
    monkeypatch.setattr(
        function_app,
        "_current_run_status",
        lambda: (_ for _ in ()).throw(RuntimeError("sensitive failure")),
    )

    response = function_app.dataprep_status(None)

    assert response.status_code == 500
    assert json.loads(response.get_body()) == {
        "published": False,
        "reason": "Status lookup failed",
    }
    assert "Failed to read current publication status" in caplog.text
