import json
from pathlib import Path

from azure.core.exceptions import ResourceNotFoundError

import function_app


def test_run_dataprep_uses_temporary_writable_workspace(monkeypatch):
    original_directory = Path.cwd()
    observed: dict[str, Path] = {}

    def fake_main(arguments: list[str]) -> int:
        observed["work_root"] = Path.cwd()
        assert arguments == ["collect-live", "--skip-local-exports", "--collection", "auto", "--enrichment", "auto"]
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
        assert arguments == ["collect-live", "--skip-local-exports", "--collection", "auto", "--enrichment", "auto"]
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
    monkeypatch.setattr(function_app, "_run_dataprep", lambda collection, enrichment: calls.append((collection, enrichment)) or 0)

    function_app.dataprep_full_snapshot("full")

    assert calls == [("full", "full")]


def test_manual_trigger_uses_scheduled_collection_policy(monkeypatch):
    calls = []
    monkeypatch.setattr(function_app, "_run_dataprep", lambda: calls.append(()) or 0)

    function_app.dataprep_manual_snapshot("")

    assert calls == [()]


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
