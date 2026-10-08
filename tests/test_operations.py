import json
from pathlib import Path

from vulnerability_view.config import Settings
from vulnerability_view.dataprep_cli import configuration_report, local_status_report, validate_outputs


def test_configuration_report_is_sanitized_and_reports_effective_auth(monkeypatch):
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "do-not-print-this")
    monkeypatch.delenv("WEBSITE_HOSTNAME", raising=False)
    report = configuration_report(Settings(auth_mode="auto", client_id="managed-client", client_secret="do-not-print-this"))

    assert report["authModeEffective"] == "local"
    assert report["clientIdConfigured"] is True
    assert report["managedIdentityClientIdConfigured"] is False
    assert report["clientSecretConfigured"] is True
    assert report["localDevelopmentOnly"] is False
    assert report["dashboardDataSource"] == "local"
    assert report["dashboardCacheSeconds"] == 30
    assert "do-not-print-this" not in json.dumps(report)


def test_local_status_report_summarizes_datasets_and_manifests(tmp_path: Path):
    data = tmp_path / "dashboard/data"
    data.mkdir(parents=True)
    (data / "findings.json").write_text(json.dumps([
        {"FindingStatus": "Open", "Severity": "Critical", "AssetClass": "AzureCloud", "SubscriptionId": "subscription-1", "DataOrigin": "Live"},
        {"FindingStatus": "PendingConfirmation", "Severity": "High", "AssetClass": "TraditionalIT", "SubscriptionId": "", "DataOrigin": "Live"},
    ]))
    raw = tmp_path / "output/raw/live-20260921T000000Z"
    raw.mkdir(parents=True)
    history = tmp_path / "output/history/live-20260921T000000Z"
    history.mkdir(parents=True)
    (history / "manifest.json").write_text(json.dumps({
        "runId": history.name,
        "snapshotTimeUtc": "2026-09-21T00:00:00Z",
        "complete": True,
        "schemaVersion": 1,
        "normalizationVersion": 2,
        "slaPolicyVersion": "policy-v1",
        "files": [{"path": "one"}],
    }))

    report = local_status_report(tmp_path)

    assert report["datasets"]["findings"] == 2
    assert report["lifecycleCounts"] == {"Open": 1, "PendingConfirmation": 1}
    assert report["currentDataset"]["severityCounts"] == {"Critical": 1, "High": 1}
    assert report["currentDataset"]["assetClassCounts"] == {"AzureCloud": 1, "TraditionalIT": 1}
    assert report["currentDataset"]["subscriptionCounts"] == {"(blank)": 1, "subscription-1": 1}
    assert report["currentDataset"]["subscriptionCount"] == 1
    assert report["rawRunCount"] == 1
    assert report["historyRunCount"] == 1
    assert report["recentHistoryRuns"][0]["complete"] is True


def test_function_schedule_is_setting_driven_and_client_secret_is_locally_guarded():
    root = Path(__file__).parents[1]
    function_source = (root / "function_app.py").read_text()
    application_source = "\n".join(path.read_text() for path in (root / "src/vulnerability_view").glob("*.py"))

    assert 'schedule="%COLLECTION_SCHEDULE%"' in function_source
    assert "ClientSecretCredential" in application_source
    assert "Client-secret authentication is restricted to local development" in application_source
    assert "ManagedIdentityCredential" in application_source
    assert "exclude_environment_credential=True" in application_source


def test_run_status_script_supports_macos_system_bash():
    script = Path("infra/check-runs.sh").read_text()

    assert '${SHOW_EXPERIMENTAL,,}' not in script
    assert "mapfile" not in script
    assert 'case "$SHOW_EXPERIMENTAL" in' in script
    assert "while IFS= read -r manifest" in script


def test_validate_outputs_checks_data_quality(tmp_path: Path):
    data = tmp_path / "dashboard/data"
    curated = tmp_path / "output/curated"
    summary = tmp_path / "output/run-summary"
    data.mkdir(parents=True)
    curated.mkdir(parents=True)
    summary.mkdir(parents=True)
    for basename in ("findings", "devices", "recommendations", "remediation-activities", "daily-summary", "collection-runs", "reconciliation"):
        (curated / f"{basename}.csv").write_text("placeholder\n")
        (data / f"{basename}.json").write_text("[]")
    (data / "devices.json").write_text(json.dumps([{"DeviceId": "device-1"}]))
    (data / "findings.json").write_text(json.dumps([
        {"FindingKey": "one", "DeviceId": "device-1", "Severity": "High", "FindingStatus": "Open", "DataOrigin": "Live", "ScenarioId": "live", "SnapshotTimeUtc": "2026-09-21T00:00:00Z", "CollectionRunId": "run"},
        {"FindingKey": "two", "DeviceId": "missing-device", "Severity": "Urgent", "FindingStatus": "Bad", "DataOrigin": "Live", "ScenarioId": "live", "SnapshotTimeUtc": "2026-09-21T00:00:00Z", "CollectionRunId": "run"},
    ]))
    (summary / "latest.json").write_text(json.dumps({"liveRowCounts": {"findings": 3}}))

    errors = validate_outputs(tmp_path)

    assert any("invalid FindingStatus" in error for error in errors)
    assert any("invalid Severity" in error for error in errors)
    assert any("absent from devices.json" in error for error in errors)
    assert any("Row count mismatch for findings" in error for error in errors)
