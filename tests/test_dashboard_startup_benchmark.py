import json
import subprocess
import time
from unittest.mock import Mock

import pytest

import benchmark_dashboard_startup as benchmark
from benchmark_dashboard_queries import generate_data
from vulnerability_view.dataset_io import iter_json_rows


def small_args(tmp_path, *extra):
    return [
        "--rows", "80", "--events", "80", "--devices", "7", "--cves", "17",
        "--recommendations", "5", "--output-dir", str(tmp_path), *extra,
    ]


def report_in(tmp_path):
    paths = list(tmp_path.glob("*/results.json"))
    assert len(paths) == 1
    return paths[0], json.loads(paths[0].read_text())


@pytest.fixture
def children(monkeypatch):
    processes = []
    popen = subprocess.Popen

    def record(*args, **kwargs):
        child = popen(*args, **kwargs)
        if "--serve-root" in args[0]:
            processes.append(child)
        return child

    monkeypatch.setattr(benchmark.subprocess, "Popen", record)
    yield processes
    assert all(process.poll() is not None for process in processes)


def test_shared_generator_cardinalities_and_lifecycle(tmp_path):
    generate_data(tmp_path, 80, 83, True, devices=7, cves=17, recommendations=5, run_id="unique-test")
    findings = list(iter_json_rows(tmp_path / "findings.json.gz"))
    events = list(iter_json_rows(tmp_path / "finding-events.json.gz"))
    assert len(findings) == 80
    assert len(events) == 83
    for field, expected in (("DeviceId", 7), ("CveId", 17), ("RecommendationId", 5), ("FindingStatus", 4)):
        assert len({row[field] for row in findings}) == expected
    assert {row["FindingStatus"] for row in findings} == {"Fixed", "PendingVerification", "Reopened", "Open"}
    assert {row["CollectionRunId"] for row in findings + events} == {"unique-test"}
    assert len(list(iter_json_rows(tmp_path / "devices.json.gz"))) == 7
    assert len(list(iter_json_rows(tmp_path / "recommendations.json.gz"))) == 5
    assert {row["FindingKey"] for row in events} == {row["FindingKey"] for row in findings}


def test_original_generator_defaults_remain_compatible(tmp_path):
    generate_data(tmp_path, 4, 0)
    findings = list(iter_json_rows(tmp_path / "findings.json.gz"))
    assert all(row["FindingStatus"] == "Open" and row["CollectionRunId"] == "benchmark" for row in findings)
    assert len(list(iter_json_rows(tmp_path / "devices.json.gz"))) == 2000
    assert len(list(iter_json_rows(tmp_path / "recommendations.json.gz"))) == 20
    assert list(iter_json_rows(tmp_path / "finding-events.json.gz")) == []
    assert len(list(tmp_path.glob("*.json.gz"))) == 13


def test_child_environment_excludes_cloud_and_inherited_local_settings(tmp_path, monkeypatch):
    for key in ("AZURE_CLIENT_SECRET", "WEBSITE_HOSTNAME", "IDENTITY_ENDPOINT", "MSI_ENDPOINT", "STORAGE_ACCOUNT_NAME"):
        monkeypatch.setenv(key, "must-not-inherit")
    monkeypatch.setenv("DASHBOARD_DATA_SOURCE", "azure")
    monkeypatch.setenv("DASHBOARD_AUTH_ENABLED", "true")
    monkeypatch.setenv("DASHBOARD_STATIC_DIR", "must-not-inherit")
    monkeypatch.setenv("AUTH_MODE", "client_secret")
    environment = benchmark.child_environment(tmp_path)
    assert not any(key.startswith(("AZURE_", "WEBSITE_", "IDENTITY_", "MSI_", "STORAGE_")) for key in environment)
    assert environment["DASHBOARD_DATA_SOURCE"] == "local"
    assert environment["DASHBOARD_AUTH_ENABLED"] == "false"
    assert environment["DASHBOARD_BRANDING_ENABLED"] == "false"
    assert environment["DASHBOARD_RECOMMENDATION_TRACKING_ENABLED"] == "false"
    assert environment["AUTH_MODE"] == "managed_identity"
    assert "DASHBOARD_STATIC_DIR" not in environment
    assert environment["TMPDIR"] == str(tmp_path)


@pytest.mark.skipif(benchmark.sys.platform not in {"darwin", "linux"}, reason="Peak RSS requires macOS or Linux")
def test_real_uvicorn_two_cold_starts_verify_views_counts_and_cleanup(tmp_path, monkeypatch, children):
    monkeypatch.setenv("DASHBOARD_DATA_SOURCE", "azure")
    monkeypatch.setenv("DASHBOARD_AUTH_ENABLED", "true")
    monkeypatch.setenv("WEBSITE_HOSTNAME", "not-a-real-host")
    monkeypatch.setenv("STORAGE_ACCOUNT_NAME", "must-not-use")
    assert benchmark.main(small_args(tmp_path, "--runs", "2")) == 0
    path, report = report_in(tmp_path)
    assert report["schemaVersion"] == 1
    assert report["status"] == "passed"
    assert report["scenario"] == {
        "findings": 80, "findingEvents": 80, "devices": 7, "distinctFindingCves": 17,
        "recommendations": 5, "mixedLifecycle": True, "trackingEnabled": False, "coldStarts": 2,
    }
    assert len(children) == len(report["runs"]) == 2
    assert len({run["pid"] for run in report["runs"]}) == 2
    assert report["generationSeconds"] > 0
    assert report["datasetBytes"] > 0
    assert report["host"]["resourceLimitsApplied"] is False
    for run in report["runs"]:
        assert run["status"] == "ready"
        assert 0 < run["startupSeconds"] < 30
        assert run["peakRssMiB"] > 0
        assert run["cpuSeconds"] > 0
        assert run["returncode"] in (0, -benchmark.signal.SIGTERM) and not run["forcedKill"]
        assert set(run["verifiedViews"]) == set(benchmark.PREPARED_VIEWS)
        assert run["preparedViewSeconds"] == {}
        assert 0 <= run["workspaceIndexSeconds"] <= run["startupSeconds"] + .1
        assert run["loadedRows"]["findings"] == run["loadedRows"]["finding-events"] == 80
        assert run["snapshot"]["runId"] == report["runId"]
        assert run["diagnostics"]["dashboardQueries"]["preparation"]["status"] == "ready"
        log = (path.parent / run["logFile"]).read_text()
        assert "[dashboard-startup] end outcome=ready" in log
        assert "Application shutdown complete" in log
    assert not list(path.parent.glob("data-*"))
    assert not list(path.parent.glob("worker-*"))


def test_timeout_retains_report_and_log_and_stops_child(tmp_path, children):
    assert benchmark.main(small_args(tmp_path, "--timeout-seconds", "0.001")) == 1
    path, report = report_in(tmp_path)
    assert report["status"] == "failed"
    run = report["runs"][0]
    assert run["status"] == "timeout"
    assert "exceeded" in run["error"]
    assert (path.parent / run["logFile"]).exists()
    assert len(children) == 1
    assert not list(path.parent.glob("data-*"))
    assert not list(path.parent.glob("worker-*"))


@pytest.mark.skipif(benchmark.sys.platform not in {"darwin", "linux"}, reason="Peak RSS requires macOS or Linux")
def test_rss_threshold_is_enforced_and_stops_remaining_runs(tmp_path, children):
    assert benchmark.main(small_args(tmp_path, "--max-rss-mib", "0.001", "--runs", "2")) == 1
    _, report = report_in(tmp_path)
    assert report["status"] == "failed"
    assert len(report["runs"]) == len(children) == 1
    assert report["runs"][0]["peakRssMiB"] > 0.001
    assert "acceptance threshold" in report["runs"][0]["error"]


def test_actual_startup_failure_is_not_readiness(tmp_path, children):
    root = tmp_path / "broken"
    source = root / "dashboard/data"
    source.mkdir(parents=True)
    (source / "findings.json").write_text("{")
    result = benchmark.run_cold_start(root, tmp_path, 1, "test", 80, 80, 30, 512)
    assert result["status"] == "failed"
    assert "data preparation failed" in result["error"]
    assert "Dashboard preparation failed" in (tmp_path / result["logFile"]).read_text()
    assert len(children) == 1
    assert not list(tmp_path.glob("worker-*"))


def test_force_kill_is_bounded():
    process = Mock(spec=subprocess.Popen)
    process.poll.return_value = None
    process.wait.side_effect = [subprocess.TimeoutExpired("test", 10), 0]
    assert benchmark.stop_process(process) is True
    process.terminate.assert_called_once()
    process.kill.assert_called_once()
    assert process.wait.call_count == 2


@pytest.mark.parametrize("extra", [
    ["--rows", "0"], ["--events", "-1"], ["--cves", "81"], ["--runs", "0"],
    ["--timeout-seconds", "nan"], ["--max-rss-mib", "inf"],
])
def test_invalid_scenario_is_rejected_before_generating_data(tmp_path, extra):
    with pytest.raises(SystemExit) as error:
        benchmark.main(small_args(tmp_path, *extra))
    assert error.value.code == 2
    assert not list(tmp_path.iterdir())


def test_startup_evidence_requires_shared_indexes_without_reports_and_exact_ingestion_counts():
    log = "stage=prepare-workspace-indexes event=complete elapsedSeconds=1.2 rows=unavailable"
    log += "\nstage=load-rows:findings event=complete elapsedSeconds=1.0 rows=80"
    log += "\nstage=load-rows:finding-events event=complete elapsedSeconds=1.0 rows=80"
    assert benchmark.startup_evidence(log, 80, 80)["loadedRows"] == {"findings": 80, "finding-events": 80}
    assert benchmark.startup_evidence(log, 80, 80)["workspaceIndexSeconds"] == 1.2
    with pytest.raises(ValueError, match="shared-index readiness"):
        benchmark.startup_evidence(log.replace("event=complete", "event=failed"), 80, 80)
    with pytest.raises(ValueError, match="without report preparation"):
        benchmark.startup_evidence(
            log + "\nstage=view:executive:1/9 event=complete elapsedSeconds=1.2", 80, 80,
        )
    with pytest.raises(ValueError, match="ingestion counts"):
        benchmark.startup_evidence(log, 81, 80)


@pytest.mark.parametrize("wrong", ["health", "run", "snapshot", "preparation"])
def test_readiness_does_not_accept_wrong_or_unprepared_snapshot(monkeypatch, wrong):
    health = {"dataSource": "local", "dashboardReady": wrong != "health"}
    snapshot = {"snapshotId": "snapshot", "runId": "wrong" if wrong == "run" else "test"}
    preparation = {
        "status": "preparing" if wrong == "preparation" else "ready",
        "readySnapshotId": "wrong" if wrong == "snapshot" else "snapshot",
    }
    monkeypatch.setattr(benchmark, "request_json", Mock(side_effect=[
        health, snapshot, {"dashboardQueries": {"preparation": preparation}},
    ]))
    with pytest.raises(ValueError):
        benchmark.verify_ready(Mock(), "http://127.0.0.1:123", "test", time.perf_counter() + 30)


def test_expired_deadline_does_not_send_a_request():
    session = Mock()
    with pytest.raises(TimeoutError, match="deadline"):
        benchmark.request_json(session, "http://127.0.0.1:123/api/health", deadline=0, method="GET")
    session.request.assert_not_called()


@pytest.mark.parametrize("error,code,status", [
    (OSError("test disk failure"), 1, "failed"),
    (KeyboardInterrupt(), 130, "interrupted"),
])
def test_generation_failure_or_interruption_retains_report_and_cleans_data(tmp_path, monkeypatch, error, code, status):
    monkeypatch.setattr(benchmark, "generate_data", Mock(side_effect=error))
    assert benchmark.main(small_args(tmp_path)) == code
    path, report = report_in(tmp_path)
    assert report["status"] == status
    assert report["error"]
    assert report["runs"] == []
    assert not list(path.parent.glob("data-*"))
