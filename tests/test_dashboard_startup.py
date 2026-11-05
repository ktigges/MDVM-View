import logging
import subprocess
import sys
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from azure.core.exceptions import HttpResponseError

from vulnerability_view import dashboard_startup as diagnostics
from vulnerability_view.dashboard_queries import DashboardQueryEngine
from test_dashboard_queries import engine


@pytest.mark.parametrize("dataset,indexes", [("findings", 21), ("finding-events", 3)])
def test_each_sqlite_index_and_analyze_exposes_the_real_order_and_plan(tmp_path, monkeypatch, capsys, dataset, indexes):
    query = engine(tmp_path)
    original = DashboardQueryEngine._connect
    monitor = diagnostics.StartupDiagnostics()
    observed, committed = [], []

    @contextmanager
    def connect(self, filters=None):
        with original(self, filters) as db:
            def trace(sql):
                progress = monitor.snapshot()
                plan = progress["indexPlan"]
                if plan is None or plan["dataset"] != dataset:
                    return
                if sql.startswith(("CREATE INDEX", "ANALYZE")):
                    observed.append((sql, progress))
                elif sql == "COMMIT" and monitor.stage.startswith("build-index:"):
                    committed.append(monitor.stage)
            db.set_trace_callback(trace)
            yield db

    monkeypatch.setattr(DashboardQueryEngine, "_connect", connect)
    with diagnostics.startup_diagnostics(monitor):
        query.dataset_info(dataset)
    assert len(observed) == indexes + 1
    assert committed == []
    for position, (sql, progress) in enumerate(observed):
        plan = progress["indexPlan"]
        assert plan["dataset"] == dataset
        assert plan["totalSteps"] == indexes + 1
        assert plan["completedSteps"] == position
        if position < indexes:
            assert progress["stage"].startswith(f"build-index:{dataset}:{position + 1}/{indexes}:")
            assert plan["steps"][position] in sql
        else:
            assert progress["stage"] == f"analyze-indexes:{dataset}"
            assert sql.startswith("ANALYZE")
            assert plan["steps"][position] == "ANALYZE"
    assert monitor.snapshot()["indexPlan"] is None
    output = capsys.readouterr().err
    assert f"index-plan dataset={dataset} totalSteps={indexes + 1}" in output
    assert f"build-index:{dataset}:1/{indexes}:" in output
    assert f"stage=analyze-indexes:{dataset} event=complete" in output


def test_index_plan_heartbeat_and_failure_keep_exact_unfinished_step(capsys):
    monitor = diagnostics.StartupDiagnostics()
    with pytest.raises(OSError):
        with diagnostics.startup_diagnostics(monitor):
            with diagnostics.startup_index_plan("findings", ["first", "second", "ANALYZE"]) as completed:
                with diagnostics.startup_stage("build-index:findings:1/2:first"):
                    pass
                completed()
                with diagnostics.startup_stage("build-index:findings:2/2:second"):
                    monitor.heartbeat()
                    raise OSError("SENSITIVE")
    failure = monitor.snapshot()["failure"]
    assert failure["stage"] == "build-index:findings:2/2:second"
    assert failure["indexPlan"]["completedSteps"] == 1
    assert failure["indexPlan"]["steps"] == ["first", "second", "ANALYZE"]
    assert monitor.index_plan is None
    output = capsys.readouterr().err
    assert "indexSteps=1/3 currentIndexStep=second" in output
    assert "event=failed" in output
    assert "SENSITIVE" not in output


def test_console_output_is_visible_under_default_uvicorn_logging():
    script = """
import logging.config
from uvicorn.config import LOGGING_CONFIG
from vulnerability_view.dashboard_startup import startup_diagnostics, startup_stage
logging.config.dictConfig(LOGGING_CONFIG)
with startup_diagnostics(), startup_stage("manifest-read"):
    pass
"""
    result = subprocess.run(
        [sys.executable, "-c", script], text=True, capture_output=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert "[dashboard-startup] begin" in result.stderr
    assert "stage=manifest-read event=start" in result.stderr
    assert "stage=manifest-read event=complete" in result.stderr
    assert "outcome=ready" in result.stderr
    assert "pid=" in result.stderr


def test_nested_stages_restore_progress_and_do_not_log_rows_or_urls(capsys):
    with diagnostics.startup_diagnostics():
        monitor = diagnostics._ACTIVE.get()
        assert monitor is not None
        with diagnostics.startup_stage("load-rows:findings"):
            diagnostics.startup_rows(256)
            with diagnostics.startup_stage("download:findings"):
                diagnostics.startup_bytes(4096)
                monitor.heartbeat()
                diagnostics.storage_retry(
                    retry_count=0, response=SimpleNamespace(status_code=429),
                    request=SimpleNamespace(url="https://secret.example/?sig=SECRET"),
                )
            assert monitor.stage == "load-rows:findings"
            assert monitor.rows == 256
            assert monitor.bytes is None
            monitor.heartbeat()
    output = capsys.readouterr().err
    assert "downloadedBytes=4096" in output
    assert "rows=256" in output
    assert "storageRetry retry=1 httpStatus=429" in output
    assert "secret.example" not in output
    assert "SECRET" not in output
    assert diagnostics._ACTIVE.get() is None


def test_heartbeat_runs_while_stage_is_waiting_and_stops_after_startup(monkeypatch, capsys):
    monkeypatch.setattr(diagnostics, "HEARTBEAT_SECONDS", 0.01)
    observed = threading.Event()
    original = diagnostics.StartupDiagnostics.heartbeat

    def heartbeat(self):
        original(self)
        observed.set()

    monkeypatch.setattr(diagnostics.StartupDiagnostics, "heartbeat", heartbeat)
    handlers = list(diagnostics.LOGGER.handlers)
    with diagnostics.startup_diagnostics(), diagnostics.startup_stage("manifest-read"):
        assert observed.wait(2)
    assert diagnostics.LOGGER.handlers == handlers
    assert not any(thread.name == "dashboard-startup-diagnostics" for thread in threading.enumerate())
    assert "heartbeat stage=manifest-read" in capsys.readouterr().err


@pytest.mark.parametrize("error", [MemoryError("SENSITIVE"), HttpResponseError("SENSITIVE")])
def test_failure_reports_type_without_sensitive_exception_message_and_cleans_up(error, capsys):
    with pytest.raises(type(error)):
        with diagnostics.startup_diagnostics(), diagnostics.startup_stage("download:findings"):
            raise error
    output = capsys.readouterr().err
    assert f"errorType={type(error).__name__}" in output
    assert "event=failed" in output
    assert "outcome=failed" in output
    assert "SENSITIVE" not in output
    assert diagnostics._ACTIVE.get() is None


def test_instrumentation_is_silent_outside_initial_startup(capsys):
    with diagnostics.startup_stage("not-startup"):
        diagnostics.startup_rows(1)
        diagnostics.startup_bytes(1)
    assert not diagnostics.startup_active()
    assert capsys.readouterr().err == ""


def test_cgroup_v2_memory_cpu_and_oom_readings(tmp_path):
    proc, cgroup = tmp_path / "proc", tmp_path / "cgroup"
    proc.mkdir()
    cgroup.mkdir()
    (proc / "status").write_text("Name:\tpython\nVmRSS:\t204800 kB\n")
    (cgroup / "memory.current").write_text(str(512 * 1024**2))
    (cgroup / "memory.max").write_text(str(1024 * 1024**2))
    (cgroup / "cpu.max").write_text("200000 100000")
    (cgroup / "cpu.stat").write_text("nr_throttled 20\nthrottled_usec 1500000\n")
    (cgroup / "memory.events").write_text("oom 2\noom_kill 1\n")
    assert diagnostics.resource_sample(proc, cgroup) == {
        "rssMiB": 200.0, "memoryMiB": 512.0, "memoryLimitMiB": 1024.0,
        "cpuQuotaCores": 2.0, "cpuThrottledSeconds": 1.5, "oomKills": 1,
    }


def test_cgroup_v1_and_unlimited_memory(tmp_path):
    (tmp_path / "memory").mkdir()
    (tmp_path / "cpu").mkdir()
    (tmp_path / "memory/memory.usage_in_bytes").write_text(str(256 * 1024**2))
    (tmp_path / "memory/memory.limit_in_bytes").write_text(str(2**63 - 4096))
    (tmp_path / "cpu/cpu.cfs_quota_us").write_text("100000")
    (tmp_path / "cpu/cpu.cfs_period_us").write_text("100000")
    (tmp_path / "cpu/cpu.stat").write_text("throttled_time 2000000000\n")
    sample = diagnostics.resource_sample(tmp_path / "missing", tmp_path)
    assert sample["memoryMiB"] == 256
    assert sample["memoryLimitMiB"] == "unlimited"
    assert sample["cpuQuotaCores"] == 1
    assert sample["cpuThrottledSeconds"] == 2
    assert sample["oomKills"] == "unavailable"


def test_resource_readings_use_the_process_cgroup_not_host_root(tmp_path):
    proc, root = tmp_path / "proc", tmp_path / "cgroup"
    proc.mkdir()
    group = root / "apps/dashboard"
    group.mkdir(parents=True)
    (proc / "cgroup").write_text("0::/apps/dashboard\n")
    (root / "memory.current").write_text(str(2048 * 1024**2))
    (group / "memory.current").write_text(str(128 * 1024**2))
    (group / "memory.max").write_text("max")
    (group / "cpu.max").write_text("max 100000")
    sample = diagnostics.resource_sample(proc, root)
    assert sample["memoryMiB"] == 128
    assert sample["memoryLimitMiB"] == "unlimited"
    assert sample["cpuQuotaCores"] == "unlimited"


def test_unsupported_resource_counters_are_explicit(tmp_path):
    sample = diagnostics.resource_sample(tmp_path, tmp_path)
    assert set(sample.values()) == {"unavailable"}


def test_heartbeat_cpu_and_throttling_deltas_are_measured(monkeypatch, caplog):
    times, cpus = iter([10.0, 40.0]), iter([2.0, 17.0])
    samples = iter([
        {"cpuThrottledSeconds": 3.0, "oomKills": 0},
        {"cpuThrottledSeconds": 5.0, "oomKills": 1},
    ])
    monkeypatch.setattr(diagnostics.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(diagnostics.time, "process_time", lambda: next(cpus))
    monkeypatch.setattr(diagnostics, "resource_sample", lambda: next(samples))
    caplog.set_level(logging.INFO, logger=diagnostics.LOGGER.name)
    monitor = diagnostics.StartupDiagnostics()
    monitor.heartbeat()
    assert "processCpuSeconds=15.0 processCpuPercent=50.0" in caplog.text
    assert "cpuThrottledSecondsDelta=2.0" in caplog.text
    assert "oomKillsDelta=1" in caplog.text
