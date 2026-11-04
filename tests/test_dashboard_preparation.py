import asyncio
import json
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path
from threading import Event, Thread
from types import SimpleNamespace

import pytest

from vulnerability_view.config import Settings
from vulnerability_view.dashboard_preparation import DashboardPreparation, initial_filters
from vulnerability_view.dashboard_queries import DashboardQueryEngine, PREPARED_VIEWS, _cache_filters
from vulnerability_view.dashboard_server import DashboardQueryRequest, create_app
from vulnerability_view.dashboard_startup import startup_rows, startup_stage
from test_dashboard_queries import SNAPSHOT, datasets, engine
from test_dashboard_query_api import request


ROOT = Path(__file__).parents[1]


class Snapshots:
    def __init__(self):
        self.current_id = "first"
        self.counts = {}

    @property
    def active(self):
        return set(self.counts)

    def current(self):
        return SimpleNamespace(id=self.current_id)

    @contextmanager
    def acquire(self, id):
        self.counts[id] = self.counts.get(id, 0) + 1
        try:
            yield SimpleNamespace(id=id, metadata=lambda: {"snapshotId": id, "notices": []})
        finally:
            self.counts[id] -= 1
            if not self.counts[id]:
                del self.counts[id]


def test_prepares_before_ready_and_holds_old_snapshot_during_replacement():
    snapshots = Snapshots()
    entered, release = Event(), Event()

    def prepare(snapshot):
        if snapshot.id == "second":
            assert snapshots.active == {"first", "second"}
            entered.set()
            assert release.wait(5)

    preparation = DashboardPreparation(snapshots, prepare, 60)
    with pytest.raises(RuntimeError, match="not completed"):
        preparation.metadata()
    preparation.start()
    try:
        assert preparation.metadata()["snapshotId"] == "first"
        snapshots.current_id = "second"
        worker = Thread(target=preparation.refresh)
        worker.start()
        assert entered.wait(5)
        assert preparation.metadata()["snapshotId"] == "first"
        release.set()
        worker.join(5)
        assert not worker.is_alive()
        assert preparation.metadata()["snapshotId"] == "second"
    finally:
        release.set()
        preparation.close()


def test_startup_failure_is_not_reported_as_ready():
    def fail(snapshot):
        raise OSError("Disk full")

    preparation = DashboardPreparation(Snapshots(), fail, 60)
    with pytest.raises(OSError, match="Disk full"):
        preparation.start()
    assert preparation.diagnostics()["readySnapshotId"] == ""
    preparation.close()


def test_background_initial_failure_is_visible_and_retries():
    attempts = []
    entered, release = Event(), Event()

    def prepare(snapshot):
        attempts.append(snapshot.id)
        if len(attempts) == 1:
            raise OSError("Temporary disk failure")
        entered.set()
        assert release.wait(5)

    preparation = DashboardPreparation(Snapshots(), prepare, 1)
    preparation.start_background()
    try:
        assert entered.wait(5)
        assert preparation.diagnostics()["readySnapshotId"] == ""
        release.set()
        preparation.close()
        assert preparation.diagnostics()["status"] == "ready"
        assert preparation.metadata()["snapshotId"] == "first"
        assert len(attempts) == 2
    finally:
        release.set()
        preparation.close()


def test_shell_health_and_progress_are_responsive_before_indexes_are_ready(tmp_path, monkeypatch):
    directory = tmp_path / "dashboard/data"
    directory.mkdir(parents=True)
    for name, rows in datasets().items():
        (directory / f"{name}.json").write_text(json.dumps(rows))
    (tmp_path / "config").mkdir()
    (tmp_path / "config/sla-policies.json").write_text('{"policies":[]}')
    application = create_app(
        Settings(
            dashboard_auth_enabled=False, dashboard_static_dir=str(ROOT / "dashboard"),
            dashboard_recommendation_tracking_enabled=False, dashboard_data_browser_enabled=True,
        ), project_root=tmp_path,
    )
    entered, release = Event(), Event()

    def wait_for_index(snapshot):
        with startup_stage("load-rows:findings"):
            startup_rows(204000)
            entered.set()
            assert release.wait(5)

    monkeypatch.setattr(application.state.dashboard_snapshots, "prepare_index", wait_for_index)

    async def verify():
        async with application.router.lifespan_context(application):
            try:
                assert await asyncio.to_thread(entered.wait, 5)
                for path in ("/", "/api/health", "/api/dashboard/status"):
                    status, _, body = await asyncio.to_thread(request, application, path)
                    assert status == 200
                    if path == "/api/health":
                        assert json.loads(body)["dashboardReady"] is False
                    elif path.endswith("/status"):
                        assert json.loads(body)["progress"]["rows"] == 204000
                status, headers, body = await asyncio.to_thread(request, application, "/api/dashboard/snapshot")
                assert status == 202
                assert headers[b"retry-after"] == b"2"
                assert "snapshotId" not in json.loads(body)
                for path in ("/api/data-browser/catalog", "/api/data-browser/findings"):
                    status, headers, _ = await asyncio.to_thread(request, application, path)
                    assert status == 503
                    assert headers[b"retry-after"] == b"2"
            finally:
                release.set()
            for _ in range(500):
                if application.state.dashboard_preparation.diagnostics()["readySnapshotId"]:
                    break
                await asyncio.sleep(.01)
            status, _, body = await asyncio.to_thread(request, application, "/api/dashboard/snapshot")
            assert status == 200
            assert json.loads(body)["preparation"]["status"] == "ready"

    asyncio.run(verify())


def test_refresh_failure_retains_ready_snapshot_and_reports_error(caplog):
    snapshots = Snapshots()
    attempted = Event()

    def prepare(snapshot):
        if snapshot.id == "second":
            attempted.set()
            raise OSError("Disk full")

    preparation = DashboardPreparation(snapshots, prepare, 1)
    preparation.start()
    snapshots.current_id = "second"
    try:
        assert attempted.wait(5)
    finally:
        preparation.close()
    assert preparation.metadata()["snapshotId"] == "first"
    assert "failed" in preparation.metadata()["notices"][0]
    assert "retaining any ready snapshot" in caplog.text


def test_shared_defaults_agree_with_actual_browser_state():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js required to verify browser default parity")
    script = r"""
const fs=require("node:fs"),vm=require("node:vm");
const source=fs.readFileSync("dashboard/app.js","utf8").split("\n");
const context=vm.createContext({window:{},Map,Set});
vm.runInContext(fs.readFileSync("dashboard/config.js","utf8"),context);
for(const line of source){
  if(line.startsWith("const presentation=")||line.startsWith("const filterConfig=")||
     line.startsWith("const workloadGroupingConfig=")||line.startsWith("const DEFAULT_RECOMMENDATION_TYPES=")||
     line.startsWith("const DEFAULT_DOMAINS=")||line.startsWith("const DEFAULT_REPORTING_DAYS=")||
     line.startsWith("const state="))vm.runInContext(line,context);
}
console.log(vm.runInContext(`JSON.stringify(Object.fromEntries(
 Object.entries(state).filter(([k,v])=>v===null||["string","number","boolean"].includes(typeof v)||v instanceof Set)
 .map(([k,v])=>[k,v instanceof Set?[...v]:v]).concat([["workloadGrouping",workloadGroupingConfig]])
))`,context));
"""
    result = subprocess.run([node, "-e", script], cwd=ROOT, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    browser = json.loads(result.stdout)
    browser.pop("slaPolicy")
    browser.pop("recommendationTrackingEnabled")
    browser.pop("recommendationTrackingLocalPreview")
    assert _cache_filters(browser) == initial_filters(ROOT / "dashboard/config.js")


def test_prepared_default_survives_other_queries_and_ignores_only_ui_state(tmp_path, monkeypatch):
    query_engine = engine(tmp_path)
    filters = initial_filters(ROOT / "dashboard/config.js")
    payload = {"view": "executive", "mode": "findings", "limit": 100, "filters": filters}
    query_engine.prepare(payload)
    expected = query_engine.query(payload)
    for index in range(10):
        query_engine.query({**payload, "filters": {**filters, "search": f"unmatched-{index}"}})

    def unexpected(*args, **kwargs):
        raise AssertionError("Prepared first page must not open SQLite")

    monkeypatch.setattr(query_engine, "_connect", unexpected)
    assert query_engine.query({
        **payload, "filters": {
            **filters, "activeView": "executive", "selectedEntity": None,
            "statisticsStartDate": "2026-10-01", "executiveSnapshotStart": "",
        },
    }) == expected
    with pytest.raises(AssertionError, match="must not open SQLite"):
        query_engine.query({**payload, "filters": {**filters, "severity": "Critical"}})


def test_custom_dates_are_part_of_cache_key():
    for mode, start in [
        ("newPeriod", "newPeriodStart"),
        ("statisticsPeriod", "statisticsStartDate"),
        ("executiveSnapshotPeriod", "executiveSnapshotStart"),
    ]:
        assert _cache_filters({mode: "custom", start: "2026-10-01"})[start] == "2026-10-01"


def test_real_lifespan_prepares_indexes_then_queries_every_view_on_demand(tmp_path, monkeypatch, capsys):
    data = tmp_path / "dashboard/data"
    data.mkdir(parents=True)
    for name, rows in datasets().items():
        (data / f"{name}.json").write_text(json.dumps(rows))
    (tmp_path / "config").mkdir()
    (tmp_path / "config/sla-policies.json").write_text('{"policies":[]}')
    application = create_app(
        Settings(
            dashboard_data_source="local", dashboard_auth_enabled=False,
            dashboard_static_dir=str(ROOT / "dashboard"),
            dashboard_recommendation_tracking_enabled=False,
        ),
        project_root=tmp_path,
    )

    async def verify():
        async with application.router.lifespan_context(application):
            preparation = application.state.dashboard_preparation
            for _ in range(500):
                if preparation.diagnostics()["readySnapshotId"]:
                    break
                await asyncio.sleep(.01)
            snapshot = preparation.metadata()
            assert preparation.diagnostics()["status"] == "ready"
            with application.state.dashboard_snapshots.acquire(snapshot["snapshotId"]) as entry:
                assert len(entry.engine._prepared) == 0
                assert len(entry.engine._responses) == 0
                assert entry.engine.cached({"view": "trend"}) is None
            for view in PREPARED_VIEWS:
                filters = initial_filters(ROOT / "dashboard/config.js")
                filters.update(activeView=view, selectedEntity=None, snapshotTimeMs=0)
                payload = DashboardQueryRequest(
                    snapshotId=snapshot["snapshotId"], view=view,
                    mode="findings" if view == "overview" else "cves", filters=filters,
                    asyncQuery=True, requestId=f"prepared-{view}",
                ).model_dump()
                for _ in range(500):
                    status, _, body = await asyncio.to_thread(
                        request, application, "/api/dashboard/query", method="POST", payload=payload,
                    )
                    if status != 202:
                        break
                    await asyncio.sleep(.01)
                assert status == 200, body
                result = json.loads(body)
                assert result["scope"]["findings"] > 0
                assert result["snapshotTimeUtc"] == SNAPSHOT

    asyncio.run(verify())
    logs = capsys.readouterr().err
    assert "stage=snapshot-metadata event=start" in logs
    assert "stage=load-rows:findings event=start" in logs
    assert "stage=build-indexes:findings:rows=" in logs
    assert "stage=prepare-workspace-indexes event=complete" in logs
    assert "stage=view:executive:" not in logs
    assert "stage=view:trend:" not in logs
    assert "outcome=ready" in logs


@pytest.mark.parametrize("fail_summary", [False, True])
def test_slow_summary_does_not_gate_snapshot_or_independent_recommendations(tmp_path, monkeypatch, fail_summary):
    directory = tmp_path / "dashboard/data"
    directory.mkdir(parents=True)
    for name, rows in datasets().items():
        (directory / f"{name}.json").write_text(json.dumps(rows))
    (tmp_path / "config").mkdir()
    (tmp_path / "config/sla-policies.json").write_text('{"policies":[]}')
    application = create_app(
        Settings(
            dashboard_auth_enabled=False, dashboard_static_dir=str(ROOT / "dashboard"),
            dashboard_recommendation_tracking_enabled=False,
        ), project_root=tmp_path,
    )
    entered, release = Event(), Event()
    original = DashboardQueryEngine._executive

    def slow_summary(self, *args):
        entered.set()
        assert release.wait(5)
        if fail_summary:
            raise OSError("Summary calculation failed")
        return original(self, *args)

    monkeypatch.setattr(DashboardQueryEngine, "_executive", slow_summary)

    async def verify():
        async with application.router.lifespan_context(application):
            try:
                for _ in range(500):
                    if application.state.dashboard_preparation.diagnostics()["readySnapshotId"]:
                        break
                    await asyncio.sleep(.01)
                assert not entered.is_set()
                status, _, body = await asyncio.to_thread(request, application, "/api/dashboard/snapshot")
                assert status == 200
                snapshot_id = json.loads(body)["snapshotId"]
                payload = {
                    "snapshotId": snapshot_id, "view": "executive",
                    "filters": initial_filters(ROOT / "dashboard/config.js"),
                    "asyncQuery": True, "requestId": "slow-summary",
                }
                status, _, _ = await asyncio.to_thread(
                    request, application, "/api/dashboard/query", method="POST", payload=payload,
                )
                assert status == 202
                assert await asyncio.to_thread(entered.wait, 5)
                payload.update(view="recommendations", requestId="independent-recommendations")
                for _ in range(500):
                    status, _, body = await asyncio.to_thread(
                        request, application, "/api/dashboard/query", method="POST", payload=payload,
                    )
                    if status != 202:
                        break
                    await asyncio.sleep(.01)
                assert status == 200, body
                assert "recommendationTable" in json.loads(body)["tables"]
                assert not release.is_set()
            finally:
                release.set()
            payload.update(view="executive", requestId="slow-summary")
            for _ in range(500):
                status, _, body = await asyncio.to_thread(
                    request, application, "/api/dashboard/query", method="POST", payload=payload,
                )
                if status != 202:
                    break
                await asyncio.sleep(.01)
            assert status == (503 if fail_summary else 200), body
            assert application.state.dashboard_preparation.diagnostics()["status"] == "ready"

    asyncio.run(verify())
