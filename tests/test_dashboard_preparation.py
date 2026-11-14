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
from vulnerability_view import dashboard_snapshots
from vulnerability_view.dashboard_snapshots import DashboardSnapshots
from vulnerability_view.dashboard_preparation import DashboardPreparation, initial_filters
from vulnerability_view.dashboard_queries import DashboardQueryEngine, PREPARED_VIEWS, _cache_filters
from vulnerability_view.dashboard_server import DashboardQueryRequest, create_app
from vulnerability_view.dashboard_startup import startup_rows, startup_stage
from test_dashboard_queries import SNAPSHOT, datasets, engine
from test_dashboard_cache import Service, cache
from test_dashboard_query_api import request


STEP4_KNOWN_FAILURE = pytest.mark.xfail(
    strict=True,
    reason="Pre-existing at archive/pre-sla-simplification (fe7eeec): the dashboard changed before the SLA "
    "refactor and this test was not updated. Resolve in Step 4 (docs/review.md section 4.6), then remove this mark.",
)

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


def test_cache_publication_handoff_at_exact_two_snapshot_retention_budget(tmp_path, monkeypatch):
    pointer = [{"runId": "first", "snapshotTimeUtc": SNAPSHOT}]
    snapshots = DashboardSnapshots(
        Settings(dashboard_data_source="azure"), tmp_path, lambda: pointer[0], object, lambda *args: {},
    )
    monkeypatch.setattr(
        dashboard_snapshots, "DashboardQueryEngine",
        lambda root, snapshot_id, snapshot_time, rows: engine(root, datasets(20), snapshot_id, snapshot_time),
    )
    service = Service()
    derived = cache(service)
    prepared = []

    def prepare(snapshot):
        snapshot.engine.read_model.prepare({})
        if prepared:
            old = snapshots._entries[prepared[0]]
            assert old.readers > 0 and snapshot.readers > 0
            assert preparation.metadata()["snapshotId"] == old.id
            snapshots.max_bytes = snapshots._local_bytes(old.root.parent)
        derived.publish(snapshot.engine, {}, reserve=snapshots._check_publication_space)
        assert snapshot.root.exists()
        prepared.append(snapshot.id)

    preparation = DashboardPreparation(snapshots, prepare, 300)
    try:
        preparation._attempt_refresh()
        first = preparation.metadata()["snapshotId"]
        pointer[0] = {"runId": "second", "snapshotTimeUtc": SNAPSHOT}
        preparation._attempt_refresh()
        assert preparation.diagnostics()["status"] == "ready"
        assert preparation.metadata()["snapshotId"] == prepared[1] != first
        assert snapshots._entries[first].root.exists()
        assert snapshots._local_bytes(snapshots._entries[first].root.parent) == snapshots.max_bytes
        assert len([name for name in service.writes if name.endswith("/complete.json")]) == 4
    finally:
        preparation.close()
        snapshots.close()


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
                        progress = json.loads(body)["progress"]
                        assert progress["rows"] == 204000
                        assert progress["phasePlan"] == {
                            "steps": ["snapshot-indexes", "snapshot-aggregates"],
                            "currentStep": 1, "totalSteps": 2,
                        }
                status, headers, body = await asyncio.to_thread(request, application, "/api/dashboard/snapshot")
                assert status == 202
                assert headers[b"retry-after"] == b"2"
                assert "snapshotId" not in json.loads(body)
                status, _, body = await asyncio.to_thread(
                    request, application, "/api/dashboard/query", method="POST",
                    payload={"snapshotId": "a" * 64, "asyncQuery": True, "requestId": "during-restart"},
                )
                assert status == 202
                assert json.loads(body)["progress"]["rows"] == 204000
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


def test_multiple_expensive_filter_requests_do_not_starve_navigation(tmp_path, monkeypatch):
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
    original = DashboardQueryEngine.query

    def slow_exact_query(self, payload):
        if payload.get("filters", {}).get("search"):
            entered.set()
            assert release.wait(5)
        return original(self, payload)

    monkeypatch.setattr(DashboardQueryEngine, "query", slow_exact_query)

    async def verify():
        async with application.router.lifespan_context(application):
            try:
                for _ in range(500):
                    if application.state.dashboard_preparation.diagnostics()["readySnapshotId"]:
                        break
                    await asyncio.sleep(.01)
                status, _, body = await asyncio.to_thread(request, application, "/api/dashboard/snapshot")
                assert status == 200
                snapshot_id = json.loads(body)["snapshotId"]
                for index in range(2):
                    payload = {
                        "snapshotId": snapshot_id, "view": "recommendations",
                        "filters": {**initial_filters(ROOT / "dashboard/config.js"), "search": f"slow-{index}"},
                        "asyncQuery": True, "requestId": f"slow-{index}",
                    }
                    status, _, _ = await asyncio.to_thread(
                        request, application, "/api/dashboard/query", method="POST", payload=payload,
                    )
                    assert status == 202
                assert await asyncio.to_thread(entered.wait, 5)
                payload.update(
                    filters=initial_filters(ROOT / "dashboard/config.js"), requestId="ordinary-navigation",
                )
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


@STEP4_KNOWN_FAILURE
def test_shared_defaults_agree_with_actual_browser_request():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js required to verify browser default parity")
    script = r"""
const fs=require("node:fs"),vm=require("node:vm");
const sourceText=fs.readFileSync("dashboard/app.js","utf8"),source=sourceText.split("\n");
const context=vm.createContext({window:{},Map,Set,$:()=>null});
vm.runInContext(fs.readFileSync("dashboard/config.js","utf8"),context);
for(const line of source){
  if(line.startsWith("const presentation=")||line.startsWith("const filterConfig=")||
     line.startsWith("const workloadGroupingConfig=")||line.startsWith("const DEFAULT_RECOMMENDATION_TYPES=")||
     line.startsWith("const DEFAULT_DOMAINS=")||line.startsWith("const DEFAULT_REPORTING_DAYS=")||
     line.startsWith("const state=")||line.startsWith("const findingsList="))vm.runInContext(line,context);
}
vm.runInContext("const dashboardQuery={snapshot:{snapshotId:'test'}};const FINDINGS_PAGE_SIZE=100;",context);
vm.runInContext(sourceText.slice(sourceText.indexOf("function dashboardFilters()"),sourceText.indexOf("function invalidateDashboardChannel(")),context);
console.log(vm.runInContext("JSON.stringify(dashboardRequest().filters)",context));
"""
    result = subprocess.run([node, "-e", script], cwd=ROOT, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    browser = json.loads(result.stdout)
    # snapshot_query_payload supplies these from the selected snapshot and store.
    for key in ("slaPolicy", "recommendationTrackingEnabled",
                "recommendationTrackingLocalPreview", "recommendationTracking"):
        browser.pop(key)
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


def test_persistent_default_rejects_changed_scope_policy_and_response_version(tmp_path, monkeypatch):
    from vulnerability_view import dashboard_queries

    original = engine(tmp_path)
    filters = initial_filters(ROOT / "dashboard/config.js")
    filters["slaPolicy"] = {"policyVersion": "original"}
    payload = {"view": "executive", "filters": filters, "limit": 100}
    original.prepare(payload)
    expected = original.cached(payload)
    for index in range(30):
        original.products.save_document(f"filtered:{index}", {"index": index})

    restored = engine(tmp_path)
    assert restored.cached(payload) == expected
    for changed in (
        {"severity": "Critical"},
        {"slaPolicy": {"policyVersion": "changed"}},
    ):
        assert restored.cached({**payload, "filters": {**filters, **changed}}) is None

    monkeypatch.setattr(dashboard_queries, "PREPARED_RESPONSE_VERSION", dashboard_queries.PREPARED_RESPONSE_VERSION + 1)
    assert engine(tmp_path).cached(payload) is None


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


def test_persistent_startup_warms_all_views_and_restores_without_reingestion(tmp_path, monkeypatch):
    from test_dashboard_cache import Service, cache
    from vulnerability_view import dashboard_server
    from vulnerability_view.dashboard_snapshots import DashboardSnapshots

    data = tmp_path / "dashboard/data"
    data.mkdir(parents=True)
    for name, rows in datasets().items():
        (data / f"{name}.json").write_text(json.dumps(rows))
    (tmp_path / "config").mkdir()
    (tmp_path / "config/sla-policies.json").write_text('{"policies":[]}')
    service = Service()
    monkeypatch.setattr(dashboard_server, "DashboardDerivedCache", lambda *args, **kwargs: cache(service))
    settings = Settings(
        dashboard_data_source="local", dashboard_auth_enabled=False,
        dashboard_static_dir=str(ROOT / "dashboard"), dashboard_derived_cache_container="viewer-cache",
    )

    async def verify():
        for restart in range(2):
            application = create_app(settings, project_root=tmp_path)
            async with application.router.lifespan_context(application):
                preparation = application.state.dashboard_preparation
                for _ in range(1000):
                    if preparation.diagnostics()["readySnapshotId"]:
                        break
                    await asyncio.sleep(.01)
                assert preparation.diagnostics()["status"] == "ready", preparation.diagnostics()
                with application.state.dashboard_snapshots.acquire(preparation.metadata()["snapshotId"]) as entry:
                    assert entry.engine.search_index.ready()
                    assert entry.engine.products.path.is_file()
                    if not restart:
                        assert entry.engine.history_index_path is not None
                if not restart:
                    def unexpected(*args):
                        raise AssertionError("A restart must restore indexes, not ingest curated rows")
                    monkeypatch.setattr(DashboardSnapshots, "_rows", unexpected)
                    original_query = DashboardQueryEngine.query

                    def require_cached(engine, payload):
                        assert engine.cached(payload) is not None, payload["view"]
                        return original_query(engine, payload)

                    monkeypatch.setattr(DashboardQueryEngine, "query", require_cached)

    asyncio.run(verify())
    assert any("/products-v1/" in name and name.endswith("/complete.json") for name in service.blobs)
    assert any("/search-v1/" in name and name.endswith("/complete.json") for name in service.blobs)
    assert any("/history-v10/" in name and name.endswith("/complete.json") for name in service.blobs)


def test_persistent_defaults_survive_filtered_query_churn_and_restart(tmp_path, monkeypatch):
    from test_dashboard_cache import Service, cache
    from vulnerability_view import dashboard_server

    data = tmp_path / "dashboard/data"
    data.mkdir(parents=True)
    for name, rows in datasets().items():
        (data / f"{name}.json").write_text(json.dumps(rows))
    (tmp_path / "config").mkdir()
    (tmp_path / "config/sla-policies.json").write_text('{"policies":[]}')
    service = Service()
    monkeypatch.setattr(dashboard_server, "DashboardDerivedCache", lambda *args, **kwargs: cache(service))
    settings = Settings(
        dashboard_data_source="local", dashboard_auth_enabled=False,
        dashboard_static_dir=str(ROOT / "dashboard"), dashboard_derived_cache_container="viewer-cache",
    )
    expected = {}

    async def verify():
        for restart in range(2):
            if restart:
                original_query = DashboardQueryEngine.query

                def require_cached(engine, payload):
                    if not payload.get("filters", {}).get("search"):
                        assert engine.cached(payload) is not None, payload["view"]
                    return original_query(engine, payload)

                monkeypatch.setattr(DashboardQueryEngine, "query", require_cached)
            application = create_app(settings, project_root=tmp_path)
            async with application.router.lifespan_context(application):
                preparation = application.state.dashboard_preparation
                for _ in range(1000):
                    if preparation.diagnostics()["readySnapshotId"]:
                        break
                    await asyncio.sleep(.01)
                assert preparation.diagnostics()["status"] == "ready", preparation.diagnostics()
                with application.state.dashboard_snapshots.acquire(preparation.metadata()["snapshotId"]) as entry:
                    filters = {
                        **initial_filters(ROOT / "dashboard/config.js"), "slaPolicy": entry.policy,
                        "recommendationTrackingEnabled": False,
                        "recommendationTrackingLocalPreview": False, "recommendationTracking": [],
                    }
                    prepared_keys = set(entry.engine._prepared)
                    for index in range(30):
                        payload = {
                            "view": "help", "filters": {**filters, "search": f"unmatched-{index}"},
                        }
                        entry.engine.query(payload)
                        entry.engine._responses.clear()
                        entry.engine.query(payload)
                    assert len(prepared_keys) == len(PREPARED_VIEWS)
                    assert set(entry.engine._prepared) == prepared_keys
                    if not restart:
                        cache(service).publish_extra(
                            entry.engine, "products-v1", entry.engine.products.path,
                            limit=64 * 1024**2, validate=entry.engine.products.validate,
                            lock=entry.engine.products.lock,
                        )
                    for view in PREPARED_VIEWS:
                        payload = {
                            "view": view, "filters": filters,
                            "mode": "cves" if view == "overview" else "findings", "limit": 100,
                        }
                        result = entry.engine.cached(payload)
                        assert result is not None, f"{view} lost its prepared result after cache churn"
                        if restart:
                            assert result == expected[view]
                        else:
                            expected[view] = result
                    assert entry.engine.cached({
                        "view": "executive", "filters": {**filters, "severity": "Critical"},
                    }) is None

    asyncio.run(verify())


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
    original = DashboardQueryEngine._management_report

    def slow_summary(self, *args):
        entered.set()
        assert release.wait(5)
        if fail_summary:
            raise OSError("Summary calculation failed")
        return original(self, *args)

    monkeypatch.setattr(DashboardQueryEngine, "_management_report", slow_summary)

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
