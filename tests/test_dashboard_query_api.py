import asyncio
import csv
import io
import json
import hashlib
import time
from threading import Event
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import pytest
from fastapi.responses import JSONResponse

from vulnerability_view import dashboard_snapshots
from vulnerability_view.config import Settings
from vulnerability_view.dashboard_server import create_app


def request(
    app, path, *, method="GET", payload=None, content_type="application/json",
    headers=(), disconnect_after_first_chunk=False, capture_chunks=None,
):
    async def run():
        messages = []
        complete = asyncio.Event()
        sent = False
        url = urlsplit(path)
        body = (
            urlencode({"payload": json.dumps(payload)}).encode()
            if content_type == "application/x-www-form-urlencoded"
            else json.dumps(payload).encode() if payload is not None else b""
        )

        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            await complete.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            messages.append(message)
            if capture_chunks is not None and message["type"] == "http.response.body" and message.get("body"):
                capture_chunks.append(message["body"])
            if message["type"] == "http.response.body" and (
                not message.get("more_body") or disconnect_after_first_chunk
            ):
                complete.set()

        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "method": method, "scheme": "http", "path": url.path, "raw_path": url.path.encode(),
            "query_string": url.query.encode(), "root_path": "",
            "headers": [(b"content-type", content_type.encode()), *headers],
            "client": ("127.0.0.1", 1), "server": ("testserver", 80),
        }
        await asyncio.wait_for(app(scope, receive, send), 20)
        response = next(message for message in messages if message["type"] == "http.response.start")
        result = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
        return response["status"], dict(response["headers"]), result

    return asyncio.run(run())


class Engine:
    calls = []

    def __init__(self, root, snapshot_id, snapshot_time, rows):
        self.snapshot_id = snapshot_id

    def query(self, payload):
        self.calls.append(payload)
        return {"snapshotId": self.snapshot_id, "cards": {}, "tables": {}, "notices": []}

    def cached(self, payload):
        return None

    def query_identity(self, payload):
        semantic = {key: value for key, value in payload.items() if key not in {"requestId", "asyncQuery"}}
        return hashlib.sha256(json.dumps(semantic, sort_keys=True).encode()).hexdigest()

    def is_interactive(self, payload):
        return payload.get("view") not in {"trend", "executiveSnapshot"}

    def indexed_rows(self):
        return {}

    def iter_export(self, payload):
        yield {"FindingKey": "a", "Severity": "High"}
        yield {"FindingKey": "b", "Severity": "Low"}

    def iter_dataset(self, name):
        return iter([{"RecommendationId": "rec-1", "DataOrigin": "Live"}])


@pytest.fixture
def app(monkeypatch, tmp_path):
    monkeypatch.setattr(dashboard_snapshots, "DashboardQueryEngine", Engine)
    Engine.calls = []
    (tmp_path / "dashboard/data").mkdir(parents=True)
    (tmp_path / "dashboard/data/collection-runs.json").write_text(json.dumps([{
        "CollectionRunId": "run-a", "SnapshotTimeUtc": "2026-10-24T00:59:46Z",
    }]))
    (tmp_path / "config").mkdir()
    (tmp_path / "config/sla-policies.json").write_text('{"policyVersion":"pinned","policies":[]}')
    application = create_app(
        Settings(dashboard_data_source="local", dashboard_recommendation_tracking_enabled=False),
        project_root=tmp_path,
    )
    select_snapshot(application)
    yield application
    application.state.dashboard_query_jobs.close()
    application.state.dashboard_snapshots.close()


def test_cached_results_bypass_occupied_workers(app, monkeypatch):
    release = Event()
    jobs = app.state.dashboard_query_jobs
    snapshot = select_snapshot(app)

    def blocked():
        assert release.wait(5)
        return JSONResponse({"ready": True})

    def cached(self, payload):
        return {"snapshotId": self.snapshot_id, "scope": {"findings": 1837575}, "notices": []}

    monkeypatch.setattr(Engine, "cached", cached)
    monkeypatch.setattr(Engine, "is_interactive", lambda *args: pytest.fail("A cache hit must not be queued"))
    try:
        jobs.poll("busy-one", snapshot["snapshotId"], blocked)
        jobs.poll("busy-two", snapshot["snapshotId"], blocked)
        start = time.monotonic()
        status, _, body = request(app, "/api/dashboard/query", method="POST", payload={
            "snapshotId": snapshot["snapshotId"], "view": "recommendations",
            "asyncQuery": True, "requestId": "cached-navigation",
        })
        assert status == 200
        assert json.loads(body)["scope"]["findings"] == 1837575
        assert time.monotonic() - start < .5
        assert Engine.calls == []
    finally:
        release.set()


def test_equivalent_api_requests_share_one_computation(app, monkeypatch):
    entered, release = Event(), Event()
    snapshot = select_snapshot(app)
    calls = []

    def blocked(self, payload):
        calls.append(payload)
        entered.set()
        assert release.wait(5)
        return {"snapshotId": self.snapshot_id, "notices": []}

    monkeypatch.setattr(Engine, "query", blocked)
    base = {"snapshotId": snapshot["snapshotId"], "view": "executiveSnapshot", "asyncQuery": True}
    try:
        for request_id in ("first-view", "second-view"):
            status, _, _ = request(
                app, "/api/dashboard/query", method="POST", payload={**base, "requestId": request_id},
            )
            assert status == 202
        assert entered.wait(1)
        assert len(app.state.dashboard_query_jobs.diagnostics()["pending"]) == 1
        release.set()
        for _ in range(100):
            status, _, _ = request(
                app, "/api/dashboard/query", method="POST", payload={**base, "requestId": "second-view"},
            )
            if status != 202:
                break
            time.sleep(.005)
        assert status == 200
        assert len(calls) == 1
    finally:
        release.set()


def test_cancel_api_releases_abandoned_query_subscription(app, monkeypatch):
    entered, release = Event(), Event()
    snapshot = select_snapshot(app)

    def blocked(self, payload):
        entered.set()
        assert release.wait(5)
        return {"snapshotId": self.snapshot_id}

    monkeypatch.setattr(Engine, "query", blocked)
    payload = {
        "snapshotId": snapshot["snapshotId"], "view": "executiveSnapshot",
        "asyncQuery": True, "requestId": "abandoned-report",
    }
    try:
        assert request(app, "/api/dashboard/query", method="POST", payload=payload)[0] == 202
        assert entered.wait(1)
        status, _, body = request(app, "/api/dashboard/query/cancel", method="POST", payload=payload)
        assert status == 200 and json.loads(body)["cancelled"] is True
        release.set()
        status, _, _ = request(app, "/api/dashboard/query", method="POST", payload=payload)
        assert status == 499
    finally:
        release.set()


def test_export_waits_with_progress_when_heavy_capacity_is_in_use(app):
    snapshot = select_snapshot(app)
    with app.state.dashboard_query_jobs.export_slot():
        status, _, body = request(app, "/api/dashboard/export", method="POST", payload={
            "snapshotId": snapshot["snapshotId"], "view": "overview",
        })
    assert status == 202
    result = json.loads(body)
    assert result["status"] == "preparing"
    assert result["retryAfterSeconds"] == 2
    assert "report or export" in result["detail"]


def test_export_batches_rows_without_changing_csv_contents(app, monkeypatch):
    snapshot = select_snapshot(app)

    def rows(self, payload):
        for index in range(1200):
            yield {"FindingKey": str(index), "Evidence": 'quoted,"value"\n' + "x" * 100}

    monkeypatch.setattr(Engine, "iter_export", rows)
    chunks = []
    status, _, body = request(
        app, "/api/dashboard/export", method="POST",
        payload={"snapshotId": snapshot["snapshotId"], "view": "overview"},
        capture_chunks=chunks,
    )
    assert status == 200
    records = list(csv.DictReader(io.StringIO(body.decode("utf-8-sig"))))
    assert len(records) == 1200
    assert records[-1] == {"FindingKey": "1199", "Evidence": 'quoted,"value"\n' + "x" * 100}
    assert len(chunks) <= 6
    assert max(map(len, chunks)) < 66 * 1024


def test_real_engine_and_async_api_agree_on_request_and_response_shape(tmp_path):
    directory = tmp_path / "dashboard/data"
    directory.mkdir(parents=True)
    fixtures = {
        "findings": [{
            "FindingKey": "a", "FindingStatus": "Open", "Severity": "High",
            "DataOrigin": "Live", "AssetClass": "TraditionalIT", "DeviceId": "device-a",
            "CveId": "CVE-2026-1000", "SnapshotTimeUtc": "2026-10-24T00:59:46Z",
        }],
        "collection-runs": [{"CollectionRunId": "run-a", "SnapshotTimeUtc": "2026-10-24T00:59:46Z"}],
    }
    for name in [
        "findings", "collection-runs", "devices", "recommendations", "finding-events",
        "recommendation-events", "run-history", "subscriptions", "secure-scores",
        "recommendation-machines", "daily-summary", "vulnerabilities",
    ]:
        (directory / f"{name}.json").write_text(json.dumps(fixtures.get(name, [])))
    application = create_app(
        Settings(dashboard_data_source="local", dashboard_recommendation_tracking_enabled=False),
        project_root=tmp_path,
    )
    try:
        snapshot = select_snapshot(application)
        payload = {
            "snapshotId": snapshot["snapshotId"], "view": "overview",
            "asyncQuery": True, "requestId": "real-engine-query",
        }
        for _ in range(200):
            status, _, body = request(application, "/api/dashboard/query", method="POST", payload=payload)
            if status != 202:
                break
            time.sleep(0.005)
        assert status == 200, body.decode()
        assert json.loads(body)["tables"]["findingsTable"]["total"] == 1
    finally:
        application.state.dashboard_query_jobs.close()
        application.state.dashboard_snapshots.close()


def ready_snapshot(app):
    # These API unit tests bypass ASGI lifespan; explicitly select a prepared fixture.
    snapshot = app.state.dashboard_snapshots.current()
    snapshot.prepared = True
    preparation = app.state.dashboard_preparation
    with preparation._lock:
        preparation._ready_id = snapshot.id
        preparation._status.update(status="ready", readySnapshotId=snapshot.id)
    return snapshot


def select_snapshot(app):
    ready_snapshot(app)
    status, headers, body = request(app, "/api/dashboard/snapshot")
    assert status == 200
    assert headers[b"cache-control"] == b"no-store"
    return json.loads(body)


def test_snapshot_selection_does_not_read_findings(app):
    snapshot = select_snapshot(app)
    assert snapshot["runId"] == "run-a"
    assert snapshot["slaPolicy"]["policyVersion"] == "pinned"
    assert len(snapshot["snapshotId"]) == 64
    assert Engine.calls == []


def test_queries_are_pinned_and_server_policy_cannot_be_overridden(app):
    snapshot = select_snapshot(app)
    payload = {"snapshotId": snapshot["snapshotId"], "view": "overview",
               "filters": {"slaPolicy": {"policyVersion": "untrusted"}}, "page": 2, "limit": 100}
    status, headers, body = request(app, "/api/dashboard/query", method="POST", payload=payload)
    assert status == 200
    assert json.loads(body)["snapshotId"] == snapshot["snapshotId"]
    assert Engine.calls[-1]["filters"]["slaPolicy"]["policyVersion"] == "pinned"
    assert Engine.calls[-1]["page"] == 2
    assert headers[b"cache-control"] == b"no-store"


@pytest.mark.parametrize("changes", [
    {"limit": 201}, {"page": -1}, {"view": "not-a-view"},
    {"snapshotId": "../unsafe"}, {"filters": {"search": "x" * 33_000}},
])
def test_query_validation_rejects_unbounded_or_invalid_requests(app, changes):
    snapshot = select_snapshot(app)
    status, _, _ = request(app, "/api/dashboard/query", method="POST", payload={
        "snapshotId": snapshot["snapshotId"], **changes,
    })
    assert status == 422
    assert not Engine.calls


def test_async_query_returns_pending_then_complete_without_restarting_work(app, monkeypatch):
    release = Event()
    calls = []

    def query(self, payload):
        calls.append(payload)
        assert release.wait(5)
        return {"snapshotId": self.snapshot_id, "total": 2_000_000}

    monkeypatch.setattr(Engine, "query", query)
    snapshot = select_snapshot(app)
    payload = {"snapshotId": snapshot["snapshotId"], "asyncQuery": True, "requestId": "logical-query-1"}
    try:
        status, _, body = request(app, "/api/dashboard/query", method="POST", payload=payload)
        assert status == 202
        assert json.loads(body)["status"] == "preparing"
        release.set()
        for _ in range(100):
            status, _, body = request(app, "/api/dashboard/query", method="POST", payload=payload)
            if status != 202:
                break
            time.sleep(0.005)
        assert status == 200
        assert json.loads(body)["total"] == 2_000_000
        assert len(calls) == 1
    finally:
        release.set()


def test_async_query_requires_stable_poll_identity(app):
    snapshot = select_snapshot(app)
    status, _, _ = request(app, "/api/dashboard/query", method="POST", payload={
        "snapshotId": snapshot["snapshotId"], "asyncQuery": True,
    })
    assert status == 422


def test_async_query_polls_remain_responsive_while_tracking_preparation_is_blocked(app, tmp_path):
    entered, release = Event(), Event()

    class Tracking:
        reads = 0

        def latest(self):
            self.reads += 1
            entered.set()
            assert release.wait(5)
            return {}

    tracking = Tracking()
    application = create_app(
        Settings(dashboard_data_source="local", dashboard_recommendation_tracking_enabled=True),
        project_root=tmp_path, recommendation_tracking_store=tracking,
    )
    snapshot = select_snapshot(application)
    payload = {
        "snapshotId": snapshot["snapshotId"], "view": "executive",
        "asyncQuery": True, "requestId": "slow-tracking",
    }

    async def exercise():
        pending = asyncio.create_task(asyncio.to_thread(
            request, application, "/api/dashboard/query", method="POST", payload=payload,
        ))
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            for attempt in range(2):
                result = await asyncio.wait_for(
                    asyncio.shield(pending) if attempt == 0 else asyncio.to_thread(
                        request, application, "/api/dashboard/query", method="POST", payload=payload,
                    ),
                    timeout=.5,
                )
                status, _, body = result
                assert status == 202
                if attempt:
                    assert json.loads(body)["progress"]["stage"] == "recommendation-tracking-read"
            assert tracking.reads == 1
        finally:
            release.set()
            await pending

    try:
        asyncio.run(exercise())
        for _ in range(100):
            status, _, body = request(application, "/api/dashboard/query", method="POST", payload=payload)
            if status != 202:
                break
            time.sleep(.005)
        assert status == 200, body
        assert tracking.reads == 1
    finally:
        release.set()
        application.state.dashboard_query_jobs.close()
        application.state.dashboard_snapshots.close()


def test_expired_or_unknown_snapshot_returns_conflict(app):
    status, _, body = request(app, "/api/dashboard/query", method="POST", payload={"snapshotId": "0" * 64})
    assert status == 409
    assert "Reload" in json.loads(body)["detail"]


@pytest.mark.parametrize("content_type", ["application/json", "application/x-www-form-urlencoded"])
def test_csv_download_streams_all_rows_with_utf8_bom(app, content_type):
    snapshot = select_snapshot(app)
    status, headers, body = request(
        app, "/api/dashboard/export", method="POST",
        payload={"snapshotId": snapshot["snapshotId"], "view": "executiveSnapshot"},
        content_type=content_type,
    )
    assert status == 200
    assert headers[b"content-type"].startswith(b"text/csv")
    assert b"attachment;" in headers[b"content-disposition"]
    assert body.decode("utf-8-sig").splitlines() == ["FindingKey,Severity", "a,High", "b,Low"]


def test_export_expiry_is_reported_before_download_headers(app):
    status, headers, body = request(
        app, "/api/dashboard/export", method="POST", payload={"snapshotId": "0" * 64},
    )
    assert status == 409
    assert headers[b"content-type"] == b"application/json"
    assert "expired" in json.loads(body)["detail"]


def test_csv_download_is_not_limited_to_a_table_page(app, monkeypatch):
    def export(self, payload):
        for index in range(205):
            yield {"FindingKey": f"finding-{index}"}

    monkeypatch.setattr(Engine, "iter_export", export)
    snapshot = select_snapshot(app)
    status, _, body = request(
        app, "/api/dashboard/export", method="POST",
        payload={"snapshotId": snapshot["snapshotId"], "view": "executiveSnapshot", "limit": 100},
    )
    assert status == 200
    assert len(body.decode("utf-8-sig").splitlines()) == 206
    assert body.decode().splitlines()[-1] == "finding-204"


def test_export_source_failure_is_not_reported_as_success(app, monkeypatch, caplog):
    def export(self, payload):
        raise RuntimeError("index unavailable")
        yield

    monkeypatch.setattr(Engine, "iter_export", export)
    snapshot = select_snapshot(app)
    status, headers, body = request(
        app, "/api/dashboard/export", method="POST", payload={"snapshotId": snapshot["snapshotId"]},
    )
    assert status == 503
    assert headers[b"content-type"] == b"application/json"
    assert "could not be prepared" in json.loads(body)["detail"]
    assert "index unavailable" in caplog.text


def test_cancelled_download_releases_its_snapshot(app, monkeypatch):
    closed = []

    def export(self, payload):
        try:
            for index in range(100_000):
                yield {"FindingKey": f"finding-{index}"}
        finally:
            closed.append(True)

    monkeypatch.setattr(Engine, "iter_export", export)
    snapshot = select_snapshot(app)
    status, _, _ = request(
        app, "/api/dashboard/export", method="POST",
        payload={"snapshotId": snapshot["snapshotId"]}, disconnect_after_first_chunk=True,
    )
    assert status == 200
    assert closed == [True]
    assert all(entry.readers == 0 for entry in app.state.dashboard_snapshots._entries.values())


def test_invalid_export_filters_return_validation_error(app, monkeypatch):
    def export(self, payload):
        raise ValueError("Invalid report period")
        yield

    monkeypatch.setattr(Engine, "iter_export", export)
    snapshot = select_snapshot(app)
    status, _, body = request(
        app, "/api/dashboard/export", method="POST", payload={"snapshotId": snapshot["snapshotId"]},
    )
    assert status == 422
    assert json.loads(body)["detail"] == "Invalid report period"


def test_new_endpoints_require_dashboard_authentication(monkeypatch, tmp_path):
    monkeypatch.setenv("WEBSITE_HOSTNAME", "app.azurewebsites.net")
    (tmp_path / "dashboard").mkdir()
    application = create_app(
        Settings(dashboard_auth_enabled=True, dashboard_branding_enabled=False,
                 dashboard_recommendation_tracking_enabled=False),
        project_root=tmp_path,
    )
    try:
        for path, method in [
            ("/api/dashboard/snapshot", "GET"),
            ("/api/dashboard/query", "POST"),
            ("/api/dashboard/export", "POST"),
        ]:
            status, _, _ = request(application, path, method=method)
            assert status == 401
    finally:
        application.state.dashboard_snapshots.close()


def test_query_paging_reuses_tracking_read_and_writes_invalidate_it(app, tmp_path):
    class Tracking:
        reads = 0

        def latest(self):
            self.reads += 1
            return {}

        def record(self, *args):
            return {"UpdatedUtc": "2026-10-24T01:00:00Z"}

    tracking = Tracking()
    application = create_app(
        Settings(dashboard_data_source="local", dashboard_recommendation_tracking_enabled=True),
        project_root=tmp_path, recommendation_tracking_store=tracking,
    )
    try:
        snapshot = select_snapshot(application)
        for page in [0, 1]:
            status, _, _ = request(
                application, "/api/dashboard/query", method="POST",
                payload={"snapshotId": snapshot["snapshotId"], "view": "overview", "page": page},
            )
            assert status == 200
        assert tracking.reads == 1
        status, _, _ = request(
            application, f'/api/recommendation-tracking?snapshotId={snapshot["snapshotId"]}',
            method="PUT", payload={"recommendationId": "rec-1", "status": "InProgress"},
        )
        assert status == 200
        status, _, _ = request(
            application, "/api/dashboard/query", method="POST", payload={"snapshotId": snapshot["snapshotId"]},
        )
        assert status == 200
        assert tracking.reads == 2
    finally:
        application.state.dashboard_snapshots.close()


def test_tracking_action_cannot_be_marked_against_an_older_snapshot(monkeypatch, tmp_path):
    monkeypatch.setattr(dashboard_snapshots, "DashboardQueryEngine", Engine)
    (tmp_path / "dashboard").mkdir()

    class Tracking:
        def latest(self):
            return {}

        def record(self, *args):
            pytest.fail("A stale workflow action must not be recorded")

    application = create_app(
        Settings(dashboard_data_source="azure", storage_account_name="account",
                 dashboard_recommendation_tracking_enabled=True),
        project_root=tmp_path, recommendation_tracking_store=Tracking(),
    )
    snapshots = application.state.dashboard_snapshots
    pointer = [{"runId": "run-a", "snapshotTimeUtc": "2026-10-24T00:59:46Z"}]
    snapshots.manifest_loader = lambda: pointer[0]
    snapshots.credential = object
    snapshots.policy_loader = lambda *args: {"policies": []}
    try:
        selected = select_snapshot(application)
        pointer[0] = {"runId": "run-b", "snapshotTimeUtc": "2026-10-25T00:59:46Z"}
        status, _, body = request(
            application, f'/api/recommendation-tracking?snapshotId={selected["snapshotId"]}',
            method="PUT", payload={"recommendationId": "rec-1", "status": "ReadyForValidation"},
        )
        assert status == 409
        assert "Reload before changing" in json.loads(body)["detail"]
    finally:
        snapshots.close()
