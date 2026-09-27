import asyncio
import base64
import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from vulnerability_view.config import Settings
from vulnerability_view.dashboard_server import (
    DashboardDataStore,
    authenticate_dashboard_request,
    create_app,
    decode_app_service_principal,
    recommendation_tracking_view,
)


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def asgi_get(app, path: str, headers: list[tuple[bytes, bytes]] | None = None) -> tuple[int, bytes]:
    status, _, body = asgi_response(app, path, headers)
    return status, body


def asgi_response(
    app,
    path: str,
    headers: list[tuple[bytes, bytes]] | None = None,
    method: str = "GET",
    request_body: bytes = b"",
) -> tuple[int, dict[bytes, bytes], bytes]:
    messages = []
    request_sent = False
    url = urlsplit(path)

    async def receive():
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": request_body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": url.path,
        "raw_path": url.path.encode(),
        "query_string": url.query.encode(),
        "root_path": "",
        "headers": headers or [],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    asyncio.run(app(scope, receive, send))
    status = next(message["status"] for message in messages if message["type"] == "http.response.start")
    response_headers = dict(next(
        message["headers"] for message in messages if message["type"] == "http.response.start"
    ))
    body = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
    return status, response_headers, body


def test_local_store_reads_generated_dashboard_data(tmp_path: Path):
    write_json(tmp_path / "dashboard/data/findings.json", [{"FindingKey": "finding-1"}])
    write_json(tmp_path / "dashboard/data/collection-runs.json", [{
        "CollectionRunId": "live-20260923T050000Z",
        "SnapshotTimeUtc": "2026-09-23T05:00:00Z",
    }])
    write_json(tmp_path / "dashboard/data/secure-scores.json", [{"ScorePercent": 74.2}])
    write_json(tmp_path / "dashboard/data/cve-details/CVE-2026-1234.json", {"CveId": "CVE-2026-1234"})
    store = DashboardDataStore(Settings(dashboard_data_source="local"), project_root=tmp_path)

    assert store.read("findings.json") == [{"FindingKey": "finding-1"}]
    assert store.read("cve-details/CVE-2026-1234.json") == {"CveId": "CVE-2026-1234"}
    assert store.status() == {
        "source": "local",
        "runId": "live-20260923T050000Z",
        "snapshotTimeUtc": "2026-09-23T05:00:00Z",
        "secureScoreAvailable": True,
    }


def test_large_data_responses_are_gzip_compressed(tmp_path: Path):
    findings = [{"FindingKey": f"finding-{index}", "Description": "repeated-value" * 20} for index in range(100)]
    write_json(tmp_path / "dashboard/data/findings.json", findings)
    app = create_app(Settings(dashboard_data_source="local"), project_root=tmp_path)

    status, headers, body = asgi_response(
        app,
        "/api/data/findings.json",
        [(b"accept-encoding", b"gzip")],
    )

    assert status == 200
    assert headers[b"content-encoding"] == b"gzip"
    assert len(body) < len(json.dumps(findings).encode("utf-8"))


def test_dashboard_can_serve_static_assets_from_deployment_directory(tmp_path: Path):
    static_directory = tmp_path / "deployed-dashboard"
    static_directory.mkdir()
    (static_directory / "index.html").write_text("deployed dashboard", encoding="utf-8")
    app = create_app(
        Settings(dashboard_static_dir=str(static_directory)),
        project_root=tmp_path / "installed-package",
    )

    status, body = asgi_get(app, "/")

    assert status == 200
    assert body == b"deployed dashboard"


def test_azure_store_reuses_verified_bundle_and_resolves_cve_detail():
    calls = []
    credential = object()
    datasets = {
        "findings": [{"FindingKey": "finding-1"}],
        "secureScores": [{"ScorePercent": 74.2}],
        "vulnerabilities": [{"CveId": "CVE-2026-1234", "Description": "Example"}],
    }
    manifest = {
        "runId": "live-20260923T050000Z",
        "snapshotTimeUtc": "2026-09-23T05:00:00Z",
    }

    def load_bundle(*args):
        calls.append(args)
        return datasets, manifest

    store = DashboardDataStore(
        Settings(
            auth_mode="local",
            storage_account_name="historyaccount",
            dashboard_data_source="azure",
        ),
        cache_seconds=60,
        bundle_loader=load_bundle,
        credential_factory=lambda *_: credential,
    )

    assert store.read("findings.json") == datasets["findings"]
    assert store.read("cve-details/cve-2026-1234.json") == datasets["vulnerabilities"][0]
    assert store.status()["secureScoreAvailable"] is True
    assert len(calls) == 1
    assert calls[0] == ("historyaccount", "dvm-history", "dvm-current", credential)


def test_store_rejects_unknown_or_unsafe_paths(tmp_path: Path):
    store = DashboardDataStore(Settings(dashboard_data_source="local"), project_root=tmp_path)

    for asset_path in ("../.env", "unknown.json", "cve-details/not-a-cve.json"):
        with pytest.raises(FileNotFoundError):
            store.read(asset_path)


def test_azure_store_requires_storage_account():
    store = DashboardDataStore(Settings(dashboard_data_source="azure"))

    with pytest.raises(RuntimeError, match="STORAGE_ACCOUNT_NAME"):
        store.read("findings.json")


def test_dashboard_health_marks_client_secret_as_local_development(tmp_path: Path):
    (tmp_path / "dashboard").mkdir()
    app = create_app(
        Settings(auth_mode="client_secret", allow_local_client_secret=True),
        project_root=tmp_path,
    )
    health_route = next(route for route in app.routes if getattr(route, "path", "") == "/api/health")

    health = health_route.endpoint()

    assert health["authMode"] == "client_secret"
    assert health["localDevelopmentOnly"] is True
    assert "Never deploy" in health["warning"]


def test_dashboard_rejects_client_secret_mode_on_azure_host(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("WEBSITE_HOSTNAME", "host.azurewebsites.net")

    with pytest.raises(RuntimeError, match="restricted to local development"):
        create_app(Settings(auth_mode="client_secret", allow_local_client_secret=True), project_root=tmp_path)


def encoded_principal(roles: list[str] | None = None) -> str:
    principal = {
        "auth_typ": "aad",
        "name_typ": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        "role_typ": "roles",
        "claims": [
            {"typ": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "val": "Test User"},
            {"typ": "http://schemas.microsoft.com/identity/claims/objectidentifier", "val": "object-id"},
            *[{"typ": "roles", "val": role} for role in (roles or ["Dashboard.Viewer"])],
        ],
    }
    return base64.b64encode(json.dumps(principal).encode()).decode()


def test_dashboard_authentication_is_disabled_by_default(tmp_path: Path):
    (tmp_path / "dashboard").mkdir()
    app = create_app(Settings(), project_root=tmp_path)
    auth_route = next(route for route in app.routes if getattr(route, "path", "") == "/api/auth")

    assert authenticate_dashboard_request(False, "") is None
    assert auth_route.endpoint(type("Request", (), {"state": type("State", (), {"dashboard_user": None})()})()) == {
        "enabled": False,
        "provider": "disabled",
        "authenticated": False,
        "user": None,
    }


def test_dashboard_authentication_cannot_be_enabled_locally(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("WEBSITE_HOSTNAME", raising=False)

    with pytest.raises(RuntimeError, match="requires Azure App Service Authentication"):
        create_app(Settings(dashboard_auth_enabled=True), project_root=tmp_path)


def test_dashboard_authentication_fails_closed_without_easy_auth_identity():
    with pytest.raises(PermissionError, match="Microsoft Entra authentication is required"):
        authenticate_dashboard_request(True, "")


def test_dashboard_authentication_protects_pages_and_api(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("WEBSITE_HOSTNAME", "dashboard.azurewebsites.net")
    (tmp_path / "dashboard").mkdir()
    (tmp_path / "dashboard/index.html").write_text("dashboard", encoding="utf-8")
    app = create_app(Settings(dashboard_auth_enabled=True), project_root=tmp_path)

    for path in (
        "/",
        "/?view=data-browser",
        "/api/auth",
        "/api/status",
        "/api/data/findings.json",
        "/api/data-browser/catalog",
    ):
        status, _ = asgi_get(app, path)
        assert status == 401


def test_dashboard_authentication_accepts_valid_easy_auth_identity(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("WEBSITE_HOSTNAME", "dashboard.azurewebsites.net")
    (tmp_path / "dashboard").mkdir()
    app = create_app(Settings(dashboard_auth_enabled=True), project_root=tmp_path)
    header = (b"x-ms-client-principal", encoded_principal().encode())

    assert authenticate_dashboard_request(True, encoded_principal()) == {
        "provider": "aad",
        "displayName": "Test User",
        "objectId": "object-id",
        "roles": ["Dashboard.Viewer"],
    }
    status, body = asgi_get(app, "/api/auth", [header])
    assert status == 200
    assert json.loads(body)["user"]["objectId"] == "object-id"


def test_decode_app_service_principal_rejects_invalid_header(monkeypatch, tmp_path: Path):
    with pytest.raises(ValueError, match="principal header"):
        decode_app_service_principal("not-base64")

    monkeypatch.setenv("WEBSITE_HOSTNAME", "dashboard.azurewebsites.net")
    (tmp_path / "dashboard").mkdir()
    app = create_app(Settings(dashboard_auth_enabled=True), project_root=tmp_path)
    status, _ = asgi_get(app, "/api/auth", [(b"x-ms-client-principal", b"not-base64")])
    assert status == 401


def test_data_browser_is_disabled_by_default(tmp_path: Path):
    (tmp_path / "dashboard").mkdir()
    app = create_app(Settings(), project_root=tmp_path)

    status, _ = asgi_get(app, "/api/data-browser/catalog")

    assert status == 404


def test_data_browser_lists_and_pages_curated_rows(tmp_path: Path):
    (tmp_path / "dashboard").mkdir()
    write_json(tmp_path / "dashboard/data/findings.json", [
        {"FindingKey": "finding-1", "Severity": "Critical"},
        {"FindingKey": "finding-2", "Severity": "High"},
    ])
    write_json(tmp_path / "dashboard/data/collection-runs.json", [{
        "CollectionRunId": "run-1",
        "SnapshotTimeUtc": "2026-09-27T12:00:00Z",
    }])
    write_json(tmp_path / "dashboard/data/secure-scores.json", [])
    app = create_app(Settings(dashboard_data_browser_enabled=True), project_root=tmp_path)

    catalog_status, catalog_body = asgi_get(app, "/api/data-browser/catalog")
    rows_status, rows_body = asgi_get(app, "/api/data-browser/findings?limit=1&query=High")

    assert catalog_status == 200
    findings = next(item for item in json.loads(catalog_body)["datasets"] if item["id"] == "findings")
    assert findings["rowCount"] == 2
    assert findings["fields"] == ["FindingKey", "Severity"]
    assert rows_status == 200
    row_payload = json.loads(rows_body)
    assert row_payload["total"] == 1
    assert row_payload["limit"] == 1
    assert row_payload["rows"][0]["FindingKey"] == "finding-2"


def test_data_browser_can_require_an_app_role(tmp_path: Path):
    (tmp_path / "dashboard").mkdir()
    app = create_app(
        Settings(
            dashboard_data_browser_enabled=True,
            dashboard_data_browser_role="Data.Evidence.Reader",
        ),
        project_root=tmp_path,
    )

    status, _ = asgi_get(app, "/api/data-browser/catalog")

    assert status == 403


def test_data_browser_accepts_configured_app_role(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("WEBSITE_HOSTNAME", "dashboard.azurewebsites.net")
    (tmp_path / "dashboard").mkdir()
    write_json(tmp_path / "dashboard/data/collection-runs.json", [])
    write_json(tmp_path / "dashboard/data/secure-scores.json", [])
    app = create_app(
        Settings(
            dashboard_auth_enabled=True,
            dashboard_data_browser_enabled=True,
            dashboard_data_browser_role="Dashboard.Viewer",
        ),
        project_root=tmp_path,
    )
    header = (b"x-ms-client-principal", encoded_principal().encode())

    status, _ = asgi_get(app, "/api/data-browser/catalog", [header])

    assert status == 200


def test_recommendation_tracking_view_confirms_after_newer_absent_run():
    events = {
        "rec-1": {
            "UserStatus": "ReadyForValidation",
            "MarkedAtRunId": "run-1",
            "MarkedAtSnapshotUtc": "2026-09-27T12:00:00Z",
            "UpdatedUtc": "2026-09-27T12:05:00Z",
            "UpdatedByDisplayName": "Test User",
        },
    }

    rows = recommendation_tracking_view(events, [], "run-2", "2026-09-28T12:00:00Z")

    assert rows[0]["effectiveStatus"] == "Confirmed"
    assert rows[0]["remainingFindings"] == 0


def test_recommendation_tracking_view_reports_still_detected_without_changing_sla():
    finding = {
        "RecommendationId": "rec-1",
        "DataOrigin": "Live",
        "FindingStatus": "Open",
        "LastObservedUtc": "2026-09-28T12:00:00Z",
        "SlaStatus": "OpenOutsideSla",
    }
    events = {
        "rec-1": {
            "UserStatus": "ReadyForValidation",
            "MarkedAtRunId": "run-1",
            "MarkedAtSnapshotUtc": "2026-09-27T12:00:00Z",
        },
    }

    rows = recommendation_tracking_view(events, [finding], "run-2", "2026-09-28T12:00:00Z")

    assert rows[0]["effectiveStatus"] == "StillDetected"
    assert rows[0]["remainingFindings"] == 1
    assert finding["SlaStatus"] == "OpenOutsideSla"


def test_recommendation_tracking_view_waits_for_a_newer_run_and_hides_clear():
    events = {
        "rec-1": {
            "UserStatus": "ReadyForValidation",
            "MarkedAtRunId": "run-1",
            "MarkedAtSnapshotUtc": "2026-09-27T12:00:00Z",
        },
        "rec-2": {
            "UserStatus": "Clear",
            "MarkedAtRunId": "run-1",
            "MarkedAtSnapshotUtc": "2026-09-27T12:00:00Z",
        },
    }

    rows = recommendation_tracking_view(events, [], "run-1", "2026-09-27T12:00:00Z")

    assert rows == [{
        "recommendationId": "rec-1",
        "userStatus": "ReadyForValidation",
        "effectiveStatus": "ReadyForValidation",
        "remainingFindings": 0,
        "markedAtRunId": "run-1",
        "markedAtSnapshotUtc": "2026-09-27T12:00:00Z",
        "updatedUtc": "",
        "updatedByDisplayName": "",
    }]


class FakeRecommendationTrackingStore:
    def __init__(self):
        self.events = {}

    def latest(self):
        return self.events

    def record(self, recommendation_id, status, run_id, snapshot_time_utc, actor_object_id, actor_display_name):
        event = {
            "RecommendationId": recommendation_id,
            "UserStatus": status,
            "MarkedAtRunId": run_id,
            "MarkedAtSnapshotUtc": snapshot_time_utc,
            "UpdatedUtc": "2026-09-27T12:05:00Z",
            "UpdatedByObjectId": actor_object_id,
            "UpdatedByDisplayName": actor_display_name,
        }
        self.events[recommendation_id] = event
        return event


def test_recommendation_tracking_api_requires_role_and_records_action(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("WEBSITE_HOSTNAME", "dashboard.azurewebsites.net")
    (tmp_path / "dashboard").mkdir()
    write_json(tmp_path / "dashboard/data/recommendations.json", [{
        "RecommendationId": "rec-1",
        "RecommendationName": "Update software",
        "DataOrigin": "Live",
    }])
    write_json(tmp_path / "dashboard/data/findings.json", [])
    write_json(tmp_path / "dashboard/data/collection-runs.json", [{
        "CollectionRunId": "run-1",
        "SnapshotTimeUtc": "2026-09-27T12:00:00Z",
    }])
    write_json(tmp_path / "dashboard/data/secure-scores.json", [])
    tracking_store = FakeRecommendationTrackingStore()
    app = create_app(
        Settings(
            dashboard_auth_enabled=True,
            dashboard_recommendation_tracking_enabled=True,
        ),
        project_root=tmp_path,
        recommendation_tracking_store=tracking_store,
    )
    body = json.dumps({"recommendationId": "rec-1", "status": "InProgress"}).encode()
    headers = [
        (b"x-ms-client-principal", encoded_principal(["Dashboard.Viewer"]).encode()),
        (b"content-type", b"application/json"),
    ]

    denied_status, _, _ = asgi_response(
        app,
        "/api/recommendation-tracking",
        headers,
        method="PUT",
        request_body=body,
    )
    headers[0] = (
        b"x-ms-client-principal",
        encoded_principal(["Dashboard.Viewer", "Recommendation.Tracker"]).encode(),
    )
    updated_status, _, updated_body = asgi_response(
        app,
        "/api/recommendation-tracking",
        headers,
        method="PUT",
        request_body=body,
    )
    listed_status, listed_body = asgi_get(app, "/api/recommendation-tracking", headers)

    assert denied_status == 403
    assert updated_status == 200
    assert json.loads(updated_body)["status"] == "InProgress"
    assert listed_status == 200
    assert json.loads(listed_body)["items"][0]["effectiveStatus"] == "InProgress"


def test_recommendation_tracking_api_is_hidden_when_disabled(tmp_path: Path):
    (tmp_path / "dashboard").mkdir()
    app = create_app(Settings(), project_root=tmp_path)

    status, _ = asgi_get(app, "/api/recommendation-tracking")

    assert status == 404


def test_recommendation_tracking_requires_dashboard_authentication(tmp_path: Path):
    (tmp_path / "dashboard").mkdir()

    with pytest.raises(RuntimeError, match="requires dashboard authentication"):
        create_app(
            Settings(dashboard_recommendation_tracking_enabled=True),
            project_root=tmp_path,
            recommendation_tracking_store=FakeRecommendationTrackingStore(),
        )
