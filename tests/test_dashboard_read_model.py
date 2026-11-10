import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy

import pytest

from vulnerability_view import dashboard_read_model
from test_dashboard_queries import SNAPSHOT, datasets, engine, finding


def canonical(result):
    result = deepcopy(result)
    result["metadata"].pop("readModel", None)
    return result


@pytest.mark.parametrize("view", ["executive", "recommendations", "priority", "overview", "workstations", "sla", "detail"])
def test_redundant_first_seen_restriction_reuses_model_without_changing_results(tmp_path, view):
    data = datasets(60)
    filters = {"newPeriodFilter": True}
    payload = {
        "view": view, "filters": filters,
        "selection": {"type": "recommendation", "id": "rec-0"},
    }
    original = engine(tmp_path, data)
    expected = canonical(original.query(payload))
    original.read_model.prepare({})
    restored = engine(tmp_path, data)
    result = restored.query(payload)
    assert result["metadata"]["readModel"] == "aggregate"
    assert canonical(result) == expected


@pytest.mark.parametrize("change", ["older", "future", "missing", "machine-only", "policy"])
def test_period_reuse_rejects_non_equivalent_evidence_and_policy(tmp_path, change):
    data = datasets(20)
    filters = {"newPeriodFilter": True}
    if change == "older":
        data["findings"][0].update(FirstObservedUtc="2026-01-01T00:00:00Z")
    elif change == "future":
        data["findings"][0].update(FirstObservedUtc="2026-10-25T00:00:00Z")
    elif change == "missing":
        data["findings"][0].update(FirstObservedUtc=None, FirstSeenUtc=None)
    elif change == "machine-only":
        data["findings"] = [row for row in data["findings"] if row["RecommendationId"] != "rec-1"]
        data["recommendation-machines"] = [finding(1, RecommendationId="rec-1")]
    else:
        filters["slaPolicy"] = {"policyVersion": "changed"}
    original = engine(tmp_path, data)
    payload = {"view": "recommendations", "filters": filters}
    expected = canonical(original.query(payload))
    original.read_model.prepare({})
    result = engine(tmp_path, data).query(payload)
    assert result["metadata"]["readModel"] == "exact-query"
    assert canonical(result) == expected


@pytest.mark.parametrize("filters", [
    {},
    {"origin": "Live", "severity": "High"},
    {"exposureStatus": "All", "recommendationTypes": ["Misconfiguration", "Vulnerability"]},
    {"exposureStatus": "PendingOnly", "team": "Operations", "subscription": "NoSubscription"},
    {"workloadGrouping": {"rules": [
        {"id": "endpoints", "label": "Endpoints", "field": "DeviceName", "operator": "prefix", "value": "endpoint-"},
    ]}},
])
def test_persisted_aggregate_reads_match_exact_queries_and_exports(tmp_path, filters):
    data = datasets(237)
    for index, row in enumerate(data["findings"]):
        row.update(
            FindingStatus=["Open", "Fixed", "PendingVerification", "OutOfScope", "Reopened"][index % 5],
            PriorityScore=index % 3,
            Severity=["Critical", "High", "Medium", "Low"][index % 4],
            SlaStatus=["OpenOutsideSla", "FixedWithinSla", "FixedOutsideSla", "OpenWithinSla"][index % 4],
            FixedUtc=SNAPSHOT if index % 5 == 1 else None,
            SubscriptionId="" if index % 5 == 2 else "subscription-1",
        )
    data["recommendations"][2]["RemediationType"] = "Configuration"
    data["recommendations"][2]["RecommendationName"] = "Configuration settings"
    e = engine(tmp_path, data)
    requests = [
        {"view": view, "filters": filters, "page": page, "limit": 7}
        for view in ("executive", "recommendations", "priority", "overview", "workstations", "sla")
        for page in (0, 1)
    ] + [
        {"view": "detail", "filters": filters, "selection": selection, "page": page, "limit": 7}
        for selection in (
            {"type": "recommendation", "id": "rec-0"},
            {"type": "recommendation", "id": "missing"},
            {"type": "machine", "id": "device-0"},
            {"type": "machine", "id": "rule:endpoints"},
            {"type": "cve", "id": "CVE-2026-0000"},
            {"type": "finding", "id": "finding-0000"},
        )
        for page in (0, 1)
    ]
    expected = [canonical(e.query(request)) for request in requests]
    primary_hash = hashlib.sha256(e.path.read_bytes()).hexdigest()
    e.read_model.prepare(filters)
    # A new engine proves disk reuse, not reuse of warm response/header caches.
    restored = engine(tmp_path, data)
    for request, reference in zip(requests, expected, strict=True):
        actual = restored.query(request)
        assert actual["metadata"]["readModel"] == "aggregate"
        for name, table in reference["tables"].items():
            for position, (left, right) in enumerate(zip(actual["tables"][name]["items"], table["items"])):
                if left != right:
                    pytest.fail(str((request, name, position, {
                        key: (left.get(key), right.get(key)) for key in left.keys() | right.keys()
                        if left.get(key) != right.get(key)
                    })))
        assert canonical(actual) == reference, request
    for view, table in (
        ("recommendations", "recommendationTable"), ("detail", "pivotCveTable"),
        ("overview", "findingsTable"),
    ):
        payload = {"view": view, "filters": filters, "table": table,
                   "selection": {"type": "recommendation", "id": "rec-0"}}
        assert list(restored.iter_export(payload)) == list(e.iter_export(payload))
    assert hashlib.sha256(e.path.read_bytes()).hexdigest() == primary_hash


def test_read_model_does_not_change_collection_index_or_publish_evidence(tmp_path, monkeypatch):
    e = engine(tmp_path)
    e.build_index({"findings": 237})
    assert not list(tmp_path.glob("*-read-*"))
    assert dashboard_read_model.VERSION == 5
    with e._connect() as db:
        assert not db.execute("SELECT name FROM sqlite_master WHERE name LIKE '%read_model%'").fetchall()
    import vulnerability_view.dashboard_index as index
    monkeypatch.setattr(dashboard_read_model.DashboardReadModel, "prepare",
                        lambda *args: pytest.fail("Collector must not construct viewer aggregates"))
    assert index.QUERY_INDEX_VERSION == 10
    e.build_index({"findings": 237})


def test_ordinary_queries_do_not_rescan_findings_for_aggregates(tmp_path, monkeypatch):
    e = engine(tmp_path, datasets(1200))
    e.read_model.prepare({})
    restored = engine(tmp_path, datasets(1200))
    original = restored._connect
    statements = []

    @contextmanager
    def trace(*args, **kwargs):
        with original(*args, **kwargs) as db:
            db.set_trace_callback(statements.append)
            yield db

    monkeypatch.setattr(restored, "_connect", trace)
    for payload in [
        {"view": "executive"}, {"view": "recommendations"}, {"view": "priority"},
        {"view": "detail", "selection": {"type": "recommendation", "id": "rec-0"}},
        {"view": "detail", "selection": {"type": "recommendation", "id": "rec-0"}, "page": 1},
    ]:
        assert restored.query(payload)["metadata"]["readModel"] == "aggregate"
    expensive = [
        sql for sql in statements
        if ("FROM scoped" in sql or "FROM detail_scope" in sql or "FROM sla_scope" in sql)
        and ("count(" in sql.lower() or "group by" in sql.lower())
        and not sql.lstrip().startswith("CREATE TEMP VIEW")
    ]
    assert expensive == []


def test_workflow_updates_remain_live_without_rebuilding_aggregates(tmp_path):
    data = datasets()
    e = engine(tmp_path, data)
    e.read_model.prepare({})
    for status in ("InProgress", "Confirmed"):
        f = {"recommendationTrackingEnabled": True, "recommendationTrackingFilter": status,
             "recommendationTracking": [{"recommendationId": "rec-0", "effectiveStatus": status}]}
        result = engine(tmp_path, data).query({"view": "recommendations", "filters": f})
        assert result["scope"]["recommendations"] == 1
        assert result["tables"]["recommendationTable"]["items"][0]["TrackingStatus"] == status
    assert len(list(tmp_path.glob("*-read-*.sqlite3"))) == 1


def test_scope_mismatch_uses_exact_filters_not_incompatible_aggregates(tmp_path):
    e = engine(tmp_path)
    e.read_model.prepare({})
    for f in ({"search": "finding-0001"}, {"slaPolicy": {"policyVersion": "changed"}},
              {"workloadGrouping": {"rules": []}}):
        result = e.query({"view": "overview", "filters": f})
        assert result["metadata"]["readModel"] == "exact-query"
    assert e.query({"view": "overview", "filters": {"search": "finding-0001"}})["scope"]["findings"] == 1


def test_failed_build_cannot_publish_partial_aggregates_and_can_retry(tmp_path, monkeypatch):
    e = engine(tmp_path)
    original = e._summary_metrics

    def fail(*args):
        raise RuntimeError("Deliberate interrupted read-model build")

    monkeypatch.setattr(e, "_summary_metrics", fail)
    with pytest.raises(RuntimeError, match="Deliberate interrupted"):
        e.read_model.prepare({})
    assert not e.read_model.path({}).exists()
    assert not list(tmp_path.glob("*.building"))
    monkeypatch.setattr(e, "_summary_metrics", original)
    e.read_model.prepare({})
    assert e.read_model.path({}).is_file()


def test_invalid_completed_model_is_an_explicit_failure(tmp_path):
    e = engine(tmp_path)
    e.read_model.prepare({})
    with sqlite3.connect(e.read_model.path({})) as db:
        db.execute("UPDATE metadata SET identity='wrong'")
    with pytest.raises(ValueError, match="does not match"):
        e.query({"view": "executive"})


def test_read_model_is_bounded_atomic_single_flight_and_read_only(tmp_path, monkeypatch):
    e = engine(tmp_path)
    original = e.read_model._build
    builds = []

    def build(*args):
        builds.append(1)
        original(*args)

    monkeypatch.setattr(e.read_model, "_build", build)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: e.read_model.prepare({}), range(4)))
    assert builds == [1]
    with e._connect() as db:
        assert e.read_model.attach(db, {})
        assert db.execute("PRAGMA read_model.cache_size").fetchone()[0] == -2048
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            db.execute("UPDATE read_model.metadata SET identity='wrong'")
    assert e.read_model.path({}).stat().st_size <= dashboard_read_model.MAX_BYTES


def test_capacity_failure_keeps_original_index_and_no_completed_model(tmp_path, monkeypatch):
    e = engine(tmp_path)
    e.prepare_workspace_indexes()
    monkeypatch.setattr(dashboard_read_model, "MAX_BYTES", 16 * 1024)
    with pytest.raises(sqlite3.OperationalError, match="full"):
        e.read_model.prepare({})
    assert not e.read_model.path({}).exists()
    assert not list(tmp_path.glob("*.building*"))
    assert e.query({"view": "overview"})["scope"]["findings"] == 237


def test_persisted_tracking_counts_preserve_typed_recommendation_identifiers(tmp_path):
    data = datasets(0)
    data["findings"] = [finding(index, RecommendationId=value)
                        for index, value in enumerate((1, "1", 2.5, "two"))]
    e = engine(tmp_path, data)
    expected = e.active_recommendation_counts(SNAPSHOT)
    e.read_model.prepare({})
    restored = engine(tmp_path, data)
    assert restored.active_recommendation_counts(SNAPSHOT) == expected
