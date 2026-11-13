from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import threading
import pytest

from test_dashboard_queries import datasets, engine, finding
from vulnerability_view import dashboard_queries
from vulnerability_view.dashboard_control import QueryCancelled, QueryControl, query_control
from vulnerability_view.dashboard_products import DashboardProducts


def test_presentation_revision_invalidates_prepared_responses_not_indexes(tmp_path, monkeypatch):
    e = engine(tmp_path)
    request = {"view": "executive"}
    before = e._completed_product_key(request)
    index = e.path
    monkeypatch.setattr(dashboard_queries, "PREPARED_RESPONSE_VERSION", dashboard_queries.PREPARED_RESPONSE_VERSION + 1)
    assert e._completed_product_key(request) != before
    assert e.path == index
    assert e.reads == {}


def test_restored_summary_refreshes_wording_without_rebuilding_read_model(tmp_path, monkeypatch):
    e = engine(tmp_path, datasets(20))
    e.read_model.prepare({})
    original = e.read_model.document

    def legacy_document(db, key):
        result = original(db, key)
        if key == "summary" and result is not None:
            result["cards"]["executiveWorkload"][0][1:] = ["Detected findings", "Legacy context"]
        return result

    def no_rebuild(*args, **kwargs):
        pytest.fail("A presentation-only change must reuse the prepared read model")

    monkeypatch.setattr(e.read_model, "document", legacy_document)
    monkeypatch.setattr(e.read_model, "prepare", no_rebuild)
    monkeypatch.setattr(e, "_summary_metrics", no_rebuild)
    result = e.query({"view": "executive"})
    assert result["cards"]["executiveWorkload"][0] == [
        20, "Active exposure instances", "20 distinct active CVEs across 12 affected devices",
    ]
    assert result["cards"]["executiveWorkload"][1][1] == "Pending exposure instances"


def test_plan_probe_requires_existing_exact_aggregate_and_never_ingests(tmp_path):
    data = datasets(60)
    e = engine(tmp_path, data)
    assert not e.is_interactive({"view": "recommendations"})
    assert e.reads == {}
    e.read_model.prepare({})
    e = engine(tmp_path, data)
    for view in ("executive", "recommendations", "priority", "overview", "workstations", "sla"):
        assert e.is_interactive({"view": view})
        assert e.is_interactive({"view": view, "filters": {"newPeriodFilter": True}})
    assert e.is_interactive({"view": "detail", "selection": {"type": "recommendation", "id": "rec-0"}})
    assert e.is_interactive({"view": "overview", "filters": {"severity": "High"}})
    for request in (
        {"view": "trend"}, {"view": "executiveSnapshot"},
        {"view": "overview", "filters": {"search": "endpoint"}},
        {"view": "detail", "selection": {"type": "cve", "id": "CVE-2026-0000"}},
        {"view": "overview", "filters": {"slaPolicy": {"version": "changed"}}},
    ):
        assert not e.is_interactive(request)
    assert e.reads == {}


def test_identity_distinguishes_pages_tracking_and_inactive_ui_state(tmp_path):
    e = engine(tmp_path)
    request = {"snapshotId": "one", "view": "overview", "page": 0, "table": "findingsTable", "limit": 100}
    key = e.query_identity(request)
    assert e.query_identity({**request, "asyncQuery": True, "requestId": "other"}) == key
    assert e.query_identity({**request, "filters": {"activeView": "other", "newPeriodStart": "unused"}}) == key
    for change in (
        {"page": 1}, {"limit": 200}, {"mode": "cves"}, {"table": "exploitTable"},
        {"snapshotId": "two"}, {"selection": {"type": "finding", "id": "one"}},
        {"filters": {"recommendationTracking": [{"recommendationId": "rec-0", "effectiveStatus": "Confirmed"}]}},
    ):
        assert e.query_identity({**request, **change}) != key


def test_equivalent_period_probe_does_not_wait_for_running_report(tmp_path, monkeypatch):
    e = engine(tmp_path, datasets(60))
    e.read_model.prepare({})
    started, release = threading.Event(), threading.Event()
    original = e._build_report

    def blocked(*args):
        started.set()
        assert release.wait(5)
        return original(*args)

    monkeypatch.setattr(e, "_build_report", blocked)
    with ThreadPoolExecutor(max_workers=2) as pool:
        report = pool.submit(e.query, {"view": "executiveSnapshot"})
        try:
            assert started.wait(2)
            probe = pool.submit(e.is_interactive, {"view": "recommendations", "filters": {"newPeriodFilter": True}})
            assert probe.result(timeout=1)
            assert not report.done()
        finally:
            release.set()
        report.result(timeout=2)


@pytest.mark.parametrize("view", ["trend", "executiveSnapshot"])
def test_completed_reports_survive_engine_restart_without_recomputing(tmp_path, monkeypatch, view):
    data = datasets(120)
    request = {"view": view, "limit": 7}
    expected = engine(tmp_path, data).query(request)
    restored = engine(tmp_path, data)
    monkeypatch.setattr(restored, "_build_report", lambda *args: pytest.fail("completed report was recomputed"))
    assert restored.query(request) == expected


def test_report_products_do_not_pin_mutable_tracking_scope(tmp_path, monkeypatch):
    data = datasets(90)
    request = {"view": "executiveSnapshot"}
    expected = engine(tmp_path, data).query(request)
    restored = engine(tmp_path, data)
    monkeypatch.setattr(restored, "_build_report", lambda *args: pytest.fail("tracking invalidated immutable report"))
    actual = restored.query({**request, "filters": {
        "recommendationTrackingEnabled": True, "recommendationTrackingFilter": "Confirmed",
        "recommendationTracking": [{"recommendationId": "rec-0", "effectiveStatus": "Confirmed"}],
    }})
    assert actual["cards"] == expected["cards"]
    assert actual["charts"] == expected["charts"]
    assert actual["scope"]["recommendations"] == 1
    assert expected["scope"]["recommendations"] == 3


def test_report_pager_can_be_answered_before_job_admission(tmp_path, monkeypatch):
    e = engine(tmp_path, datasets(180))
    request = {"view": "executiveSnapshot", "limit": 1}
    e.query(request)
    monkeypatch.setattr(e, "_connect", lambda *args: pytest.fail("cache preflight opened SQLite"))
    page = e.cached({**request, "table": "executiveSnapshotRecommendationTable", "page": 1})
    assert page is not None
    assert page["tables"]["executiveSnapshotRecommendationTable"]["offset"] == 1
    assert len(page["tables"]["executiveSnapshotRecommendationTable"]["items"]) == 1


def test_report_materialization_does_not_decode_finding_payloads(tmp_path, monkeypatch):
    e = engine(tmp_path, datasets(150))
    e.prepare_workspace_indexes()
    original = e._connect

    @contextmanager
    def connect(*args, **kwargs):
        with original(*args, **kwargs) as db:
            original_unpack = dashboard_queries._unpack

            def payload(rowid, dataset):
                assert dataset != "findings", "report decoded finding payload"
                block = db.execute(
                    f'SELECT data FROM "{dataset.replace("-", "_")}_payloads" WHERE rowid=?',
                    ((rowid - 1) // 256,),
                ).fetchone()
                import json
                return json.loads(original_unpack(block[0]))[(rowid - 1) % 256][0]

            db.create_function("payload_json", 2, payload)
            yield db

    monkeypatch.setattr(e, "_connect", connect)
    assert e.query({"view": "executiveSnapshot"})["scope"]["findings"] == 150


@pytest.mark.parametrize("filters", [{}, {"severity": "High", "newPeriodFilter": True}])
@pytest.mark.parametrize("report", ["trend", "executiveSnapshot"])
def test_reports_avoid_full_fact_materialization_with_exact_nullable_name_fallback(tmp_path, monkeypatch, filters, report):
    data = datasets(120)
    for index, row in enumerate(data["findings"]):
        row["RecommendationId"] = (None, "", "rec-0", "rec-1")[index % 4]
        row["RecommendationName"] = (None, "", "fallback-a", "fallback-b")[(index // 4) % 4]
        row["FindingStatus"] = ("Open", "Fixed", "PendingVerification")[index % 3]
        if index % 3 == 1:
            row["FixedUtc"] = "2026-10-23T00:00:00Z"
    reference = engine(tmp_path / "reference", data)
    original_view = reference._view
    materialized = False

    def view(db, name, sql, args):
        nonlocal materialized
        original_view(db, name, sql, args)
        if name == "report_analytics" and not materialized:
            materialized = True
            db.execute("""
                CREATE TEMP TABLE report_metrics AS SELECT
                  _rowid,_first,_fixed,_reopened,_due,DeviceId,_exploit,FindingStatus,_observed,
                  _last,_snapshot,RecommendationId,RecommendationName,_rank,_cve,Severity,
                  DeviceName,_observed_text,SubscriptionId,OwnerTeam
                FROM report_analytics
            """)
            db.execute("DROP VIEW temp.report_analytics")
            original_view(db, "report_analytics", "SELECT * FROM report_metrics", [])

    monkeypatch.setattr(reference, "_view", view)
    request = {"view": report, "filters": filters}
    expected = reference.query(request)
    assert materialized
    actual = engine(tmp_path / "actual", data)
    connect = actual._connect
    statements = []

    @contextmanager
    def trace(*args, **kwargs):
        with connect(*args, **kwargs) as db:
            db.set_trace_callback(statements.append)
            yield db

    monkeypatch.setattr(actual, "_connect", trace)
    assert actual.query(request) == expected
    assert not any("CREATE TEMP TABLE REPORT_METRICS" in sql.upper() for sql in statements)


def test_complete_results_restore_without_querying_and_respect_semantic_identity(tmp_path, monkeypatch):
    data = datasets(60)
    request = {"view": "executive"}
    expected = engine(tmp_path, data).query(request)
    restored = engine(tmp_path, data)
    monkeypatch.setattr(restored, "_connect", lambda *args: pytest.fail("durable hit queried facts"))
    assert restored.cached(request) == expected
    assert restored.query(request) == expected
    modified = restored.cached(request)
    modified["scope"]["findings"] = -1
    assert restored.cached(request) == expected
    for filters in (
        {"severity": "High"},
        {"recommendationTrackingEnabled": True, "recommendationTracking": [
            {"recommendationId": "rec-0", "effectiveStatus": "Confirmed"},
        ]},
    ):
        assert restored.cached({**request, "filters": filters}) is None


def test_common_week_and_category_filter_uses_interactive_exact_cube(tmp_path):
    data = datasets(96)
    for index, row in enumerate(data["findings"]):
        row["Severity"] = ("High", "Low", "Critical", "High")[index % 4]
    data["findings"] = [row for row in data["findings"] if row["RecommendationId"] != "rec-1"]
    data["recommendation-machines"] = [finding(1, RecommendationId="rec-1")]
    request = {"view": "recommendations", "filters": {
        "newPeriodFilter": True, "newPeriod": "week", "severity": "High",
    }}
    expected = engine(tmp_path / "reference", data).query(request)
    actual = engine(tmp_path / "actual", data)
    actual.read_model.prepare({})
    assert actual.is_interactive(request)
    result = actual.query(request)
    assert result["metadata"].pop("readModel") == "filtered-aggregate"
    expected["metadata"].pop("readModel")
    assert result == expected


@pytest.mark.parametrize("change", ["named", "missing-name", "fixed", "overdue"])
def test_current_period_cube_report_requires_exact_uniform_clock_proof(tmp_path, monkeypatch, change):
    data = datasets(96)
    if change == "missing-name":
        data["recommendations"][0]["RecommendationName"] = None
    elif change == "fixed":
        data["findings"][0]["FixedUtc"] = "2026-10-24T00:00:00Z"
    elif change == "overdue":
        data["findings"][0]["SlaDueUtc"] = "2026-10-20T00:00:00Z"
    request = {"view": "executiveSnapshot", "filters": {"executiveSnapshotPeriod": "7days"}}
    expected = engine(tmp_path / "reference", data).query(request)
    actual = engine(tmp_path / "actual", data)
    actual.read_model.prepare({})
    calls = []
    original = actual._executive_workload_metrics

    def metrics(*args):
        calls.append(True)
        return original(*args)

    monkeypatch.setattr(actual, "_executive_workload_metrics", metrics)
    result = actual.query(request)
    result["metadata"].pop("readModel")
    expected["metadata"].pop("readModel")
    assert result == expected
    assert bool(calls) == (change != "named")


def test_weighted_clocks_preserve_nullable_typed_devices_and_daily_intervals(tmp_path):
    data = datasets(120)
    for index, row in enumerate(data["findings"]):
        row.update(
            DeviceId=(None, "", 0, "0", 1, 1.0, "1")[index % 7],
            FirstSeenUtc=("2026-10-10T12:00:00Z", "2026-10-20T12:00:00Z", None)[index % 3],
            FixedUtc=("2026-10-21T11:00:00Z", None)[index % 2],
            ReopenedUtc=("2026-10-21T12:00:00Z", "2026-10-20T12:00:00Z", None)[index % 3],
        )
    e = engine(tmp_path, data)
    e._ensure("findings")
    with e._connect() as db:
        e._view(db, "report_scope", "SELECT * FROM findings", [])
        e._view(db, "report_analytics", "SELECT * FROM findings", [])
        e._report_clocks(db, "1", [], {})
        for period in (
            {"label": "test", "start": "2026-10-10", "end": "2026-10-21"},
            {"label": "test", "start": "2026-10-22", "end": "2026-10-24"},
        ):
            assert e._summarize(db, period, "report_clocks") == e._summarize(db, period)
        start = dashboard_queries._timestamp("2026-10-01T00:00:00Z")
        assert e._daily_points(db, start, "report_clocks") == e._daily_points(db, start)


def test_post_group_workload_name_preserves_max_rank_representative_and_ties(tmp_path):
    data = datasets(60)
    data["recommendations"][0]["RecommendationName"] = None
    data["recommendations"][1]["RecommendationName"] = ""
    data["recommendations"] = data["recommendations"][:2]
    for index, row in enumerate(data["findings"]):
        row["RecommendationName"] = f"fallback-{index}"
        row["Severity"] = ("Critical", "High", "Low", "Critical", "Low")[index % 5]
    e = engine(tmp_path, data)
    e.prepare_workspace_indexes()
    with e._connect() as db:
        e._view(db, "report_analytics", "SELECT * FROM findings_analytics", [])
        start = dashboard_queries._timestamp("2026-10-18T00:00:00Z")
        end = dashboard_queries._timestamp("2026-10-24T23:59:59.999Z")
        e._executive_workload_metrics(db, start, end)
        expected = [tuple(row) for row in db.execute(f"""
          SELECT RecommendationId,
            coalesce((SELECT r.RecommendationName FROM recommendations r
              WHERE r.RecommendationId=f.RecommendationId LIMIT 1),f.RecommendationName,RecommendationId),
            max(_rank)
          FROM report_analytics f WHERE coalesce(RecommendationId,'')<>''
            AND ((_fixed BETWEEN {start} AND {end}) OR {e._open_at(end)})
          GROUP BY RecommendationId ORDER BY RecommendationId
        """)]
        actual = [tuple(row) for row in db.execute("""
          SELECT RecommendationId,
            coalesce((SELECT r.RecommendationName FROM recommendations r
              WHERE r.RecommendationId=m.RecommendationId LIMIT 1),
              (SELECT f.RecommendationName FROM findings_facts f WHERE f._rowid=m._sample_finding),
              RecommendationId),_maximum_rank
          FROM executive_workload_metrics m ORDER BY RecommendationId
        """)]
        assert actual == expected


def test_search_reuses_only_global_snapshot_metadata_not_filtered_activity(tmp_path, monkeypatch):
    data = datasets(60)
    data["findings"][0]["ProductName"] = "unique-needle"
    request = {"view": "overview", "filters": {"search": "unique-needle"}}
    expected = engine(tmp_path / "reference", data).query(request)
    actual = engine(tmp_path / "actual", data)
    actual.read_model.prepare({})
    statements = []
    connect = actual._connect

    @contextmanager
    def trace(*args, **kwargs):
        with connect(*args, **kwargs) as db:
            db.set_trace_callback(statements.append)
            yield db

    monkeypatch.setattr(actual, "_connect", trace)
    assert actual.query(request) == expected
    assert not any("SELECT DISTINCT OwnerTeam FROM" in sql for sql in statements)
    assert any("search_matches" in sql for sql in statements)
    assert expected["scope"]["findings"] == 1


@pytest.mark.parametrize("cube", [False, True])
def test_batched_recommendation_enrichment_matches_original_queries(tmp_path, monkeypatch, cube):
    data = datasets(180)
    for index, row in enumerate(data["findings"]):
        row["AssetClass"] = "AzureCloud" if index % 5 == 0 else "TraditionalIT"
        row["FindingStatus"] = ("Open", "Fixed", "PendingVerification")[index % 3]
        row["CveId"] = f"CVE-2026-{index % 29:04}"
    request = {"view": "recommendations", "filters": {"severity": "High"}}
    reference = engine(tmp_path, data)
    if cube:
        reference.read_model.prepare({})
    monkeypatch.setattr(reference, "_batch_impact", lambda *args: None)
    expected = reference.query(request)
    assert engine(tmp_path, data).query(request) == expected


def test_detail_pager_reuses_counts_and_does_not_query_sibling_tables(tmp_path, monkeypatch):
    e = engine(tmp_path, datasets(900))
    request = {"view": "detail", "selection": {"type": "recommendation", "id": "rec-0"}, "limit": 25}
    first = e.query(request)
    monkeypatch.setattr(e, "_stats", lambda *args, **kwargs: pytest.fail("detail counts were rescanned"))
    monkeypatch.setattr(e, "_machines", lambda *args, **kwargs: "invalid sibling SQL")
    monkeypatch.setattr(e, "_cves", lambda *args: "invalid sibling SQL")
    result = e.query({**request, "page": 1, "table": "pivotFindingTable"})
    assert result["detail"]["counts"] == first["detail"]["counts"]
    assert result["tables"]["pivotFindingTable"]["offset"] == 25
    assert result["tables"]["pivotTable"] == first["tables"]["pivotTable"]


def test_exact_scope_products_reuse_counts_across_views_and_tracking_changes(tmp_path, monkeypatch):
    data = datasets(90)
    engine(tmp_path, data).query({"view": "overview"})
    restored = engine(tmp_path, data)
    monkeypatch.setattr(restored, "_header", lambda *args: pytest.fail("immutable header was recomputed"))
    monkeypatch.setattr(restored, "_stats", lambda *args, **kwargs: pytest.fail("immutable scope was recounted"))
    result = restored.query({"view": "recommendations", "filters": {
        "recommendationTrackingEnabled": True, "recommendationTrackingFilter": "Confirmed",
        "recommendationTracking": [{"recommendationId": "rec-0", "effectiveStatus": "Confirmed"}],
    }})
    assert result["scope"]["recommendations"] == 1
    assert result["scope"]["findings"] == 90


def test_generic_export_uses_one_query_and_one_cursor_for_all_rows(tmp_path, monkeypatch):
    e = engine(tmp_path, datasets(1500))
    request = {"view": "detail", "selection": {"type": "recommendation", "id": "rec-0"}, "table": "pivotFindingTable"}
    expected = []
    for page in range(3):
        expected.extend(e.query({**request, "page": page, "limit": 200})["tables"]["pivotFindingTable"]["items"])
    calls = 0
    original = e.query

    def query(payload):
        nonlocal calls
        calls += 1
        return original(payload)

    monkeypatch.setattr(e, "query", query)
    assert list(e.iter_export(request)) == expected
    assert calls == 1


def test_finding_export_reuses_exact_search_matches_without_payload_search_scan(tmp_path, monkeypatch):
    data = datasets(60)
    for index in (2, 14, 33):
        data["findings"][index]["ProductName"] = "unique-export-needle"
    e = engine(tmp_path, data)
    request = {
        "view": "overview", "mode": "findings", "table": "findingsTable",
        "filters": {"search": "unique-export-needle"},
    }
    expected = e.query(request)["tables"]["findingsTable"]["items"]
    e.search_index.prepare()
    connect = e._connect

    @contextmanager
    def indexed_only(*args, **kwargs):
        with connect(*args, **kwargs) as db:
            db.create_function(
                "payload_search", 2,
                lambda *args: pytest.fail("finding export performed a compressed-evidence search scan"),
            )
            yield db

    monkeypatch.setattr(e, "_connect", indexed_only)
    assert list(e.iter_export(request)) == expected
    assert len(expected) == 3


def test_search_match_products_preserve_unicode_substring_and_reuse_across_views(tmp_path, monkeypatch):
    data = datasets(0)
    data["findings"] = [
        finding(1, ProductName="MÜNCHEN Straße İSTANBUL"),
        finding(2, ProductName="Null \u0000 trailing needle"),
        finding(3, ProductName=None),
        finding(4, ProductName="prefixneedleSuffix"),
    ]
    for term in ("ünch", "straße", "i\u0307stan", "needle", "null", "no matches"):
        request = {"view": "overview", "filters": {"search": term}}
        e = engine(tmp_path, data)
        expected = e.query(request)
        restored = engine(tmp_path, data)
        original = dashboard_queries.startup_stage

        @contextmanager
        def stage(name):
            assert name != "query:search:exact-substring-scan"
            with original(name):
                yield

        with monkeypatch.context() as patch:
            patch.setattr(dashboard_queries, "startup_stage", stage)
            assert restored.query(request) == expected


def test_sqlite_interrupt_translates_cancelled_control(tmp_path):
    e = engine(tmp_path)
    control = QueryControl(10)
    with pytest.raises(QueryCancelled), query_control(control), e._connect() as db:
        control.cancel()
        db.execute("""
            WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<100000)
            SELECT sum(i) FROM n
        """).fetchone()


def test_controlled_connection_bounds_sqlite_busy_wait(tmp_path):
    e = engine(tmp_path)
    with query_control(QueryControl(10)), e._connect() as db:
        assert db.execute("PRAGMA busy_timeout").fetchone()[0] == 1000


def test_fallback_history_is_separate_and_reused_without_event_reingestion(tmp_path):
    data = datasets(60)
    data["finding-events"] = [finding(1, EventType="Fixed", EventTimeUtc="2026-10-24T11:00:00Z")]
    data["recommendation-events"] = [finding(2, EventType="New", EventTimeUtc="2026-10-24T10:00:00Z")]
    e = engine(tmp_path, data)
    published = []
    e.history_index_publisher = published.append
    expected = e.query({"view": "trend", "filters": {"reportingChange": "All"}})
    assert e.history_index_path is not None
    assert published == [e.history_index_path]
    with e._connect() as db:
        assert not db.execute("SELECT 1 FROM main.sqlite_master WHERE name='finding_events_facts'").fetchone()
        assert not db.execute("SELECT 1 FROM main.datasets WHERE name='finding-events'").fetchone()
        assert not db.execute("SELECT 1 FROM main.fields WHERE dataset='finding-events'").fetchone()
        assert db.execute("SELECT count(*) FROM finding_events").fetchone()[0] == 1
        assert db.execute("PRAGMA history_index.journal_mode").fetchone()[0] == "delete"
    restored = engine(tmp_path, data)
    actual = restored.query({"view": "trend", "filters": {"reportingChange": "All"}})
    assert actual == expected
    assert restored.reads == {}
    assert restored.dataset_info("finding-events")["rowCount"] == 1
    assert restored.indexed_rows()["finding-events"] == 1


def test_restored_history_loader_does_not_read_curated_events(tmp_path):
    data = datasets(10)
    data["finding-events"] = [finding(1, EventType="Fixed", EventTimeUtc="2026-10-24T11:00:00Z")]
    source = engine(tmp_path / "source", data)
    source.query({"view": "trend"})
    target = engine(tmp_path / "target", data)
    target.history_index_loader = lambda: source.history_index_path
    result = target.query({"view": "trend"})
    assert result["tables"]["lifecycleHistoryTable"]["total"] == 1
    assert "finding-events" not in target.reads
    assert "recommendation-events" not in target.reads


def test_missing_optional_history_still_serves_empty_lifecycle_with_notices(tmp_path):
    data = datasets(10)
    data.pop("finding-events")
    data.pop("recommendation-events")
    e = engine(tmp_path, data)
    result = e.query({"view": "trend"})
    assert result["tables"]["lifecycleHistoryTable"]["total"] == 0
    assert any("finding-events.json is unavailable" in notice for notice in result["notices"])


def test_published_history_build_preserves_existing_collector_artifact_layout(tmp_path):
    data = datasets(0)
    data["finding-events"] = [finding(1, EventType="Fixed")]
    e = engine(tmp_path, data)
    e.build_index({"finding-events": 1, "recommendation-events": 0})
    assert e.history_index_path is None
    assert not (tmp_path / "history").exists()
    with e._connect() as db:
        assert db.execute("SELECT count(*) FROM main.finding_events_facts").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM main.recommendation_events_facts").fetchone()[0] == 0


def test_query_products_bound_entries_and_keep_primary_unchanged(tmp_path):
    primary = tmp_path / "primary.sqlite3"
    primary.write_bytes(b"untouched")
    products = DashboardProducts(primary)
    for index in range(30):
        products.save_document(str(index), {"index": index})
    assert products.document("0") is None
    assert products.document("29") == {"index": 29}
    products.validate()
    assert primary.read_bytes() == b"untouched"


def test_product_publication_hook_sees_committed_valid_database(tmp_path):
    products = DashboardProducts(tmp_path / "primary.sqlite3")
    published = []

    def publish(path):
        products.validate(path)
        published.append(path)

    products.publisher = publish
    products.save_document("scope:one", {"findings": 10})
    assert published == [products.path]


def test_query_products_preserve_default_reports_within_existing_entry_budget(tmp_path):
    products = DashboardProducts(tmp_path / "primary.sqlite3")
    for view in range(10):
        products.save_document(f"default:{view}", {"view": view})
    for index in range(40):
        products.save_document(f"filtered:{index}", {"index": index})
    for view in range(10):
        assert products.document(f"default:{view}") == {"view": view}
    assert products.document("filtered:0") is None
    assert products.document("filtered:39") == {"index": 39}
    products.validate()
