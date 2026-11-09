"""Last modified: 2026-11-05.
Purpose: Verify snapshot-pinned query counts, filtering, evidence, and exports.
"""

from concurrent.futures import ThreadPoolExecutor
from collections import OrderedDict
from contextlib import contextmanager
import json
import math
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vulnerability_view.dashboard_queries import DashboardQueryEngine
from vulnerability_view import dashboard_queries


SNAPSHOT = "2026-10-24T12:00:00Z"


def test_compact_evidence_blocks_share_identifiers_and_preserve_sql_types(tmp_path):
    values = [None, "", 0, "0", 1, 1.0, True, False, "Case", "case", "MÜNCHEN", ["x"], {"x": 1}]
    data = datasets(0)
    data["findings"] = [
        finding(index, DeviceId=value, DeviceName=value, RecommendationId=value)
        for index, value in enumerate(values * 40)
    ]
    e = engine(tmp_path, data)
    e._ensure("findings")
    assert list(e.iter_dataset("findings")) == data["findings"]
    with e._connect() as db:
        assert db.execute("PRAGMA page_size").fetchone()[0] == dashboard_queries.QUERY_INDEX_PAGE_BYTES
        assert db.execute("PRAGMA max_page_count").fetchone()[0] * db.execute("PRAGMA page_size").fetchone()[0] == 7 * 1024**3
        assert db.execute("SELECT count(*) FROM findings_payloads").fetchone()[0] == math.ceil(len(data["findings"]) / 256)
        assert db.execute("SELECT count(*) FROM shared_values").fetchone()[0] <= len(values)
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE name='findings_searches'").fetchone()[0] == 0
        actual = db.execute("SELECT DeviceId,typeof(DeviceId) FROM findings ORDER BY _rowid").fetchall()
        for row, original in zip(actual, data["findings"], strict=True):
            expected = db.execute(
                "SELECT json_extract(?,'$.DeviceId'),typeof(json_extract(?,'$.DeviceId'))",
                (json.dumps(original), json.dumps(original)),
            ).fetchone()
            assert tuple(row) == tuple(expected)


def test_compact_covering_analytics_preserve_empty_identifier_counts(tmp_path, monkeypatch):
    data = datasets(0)
    data["findings"] = [
        finding(index, DeviceId=device, RecommendationId=recommendation)
        for index, (device, recommendation) in enumerate(((None, None), ("", ""), ("device", "rec"), ("device", "rec")))
    ]
    e = engine(tmp_path, data)
    e.query({"view": "overview"})
    def header():
        out = {key: {} for key in ("activity", "facets", "metadata", "texts")}
        with e._connect() as db:
            e._header(db, out, {"origin": "Live"})
        return out
    broad = header()
    monkeypatch.setattr(e, "_broad_analytics", lambda *args, **kwargs: False)
    assert header() == broad


def test_index_capacity_error_reports_database_budget_and_free_disk(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard_queries, "QUERY_INDEX_MAX_BYTES", 512 * 1024)
    e = engine(tmp_path, datasets(2000))
    with pytest.raises(dashboard_queries.DashboardIndexCapacityError, match="database limit=.*filesystem free="):
        e._ensure("findings")


def test_shared_identifier_lookups_use_fact_indexes_instead_of_scanning(tmp_path):
    data = datasets(5000)
    for index, row in enumerate(data["findings"]):
        row["RecommendationId"] = f"recommendation-{index % 250}"
    e = engine(tmp_path, data)
    e._ensure("findings")
    with e._connect() as db:
        plan = " ".join(row["detail"] for row in db.execute(
            "EXPLAIN QUERY PLAN SELECT count(*) FROM findings WHERE RecommendationId=?",
            ("recommendation-249",),
        ))
        assert "SEARCH v_RecommendationId USING COVERING INDEX shared_values_lookup" in plan
        assert "SEARCH f USING" in plan
        assert "SCAN f" not in plan


def test_set_based_remediation_matches_correlated_reference_with_nullable_and_typed_keys(tmp_path):
    rng = random.Random(37)
    data = datasets(0)
    identifiers = [None, "", "one", "two", 1, 1.0, "1"]
    dates = [None, "2026-10-12T00:00:00Z", "2026-10-20T12:00:00Z", "2026-10-24T11:00:00Z"]
    data["findings"] = [
        finding(
            index, DeviceId=rng.choice(identifiers), RecommendationId=rng.choice(identifiers),
            RecommendationName=rng.choice(identifiers),
            FirstSeenUtc=rng.choice(dates), FixedUtc=rng.choice(dates), ReopenedUtc=rng.choice(dates),
        )
        for index in range(160)
    ]
    e = engine(tmp_path, data)
    e._ensure("findings")
    with e._connect() as db:
        e._view(db, "report_scope", "SELECT * FROM findings", [])
        for start in ("2026-10-10", "2026-10-19", "2026-10-24"):
            for end in ("2026-10-20", "2026-10-24"):
                begin = dashboard_queries._timestamp(start + "T00:00:00Z")
                finish = dashboard_queries._timestamp(end + "T23:59:59.999Z")
                cleared = f"""
                  SELECT DISTINCT coalesce(RecommendationId,RecommendationName,'') rec,DeviceId
                  FROM report_scope f WHERE _fixed BETWEEN {begin} AND {finish} AND coalesce(DeviceId,'')<>''
                  AND NOT EXISTS(SELECT 1 FROM report_scope o WHERE o.DeviceId=f.DeviceId
                    AND coalesce(o.RecommendationId,o.RecommendationName,'')=coalesce(f.RecommendationId,f.RecommendationName,'')
                    AND {e._open_at(finish)})
                """
                assets = db.execute(f"SELECT count(DISTINCT DeviceId) FROM ({cleared})").fetchone()[0]
                findings = db.execute(f"""
                  SELECT count(*) FROM report_scope f WHERE _fixed BETWEEN {begin} AND {finish}
                  AND EXISTS(SELECT 1 FROM ({cleared}) c WHERE c.DeviceId=f.DeviceId
                    AND c.rec=coalesce(f.RecommendationId,f.RecommendationName,''))
                """).fetchone()[0]
                result = e._remediation_outcome(db, start, end)
                assert result["AssetsRemediated"] == assets
                assert result["FindingsResolved"] == findings


def test_recommendation_domain_union_has_no_payload_columns_or_decoder_operations(tmp_path):
    data = datasets(20)
    data["findings"][0]["AssetClass"] = "AzureCloud"
    e = engine(tmp_path, data)
    e.prepare_workspace_indexes()
    with e._connect() as db:
        e._match_recommendations(db, {})
        assert [row["name"] for row in db.execute("PRAGMA table_info(rec_all_evidence)")] == [
            "RecommendationId", "AssetClass",
        ]
        sql = """SELECT DISTINCT CASE WHEN AssetClass='AzureCloud' THEN 'Cloud' ELSE 'Devices' END
          FROM rec_all_evidence WHERE RecommendationId=?"""
        bytecode = list(db.execute("EXPLAIN " + sql, ("rec-0",)))
        assert not any(row["p4"] and "payload_" in str(row["p4"]) for row in bytecode)

        def unexpected(*args):
            raise AssertionError("Domain lookup must not decode compressed evidence")

        db.create_function("payload_json", 2, unexpected)
        db.create_function("payload_search", 2, unexpected)
        assert {row[0] for row in db.execute(sql, ("rec-0",))} == {"Cloud", "Devices"}


def test_recommendation_search_fallback_still_searches_finding_evidence(tmp_path):
    data = datasets(20)
    data["findings"][0]["ProductName"] = "Unique finding evidence text"
    e = engine(tmp_path, data)
    e.prepare_workspace_indexes()
    with e._connect() as db:
        e._match_recommendations(db, {"search": "unique finding evidence text"})
        assert [row[0] for row in db.execute("SELECT RecommendationId FROM matched_recommendations")] == ["rec-0"]


@pytest.mark.parametrize("selection", [
    {"type": "recommendation", "id": "rec-0"},
    {"type": "machine", "id": "device-0"},
    {"type": "cve", "id": "CVE-2026-0000"},
    {"type": "finding", "id": "finding-0000"},
    {"type": "machine", "id": "rule:endpoints"},
])
def test_detail_counts_and_sorting_decode_only_displayed_finding_payloads(tmp_path, selection):
    data = datasets(1200)
    e = engine(tmp_path, data)
    e.prepare_workspace_indexes()
    reads = {}
    payload_reads = 0
    statement = ""
    filters = {"workloadGrouping": {"rules": [
        {"id": "endpoints", "label": "Endpoints", "field": "DeviceName", "operator": "prefix", "value": "endpoint-"},
    ]}}
    with e._connect(filters) as db:
        def trace(sql):
            nonlocal statement
            statement = sql

        def payload(rowid, dataset):
            nonlocal payload_reads
            payload_reads += dataset == "findings"
            if statement.startswith("SELECT count(*) FROM ("):
                reads[statement] = reads.get(statement, 0) + 1
            return json.dumps(data[dataset][rowid - 1])

        db.set_trace_callback(trace)
        db.create_function("payload_json", 2, payload)
        e._finding_scope(db, "scoped", "1", [], filters)
        out = {"texts": {}, "cards": {}, "tables": {}}
        e._detail(db, out, {"selection": selection, "limit": 5}, filters, [])
    assert not reads, {sql: count for sql, count in reads.items()}
    assert payload_reads <= sum(len(table["items"]) for table in out["tables"].values()) + 2


@pytest.mark.parametrize("status", [None, "", "Unavailable", "Available", False, 0, {"source": "unknown"}, ["unknown"]])
def test_paged_cve_metadata_preserves_sql_json_scalar_semantics(tmp_path, status):
    data = datasets(1)
    data["findings"][0]["CveMetadataStatus"] = status
    e = engine(tmp_path, data)
    result = e.query({"view": "overview", "mode": "cves"})["tables"]["findingsTable"]["items"][0]
    with e._connect() as db:
        expected = db.execute("""
            SELECT coalesce(nullif(json_extract(data,'$.CveMetadataStatus'),''),'Available') status,
              CASE WHEN json_extract(data,'$.CveMetadataStatus')='Unavailable' THEN NULL ELSE _exploit END exploit
            FROM findings
        """).fetchone()
    assert result["CveMetadataStatus"] == expected["status"]
    assert type(result["CveMetadataStatus"]) is type(expected["status"])
    assert result["KnownExploit"] == expected["exploit"]


def finding(index=0, **changes):
    return {
        "FindingKey": f"finding-{index:04}",
        "DeviceId": f"device-{index % 12}",
        "DeviceName": f"endpoint-{index % 12}",
        "CveId": f"CVE-2026-{index % 37:04}",
        "RecommendationId": f"rec-{index % 3}",
        "RecommendationName": "Update vulnerable software",
        "FindingStatus": "Open", "Severity": "High",
        "CvssScore": 8.1, "PriorityScore": index,
        "DataOrigin": "Live", "AssetClass": "TraditionalIT",
        "SubscriptionId": "subscription-1", "OwnerTeam": "Operations",
        "FirstSeenUtc": "2026-10-23T13:00:00Z",
        "FirstObservedUtc": "2026-10-23T13:00:00Z",
        "LastSeenUtc": "2026-10-24T11:00:00Z",
        "LastObservedUtc": SNAPSHOT,
        "SnapshotTimeUtc": SNAPSHOT,
        "SlaStatus": "OpenWithinSla", "SlaDueUtc": "2026-11-01T00:00:00Z",
        **changes,
    }


def datasets(count=237):
    return {
        "findings": [finding(i) for i in range(count)],
        "recommendations": [{
            "RecommendationId": f"rec-{i}", "RecommendationName": f"Update vulnerability {i}",
            "SeverityScore": 8, "Status": "Active", "DataOrigin": "Live",
            "RemediationType": "SecurityUpdate", "ExposedMachinesCount": 12,
        } for i in range(3)],
        "devices": [finding(i, OnboardingStatus="Onboarded", HealthStatus="Active") for i in range(12)],
        "recommendation-machines": [],
        "collection-runs": [
            {"SnapshotTimeUtc": "2026-10-23T12:00:00Z", "DataOrigin": "Live", "RunStatus": "Success"},
            {"SnapshotTimeUtc": SNAPSHOT, "DataOrigin": "Live", "RunStatus": "Success"},
        ],
        "subscriptions": [{"SubscriptionId": "subscription-1", "SubscriptionName": "Production"}],
        "secure-scores": [{"ScorePercent": 80, "DataOrigin": "Live", "SnapshotTimeUtc": SNAPSHOT}],
        "run-history": [],
        "finding-events": [],
        "recommendation-events": [],
        "vulnerabilities": [],
    }


def engine(root, data=None, snapshot_id="snapshot-1", snapshot_time=SNAPSHOT):
    data = datasets() if data is None else data
    reads = {}

    def rows(name):
        reads[name] = reads.get(name, 0) + 1
        if name not in data:
            raise FileNotFoundError(name + ".json")
        yield from data[name]

    result = DashboardQueryEngine(root, snapshot_id, snapshot_time, rows)
    result.reads = reads
    return result


def platform_datasets():
    data = datasets(0)
    data["findings"] = [
        finding(0, DeviceId="win", OSPlatform="Windows11", RecommendationId="rec-0", CveId="CVE-2026-0001"),
        finding(1, DeviceId="linux", OSPlatform="Ubuntu", RecommendationId="rec-1", CveId="CVE-2026-0001"),
        finding(2, DeviceId="unknown-none", OSPlatform=None, RecommendationId="rec-2"),
        finding(3, DeviceId="unknown-empty", OSPlatform="", RecommendationId="rec-2"),
        finding(4, DeviceId="unknown-text", OSPlatform="Unknown", RecommendationId="rec-2"),
        finding(5, DeviceId="win", OSPlatform="Windows11", RecommendationId="rec-1", CveId="CVE-2026-0001"),
    ]
    devices = {row["DeviceId"]: row for row in data["findings"]}
    devices["mac"] = finding(6, DeviceId="mac", OSPlatform="macOS")
    devices["android"] = finding(7, DeviceId="android", OSPlatform="Android")
    data["devices"] = [
        {**row, "OnboardingStatus": "Onboarded", "HealthStatus": "Active"}
        for row in devices.values()
    ]
    data["recommendations"].append({
        **data["recommendations"][0], "RecommendationId": "rec-machine-only",
    })
    data["recommendation-machines"] = [
        finding(7, DeviceId="android", OSPlatform="Android", RecommendationId="rec-machine-only"),
    ]
    return data


@pytest.mark.parametrize("os_type,findings,recommendations,machines", [
    ("All", 6, 4, 7),
    ("Windows11", 2, 2, 1),
    ("Ubuntu", 1, 1, 1),
    ("Unknown", 3, 1, 3),
    ("Android", 0, 1, 1),
    ("macOS", 0, 0, 1),
    ("missing' OR 1=1 --", 0, 0, 0),
])
def test_os_type_filters_every_view_inventory_and_exports(
    tmp_path, os_type, findings, recommendations, machines,
):
    e = engine(tmp_path, platform_datasets())
    filters = {"osType": os_type}
    for view in dashboard_queries.PREPARED_VIEWS:
        result = e.query({"view": view, "filters": filters})
        assert result["scope"]["findings"] == findings, view
        assert result["scope"]["recommendations"] == recommendations, view
        assert result["facets"]["osTypes"] == ["Android", "Ubuntu", "Unknown", "Windows11", "macOS"]
        if view == "workstations":
            assert result["tables"]["workstationTable"]["total"] == machines
    exported = list(e.iter_export({"view": "overview", "table": "findingsTable", "filters": filters}))
    assert len(exported) == findings
    if os_type != "All":
        assert all((row["OSPlatform"] or "Unknown") == os_type for row in exported)
    assert e.reads["devices"] == 1


@pytest.mark.parametrize("prepared", [False, True])
def test_os_type_preserves_filtered_details_and_combined_scope_after_default_cache(tmp_path, prepared):
    e = engine(tmp_path, platform_datasets())
    if prepared:
        e.read_model.prepare({})
    assert e.query({"view": "executive"})["scope"]["findings"] == 6
    filters = {"osType": "Windows11", "severity": "High", "subscription": "subscription-1"}
    result = e.query({"view": "detail", "filters": filters, "selection": {"type": "recommendation", "id": "rec-1"}})
    assert result["scope"]["findings"] == 2
    assert result["tables"]["pivotFindingTable"]["total"] == 1
    assert result["tables"]["pivotFindingTable"]["items"][0]["OSPlatform"] == "Windows11"
    cves = e.query({"view": "overview", "mode": "cves", "filters": filters})
    assert cves["tables"]["findingsTable"]["total"] == 1
    assert cves["tables"]["findingsTable"]["items"][0]["OpenFindings"] == 2
    assert e.query({"view": "overview", "filters": {**filters, "severity": "Low"}})["scope"]["findings"] == 0
    assert e.query({"view": "executive"})["scope"]["findings"] == 6


def test_paging_and_off_page_search_are_exact(tmp_path):
    e = engine(tmp_path)
    first = e.query({"view": "overview"})["tables"]["findingsTable"]
    last = e.query({"view": "overview", "page": 2})["tables"]["findingsTable"]
    assert first["total"] == last["total"] == 237
    assert len(first["items"]) == 100
    assert len(last["items"]) == 37
    assert last["offset"] == 200
    assert first["items"][0]["FindingKey"] == "finding-0236"
    assert not set(r["FindingKey"] for r in first["items"]) & set(r["FindingKey"] for r in last["items"])
    search = e.query({"view": "overview", "filters": {"search": "finding-0001"}})
    assert search["tables"]["findingsTable"]["total"] == 1
    assert search["tables"]["findingsTable"]["items"][0]["FindingKey"] == "finding-0001"
    assert search["activity"]["newFindings"] == 1
    assert e.reads["findings"] == 1


def test_distinct_cves_do_not_replace_finding_instances(tmp_path):
    result = engine(tmp_path).query({"view": "overview", "mode": "cves", "limit": 200})
    table = result["tables"]["findingsTable"]
    assert table["total"] == 37
    assert sum(r["EvidenceRows"] for r in table["items"]) == 237
    assert sum(r["OpenFindings"] for r in table["items"]) == 237
    assert result["activity"]["newCves"] == 37
    assert result["activity"]["newMachines"] == 12
    assert result["scope"]["findings"] == 237


def test_unavailable_metadata_keeps_findings_counts_and_exports_unknown_cve_details(tmp_path):
    data = datasets(3)
    for row in data["findings"]:
        row.update(CveId="CVE-2026-61359", CveMetadataStatus="Unavailable", CvssScore=None,
                   PublicExploitAvailable=None, VerifiedExploitAvailable=None, ExploitKitAvailable=None)
    data["vulnerabilities"] = [{
        "CveId": "CVE-2026-61359", "CveMetadataStatus": "Unavailable",
        "CvssScore": None, "PublicExploitAvailable": None, "VerifiedExploitAvailable": None,
    }]
    e = engine(tmp_path, data)
    findings = e.query({"view": "overview"})["tables"]["findingsTable"]
    assert findings["total"] == 3
    assert "CveMetadataStatus" in findings["columns"]
    assert all(row["CveMetadataStatus"] == "Unavailable" for row in findings["items"])
    request = {"view": "overview", "mode": "cves"}
    grouped = e.query(request)["tables"]["findingsTable"]
    assert grouped["total"] == 1
    cve = grouped["items"][0]
    assert cve["OpenFindings"] == cve["EvidenceRows"] == 3
    assert cve["CvssScore"] is None and cve["KnownExploit"] is None
    assert cve["CveMetadataStatus"] == "Unavailable"
    exported = list(e.iter_export(request))
    assert exported[0]["CveMetadataStatus"] == "Unavailable"
    assert exported[0]["CvssScore"] is None and exported[0]["KnownExploit"] is None
    detail = e.query({"view": "detail", "selection": {"type": "cve", "id": "CVE-2026-61359"}})
    assert detail["detail"]["record"]["CveMetadataStatus"] == "Unavailable"
    assert detail["detail"]["counts"]["activeFindings"] == 3
    assert "metadata unavailable" in detail["texts"]["pivotSummary"]


def test_machine_active_totals_exclude_pending_but_keep_all_evidence_and_distinct_cves(tmp_path):
    data = datasets(0)
    device = "example-workstation"
    data["findings"] = [
        finding(i, DeviceId=device, DeviceName="example-ws11", CveId=f"CVE-2026-{i:04}")
        for i in range(165)
    ] + [
        finding(165 + i, DeviceId=device, CveId=f"CVE-2026-{i:04}", SoftwareName="Second product")
        for i in range(20)
    ] + [
        finding(
            185 + i, DeviceId=device, CveId=f"CVE-2026-{i + 100:04}",
            FindingStatus="PendingConfirmation" if i % 2 else "PendingVerification",
            Severity="Critical",
        )
        for i in range(150)
    ]
    data["devices"] = [finding(DeviceId=device, DeviceName="example-ws11", OnboardingStatus="Onboarded")]
    query_engine = engine(tmp_path, data)
    request = {
        "view": "detail", "selection": {"type": "machine", "id": device},
        "filters": {"exposureStatus": "DetectedAndPending"}, "limit": 200,
    }
    result = query_engine.query(request)
    assert result["detail"]["counts"] == {
        "activeCves": 165, "activeFindings": 185, "pendingFindings": 150,
        "pendingCves": 150, "evidenceRows": 335,
    }
    assert result["cards"]["pivotCards"][0] == [165, "Distinct active CVEs"]
    assert result["cards"]["pivotCards"][1] == [185, "Active exposure instances"]
    assert "excluded from active totals" in result["texts"]["pivotSummary"]
    assert result["tables"]["pivotFindingTable"]["total"] == 335
    assert result["tables"]["pivotFindingTable"]["rowLabel"] == "evidence rows"
    last = query_engine.query({**request, "table": "pivotFindingTable", "page": 1})
    assert len(last["tables"]["pivotFindingTable"]["items"]) == 135
    machine = result["tables"]["pivotTable"]["items"][0]
    assert machine["DetectedCVEs"] == 165
    assert machine["PendingCVEs"] == 150
    cve_rows = result["tables"]["pivotCveTable"]["items"]
    pending_only = next(row for row in cve_rows if row["CveId"] == "CVE-2026-0165")
    assert pending_only["DetectedMachines"] == pending_only["OpenFindings"] == 0
    assert pending_only["PendingFindings"] == pending_only["EvidenceRows"] == 1
    shared = next(row for row in cve_rows if row["CveId"] == "CVE-2026-0100")
    assert shared["OpenFindings"] == shared["PendingFindings"] == 1
    assert shared["DetectedMachines"] == 1
    exported = list(query_engine.iter_export({**request, "table": "pivotFindingTable"}))
    assert len(exported) == 335
    assert sum(row["FindingStatus"].startswith("Pending") for row in exported) == 150
    grouped_export = list(query_engine.iter_export({**request, "table": "pivotCveTable"}))
    assert "EvidenceRows" in grouped_export[0]
    assert "FindingInstances" not in grouped_export[0]
    overview = query_engine.query({"view": "overview", "filters": {"search": device}})
    assert overview["scope"]["detectedCves"] == 165
    assert overview["scope"]["pending"] == 150
    assert overview["tables"]["findingsTable"]["total"] == 335
    assert "165 distinct active CVEs" in overview["texts"]["findingsListContext"]
    overview_cves = query_engine.query({"view": "overview", "mode": "cves"})
    assert overview_cves["tables"]["findingsTable"]["total"] == 250
    assert overview_cves["tables"]["findingsTable"]["rowLabel"] == "CVEs with evidence"
    overview_export = list(query_engine.iter_export({"view": "overview", "mode": "cves"}))
    assert len(overview_export) == 250
    assert sum(row["OpenFindings"] for row in overview_export) == 185
    assert sum(row["PendingFindings"] for row in overview_export) == 150
    assert sum(row["EvidenceRows"] for row in overview_export) == 335


@pytest.mark.parametrize("prepared", [False, True])
def test_recommendation_distinct_cves_are_union_not_per_device_count(tmp_path, prepared):
    data = datasets(0)
    data["findings"] = [
        finding(i, DeviceId="device-0", DeviceName="endpoint-0", RecommendationId="rec-0",
                CveId=f"CVE-2026-{i:04}", SoftwareVersion="1")
        for i in range(2057)
    ] + [
        finding(2057 + i, DeviceId="device-1", DeviceName="endpoint-1", RecommendationId="rec-0",
                CveId=f"CVE-2026-{400 + i:04}", SoftwareVersion="2")
        for i in range(1712)
    ]
    data["devices"] = data["devices"][:2]
    query_engine = engine(tmp_path, data)
    if prepared:
        query_engine.read_model.prepare({})
    result = query_engine.query({
        "view": "detail", "selection": {"type": "recommendation", "id": "rec-0"},
    })
    assert result["detail"]["counts"]["activeCves"] == 2112
    assert result["detail"]["counts"]["activeFindings"] == 3769
    machines = {row["DeviceId"]: row for row in result["tables"]["pivotTable"]["items"]}
    assert machines["device-0"]["DetectedCVEs"] == machines["device-0"]["OpenFindings"] == 2057
    assert machines["device-1"]["DetectedCVEs"] == machines["device-1"]["OpenFindings"] == 1712
    assert result["tables"]["pivotCveTable"]["total"] == 2112
    assert [2112, "Distinct active CVEs"] in result["cards"]["pivotCards"]
    machine = query_engine.query({
        "view": "detail", "selection": {"type": "machine", "id": "device-0"},
    })
    assert machine["detail"]["counts"]["activeCves"] == 2057


def test_machine_related_recommendations_preserve_scope_counts_and_navigation(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(0, DeviceId="device-0", RecommendationId="rec-0"),
        finding(1, DeviceId="device-0", RecommendationId="rec-0", SoftwareVersion="2"),
        finding(2, DeviceId="device-0", RecommendationId="rec-1", FindingStatus="PendingVerification"),
        finding(3, DeviceId="device-1", RecommendationId="rec-2"),
    ]
    e = engine(tmp_path, data)
    request = {
        "view": "detail", "selection": {"type": "machine", "id": "device-0"},
        "filters": {"exposureStatus": "DetectedAndPending"}, "limit": 1,
    }
    result = e.query(request)
    assert [2, "Related recommendations"] in result["cards"]["pivotCards"]
    links = result["tables"]["pivotRecommendationTable"]
    assert links["action"] == "recommendation"
    assert links["total"] == 2
    assert links["items"][0]["RecommendationId"] == "rec-0"
    assert links["items"][0]["OpenFindings"] == 2
    second = e.query({**request, "table": "pivotRecommendationTable", "page": 1})
    row = second["tables"]["pivotRecommendationTable"]["items"][0]
    assert row["RecommendationId"] == "rec-1"
    assert row["PendingFindings"] == 1
    exported = list(e.iter_export({**request, "table": "pivotRecommendationTable"}))
    assert {row["RecommendationId"] for row in exported} == {"rec-0", "rec-1"}
    active = e.query({**request, "filters": {"exposureStatus": "DetectedOnly"}})
    assert [1, "Related recommendations"] in active["cards"]["pivotCards"]
    assert active["tables"]["pivotRecommendationTable"]["total"] == 1
    recommendation = e.query({"view": "detail", "selection": {"type": "recommendation", "id": "rec-0"}})
    assert recommendation["detail"]["record"]["RecommendationId"] == "rec-0"
    summary = e.query({"view": "executive"})["cards"]["executiveWorkload"][0]
    assert summary == [3, "Active exposure instances", "3 distinct active CVEs across 2 affected devices"]


def test_pending_only_device_has_no_active_vulnerability_or_severity_totals(tmp_path):
    data = datasets(0)
    data["findings"] = [finding(0, FindingStatus="PendingVerification", Severity="Critical")]
    query_engine = engine(tmp_path, data)
    result = query_engine.query({"view": "workstations"})
    device = next(row for row in result["tables"]["workstationTable"]["items"] if row["DeviceId"] == "device-0")
    assert device["OpenFindings"] == 0
    assert device["PendingFindings"] == 1
    assert all(device[severity] == 0 for severity in ("Critical", "High", "Medium", "Low"))
    detail = query_engine.query({
        "view": "detail", "selection": {"type": "machine", "id": "device-0"},
        "filters": {"exposureStatus": "PendingOnly"},
    })
    assert detail["detail"]["counts"]["activeCves"] == 0
    assert detail["detail"]["counts"]["pendingFindings"] == 1
    assert detail["tables"]["pivotFindingTable"]["total"] == 1


def test_data_browser_uses_all_fields_and_searches_all_rows(tmp_path):
    e = engine(tmp_path)
    info = e.dataset_info("findings")
    assert info["rowCount"] == 237
    assert "FindingKey" in info["fields"]
    page = e.page_dataset("findings", 200, 500)
    assert len(page["items"]) == 37
    assert page["unfilteredTotal"] == page["total"] == 237
    found = e.page_dataset("findings", query="FINDING-0236")
    assert found["total"] == 1
    assert found["items"][0]["FindingKey"] == "finding-0236"
    assert found["unfilteredTotal"] == 237
    assert len(e.page_dataset("findings", limit=1000)["items"]) == 200
    with pytest.raises(ValueError):
        e.page_dataset("../findings")


def test_analytical_scans_do_not_read_json_or_search_payloads(tmp_path):
    query_engine = engine(tmp_path)
    query_engine._ensure("findings")
    with query_engine._connect() as db:
        sql = """
            SELECT count(*),sum(_fixed<=_due),
                count(DISTINCT DeviceId),count(DISTINCT _cve)
            FROM findings WHERE Severity='High'
        """
        plan = " ".join(row["detail"] for row in db.execute("EXPLAIN QUERY PLAN " + sql))
        assert "CORRELATED SCALAR SUBQUERY" not in plan
        opened = {row["p2"] for row in db.execute("EXPLAIN " + sql) if row["opcode"] == "OpenRead"}
        roots = dict(db.execute("""
            SELECT name,rootpage FROM sqlite_master
            WHERE tbl_name='findings_facts' OR name IN ('findings_payloads','shared_values')
        """))
        fact_roots = {root for name, root in roots.items() if name not in ("findings_payloads", "findings_searches")}
        assert opened and opened <= fact_roots
        assert roots["findings_payloads"] not in opened
        assert not any(row["opcode"] == "Function" and "payload_" in str(row["p4"]) for row in db.execute("EXPLAIN " + sql))
        db.execute(sql).fetchone()
        payload_plan = " ".join(row["detail"] for row in db.execute(
            "EXPLAIN QUERY PLAN SELECT data FROM findings WHERE _rowid=1"
        ))
        assert "CORRELATED SCALAR SUBQUERY" not in payload_plan
        assert any(
            row["opcode"] == "Function" and "payload_json" in str(row["p4"])
            for row in db.execute("EXPLAIN SELECT data FROM findings WHERE _rowid=1")
        )


def test_cve_mode_cannot_bypass_other_prepared_views(tmp_path, monkeypatch):
    query_engine = engine(tmp_path)
    for view in ("executive", "overview", "recommendations"):
        query_engine.prepare({"view": view, "mode": "findings"})
    assert query_engine.cached({"view": "overview", "mode": "cves"}) is None

    def unexpected_query(*args, **kwargs):
        pytest.fail("A prepared view must not reopen SQLite after changing CVE mode")

    monkeypatch.setattr(query_engine, "_connect", unexpected_query)
    for view in ("executive", "recommendations"):
        assert query_engine.query({"view": view, "mode": "cves"}) == query_engine.cached({"view": view})


def test_separated_records_round_trip_unknown_fields_and_multiple_pages(tmp_path):
    data = datasets(401)
    data["findings"][0].update(
        CustomObject={"nested": [None, "MÜNCHEN", {"quote": "O'Brien"}]},
        NullableField=None, CustomBoolean=True,
    )
    query_engine = engine(tmp_path, data)
    assert list(query_engine.iter_dataset("findings")) == data["findings"]
    assert query_engine.page_dataset("findings", 399, 100)["items"] == data["findings"][399:]
    assert query_engine.page_dataset("findings", query="MÜNCHEN")["items"] == data["findings"][:1]


def test_deferred_timestamps_and_oldest_detection_preserve_original_text(tmp_path):
    data = datasets(0)
    first = "2026-10-23T16:00:00+03:00"
    data["findings"] = [
        finding(index, FirstSeenUtc=first, FirstObservedUtc=observed,
                LastSeenUtc="2026-10-24T14:00:00+03:00")
        for index, observed in enumerate((None, "", "2026-10-23T14:00:00+01:00"))
    ]
    query_engine = engine(tmp_path, data)
    query_engine._ensure("findings")
    with query_engine._connect() as db:
        rows = db.execute("""
            SELECT FirstSeenUtc,FirstObservedUtc,LastSeenUtc,SnapshotTimeUtc,_observed_text
            FROM findings ORDER BY _rowid
        """).fetchall()
    for row, source in zip(rows, data["findings"], strict=True):
        assert dict(row) == {
            **{field: source[field] for field in ("FirstSeenUtc", "FirstObservedUtc", "LastSeenUtc", "SnapshotTimeUtc")},
            "_observed_text": source["FirstObservedUtc"] if source["FirstObservedUtc"] is not None else first,
        }
    result = query_engine.query({"view": "trend"})
    oldest = {row["DeviceId"]: row["OldestDetectionUtc"] for row in result["tables"]["weeklyRiskTable"]["items"]}
    assert oldest == {"device-0": first, "device-1": "", "device-2": "2026-10-23T14:00:00+01:00"}


def test_shared_sla_statistics_include_unknown_severities_without_changing_graphs(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(0, Severity=None, FindingStatus="Fixed", SlaStatus="FixedWithinSla", FixedUtc=SNAPSHOT),
        finding(1, Severity="Informational", SlaStatus="OpenOutsideSla"),
    ]
    query_engine = engine(tmp_path, data)
    sla = query_engine.query({"view": "sla"})
    assert [card[0] for card in sla["cards"]["slaCards"]] == [2, 1, 0, 1, 0, 1]
    assert all(row["FixedWithinSLA"] == 0 for row in sla["slaGraphs"]["findingSlaGraph"]["rows"])
    summary = query_engine.query({"view": "executive"})
    assert [card[0] for card in summary["cards"]["executiveSlaPerformance"]] == ["100%", 1, 0, 1]


def test_executive_concentration_other_keeps_distinct_machine_counts(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(index, OwnerTeam=f"team-{index}", DeviceId=f"device-{min(index, 6)}")
        for index in range(9)
    ]
    result = engine(tmp_path, data).query({"view": "executiveSnapshot"})
    rows = result["charts"]["executiveOwnerConcentration"]["rows"]
    assert len(rows) == 7
    assert rows[-1] == {"label": "Other", "value": 3, "criticalHigh": 3, "machines": 1}


@pytest.mark.parametrize("severity", [None, "High"])
def test_executive_concentration_compacts_one_sequential_scan_with_exact_counts(tmp_path, severity):
    rng = random.Random(71)
    data = datasets(0)
    data["findings"] = [
        finding(
            index, DeviceId=rng.choice([None, "", 0, "0", 1, 1.0, "1", "device"]),
            SubscriptionId=rng.choice([None, "", *[f"sub-{n}" for n in range(9)]]),
            OwnerTeam=rng.choice([None, "", *[f"team-{n}" for n in range(10)]]),
            Severity=rng.choice(["Critical", "High", "Medium", None]),
            FirstSeenUtc=rng.choice(["2026-10-01T00:00:00Z", "2026-10-23T00:00:00Z", SNAPSHOT]),
            FixedUtc=rng.choice([None, "2026-10-21T00:00:00Z", "2026-10-24T00:00:00Z"]),
            ReopenedUtc=rng.choice([None, "2026-10-22T00:00:00Z"]),
        )
        for index in range(240)
    ]
    data["findings"] *= 3
    e = engine(tmp_path, data)
    e._ensure("findings")
    end = dashboard_queries._timestamp("2026-10-23T23:59:59.999Z")
    with e._connect() as db:
        e._finding_scope(db, "report_scope", "f.Severity=?" if severity else "1", [severity] if severity else [], {})
        e._view(db, "period_open", f"SELECT * FROM report_scope WHERE {e._open_at(end)}", [])
        statements = []
        db.set_trace_callback(statements.append)
        out = {"charts": {}}
        e._executive_concentration(db, out, None, end)
        db.set_trace_callback(None)
        materializations = [sql for sql in statements if "CREATE TEMP TABLE executive_open_dimensions" in sql]
        assert len(materializations) == 1
        plan = " ".join(row["detail"] for row in db.execute(
            "EXPLAIN QUERY PLAN " + materializations[0].split(" AS", 1)[1],
        ))
        assert ("SEARCH f USING INDEX findings_Severity" if severity else "SCAN f") in plan
        assert "findings_recommendation_rank" not in plan
        assert db.execute("SELECT count(*) FROM executive_open_dimensions").fetchone()[0] < db.execute(
            "SELECT count(*) FROM period_open"
        ).fetchone()[0]
        for chart, field in (("executiveSubscriptionConcentration", "SubscriptionId"), ("executiveOwnerConcentration", "OwnerTeam")):
            rows = [dict(row) for row in db.execute(f"""
                SELECT coalesce(nullif({field},''),'Unassigned') label,count(*) value,
                  sum(Severity IN ('Critical','High')) criticalHigh,
                  count(DISTINCT nullif(DeviceId,'')) machines
                FROM period_open GROUP BY {field} ORDER BY value DESC,label
            """)]
            assert len(rows) > 6
            labels = [row["label"] for row in rows[:6]]
            other = dict(db.execute(f"""
                SELECT count(*) value,coalesce(sum(Severity IN ('Critical','High')),0) criticalHigh,
                  count(DISTINCT nullif(DeviceId,'')) machines FROM period_open
                WHERE coalesce(nullif({field},''),'Unassigned') NOT IN ({','.join('?' for _ in labels)})
            """, labels).fetchone())
            expected = rows[:6] + [{"label": "Other", **other}]
            assert out["charts"][chart]["rows"] == expected


@pytest.mark.parametrize("rule", [
    {"id": "unicode", "field": "DeviceName", "operator": "prefix", "value": "mün", "label": "Unicode hosts"},
    {"id": "quotes", "field": "DeviceName", "operator": "contains", "value": "o'brien", "label": "O'Brien hosts"},
    {"id": "custom", "field": "CustomBoolean", "operator": "exact", "value": "true"},
])
def test_optimized_workload_expressions_preserve_python_rules_and_vmss_precedence(tmp_path, rule):
    data = datasets(0)
    data["findings"] = [
        finding(0, DeviceName="MÜNCHEN O'Brien", CustomBoolean=True),
        finding(1, DeviceName="MÜNCHEN O'Brien", CustomBoolean=True,
                AzureResourceId="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/pool/virtualMachines/1"),
        finding(2, DeviceName="ordinary-host"),
    ]
    query_engine = engine(tmp_path, data)
    filters = {"workloadGrouping": {"rules": [rule]}}
    query_engine._ensure("findings")
    with query_engine._connect(filters) as db:
        query_engine._finding_scope(db, "scoped", "1", [], filters)
        actual = db.execute("""
            SELECT _workload,_workload_name,_workload_type FROM scoped ORDER BY _rowid
        """).fetchall()
        assert [tuple(row) for row in actual] == [
            query_engine._workload(row, filters) for row in data["findings"]
        ]


@pytest.mark.parametrize("view", [
    "executive", "overview", "workstations", "recommendations", "priority", "sla",
    "trend", "executiveSnapshot", "help",
])
def test_all_views_have_bounded_snapshot_pinned_output(tmp_path, view):
    e = engine(tmp_path)
    result = e.query({"view": view, "limit": 7})
    assert result["snapshotId"] == "snapshot-1"
    assert result["snapshotTimeUtc"] == SNAPSHOT
    assert result["scope"]["findings"] == 237
    for key in ("cards", "texts", "tables", "donuts", "slaGraphs", "activity", "scope", "facets", "metadata"):
        assert key in result
    for table in result["tables"].values():
        assert len(table["items"]) <= max(14, table["limit"])
        assert table["total"] >= len(table["items"])
    assert "findings" not in result
    if view == "executive":
        assert not {"vulnerabilities", "recommendation-events", "daily-summary"} & e.reads.keys()


def test_sla_fixed_device_pairs_preserve_unresolved_and_null_key_semantics(tmp_path):
    data = datasets(0)
    cases = [
        ("fixed-only", "rec-0", "Fixed"),
        ("mixed", "rec-0", "Fixed"), ("mixed", "rec-0", "Open"),
        ("pending", "rec-0", "Fixed"), ("pending", "rec-0", "PendingVerification"),
        ("other-recommendation", "rec-0", "Fixed"), ("other-recommendation", "rec-1", "Open"),
        ("unlinked", None, "Fixed"), ("unlinked", None, "Open"),
        (None, "rec-0", "Fixed"), (None, "rec-0", "Open"),
    ]
    data["findings"] = [
        finding(index, DeviceId=device, RecommendationId=recommendation, FindingStatus=status,
                FixedUtc=SNAPSHOT if status == "Fixed" else None,
                SlaStatus="FixedWithinSla" if status == "Fixed" else "OpenWithinSla")
        for index, (device, recommendation, status) in enumerate(cases)
    ]
    result = engine(tmp_path, data).query({"view": "sla"})
    rows = {row["RecommendationId"]: row for row in result["tables"]["remediationOutcomeTable"]["items"]}
    assert rows["rec-0"]["FixedDevicesToday"] == 2
    assert rows["rec-1"]["FixedDevicesToday"] == 0
    assert rows[None]["FixedDevicesToday"] == 1
    assert rows["rec-0"]["FixedToday"] == 5


def test_sla_ignores_exposure_and_period_filters_and_uses_first_absence(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(1, FindingStatus="PendingConfirmation", SlaStatus="FixedWithinSla",
                EffectiveRemediationUtc="2026-10-24T03:00:00Z"),
        finding(2, FindingStatus="PendingVerification", SlaStatus="FixedOutsideSla",
                EffectiveRemediationUtc="2026-10-24T03:00:00Z"),
        finding(3, FindingStatus="Fixed", SlaStatus="FixedWithinSla", FixedUtc="2026-10-01T00:00:00Z"),
        finding(4, FindingStatus="Open", SlaStatus="OpenOutsideSla"),
        finding(5, FindingStatus="Fixed", SlaStatus="FixedWithinSla", FixedUtc=""),
    ]
    result = engine(tmp_path, data).query({
        "view": "sla", "filters": {
            "exposureStatus": "DetectedOnly", "newPeriodFilter": True,
            "newPeriod": "custom", "newPeriodStart": "2020-01-01", "newPeriodEnd": "2020-01-02",
            "remediationPeriodFilter": True,
        },
    })
    cards = {label: value for value, label in result["cards"]["slaCards"]}
    assert cards["Finding instances observed"] == 5
    assert cards["Findings confirmed fixed"] == 2
    assert cards["SLA remediations pending verification"] == 2
    assert cards["Remediation observed within policy SLA"] == 2
    assert cards["Remediation observed outside policy SLA"] == 1
    assert cards["Detected findings overdue"] == 1
    high = result["slaGraphs"]["findingSlaGraph"]["rows"][1]
    assert high["FixedWithinSLA"] == 2
    assert high["PendingVerification"] == 2
    assert result["scope"]["findings"] == 0


def test_reporting_domain_team_subscription_origin_and_recommendation_kind(tmp_path):
    data = datasets(0)
    data["recommendations"].append({
        "RecommendationId": "misconfiguration", "RecommendationName": "Enable security setting",
        "RemediationType": "ConfigurationChange", "DataOrigin": "Live",
    })
    data["findings"] = [
        finding(1), finding(2, Severity="Critical"),
        finding(3, AssetClass="AzureCloud"),
        finding(4, DataOrigin="Synthetic"),
        finding(5, OwnerTeam="Other"), finding(6, SubscriptionId="subscription-2"),
        finding(7, LastSeenUtc="2026-01-01T00:00:00Z"),
        finding(8, RecommendationId="misconfiguration"),
    ]
    filters = {
        "origin": "Live", "severity": "High", "domains": ["Devices"],
        "team": "Operations", "subscription": "subscription-1",
        "hideNonReporting": True, "reportingDays": 30, "recommendationTypes": ["Vulnerability"],
    }
    e = engine(tmp_path, data)
    result = e.query({"view": "overview", "filters": filters})
    assert result["tables"]["findingsTable"]["total"] == 1
    assert result["tables"]["findingsTable"]["items"][0]["FindingKey"] == "finding-0001"
    assert result["facets"]["teams"] == ["Operations", "Other"]
    assert len(result["facets"]["subscriptions"]) == 2
    filters.update(subscription="NoSubscription")
    assert e.query({"view": "overview", "filters": filters})["scope"]["findings"] == 0


def test_grouping_vmss_precedes_configured_rules_and_preserves_instances(tmp_path):
    data = datasets(0)
    rows = [finding(i, DeviceId=f"d-{i}", DeviceName="cluster-" + str(i), OnboardingStatus="Onboarded") for i in range(4)]
    for i in (0, 1):
        rows[i]["AzureResourceId"] = f"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/web/virtualMachines/{i}"
    data["findings"] = rows
    data["devices"] = rows
    result = engine(tmp_path, data).query({
        "view": "workstations", "filters": {
            "workloadGrouping": {"rules": [{"id": "cluster", "label": "Cluster", "field": "DeviceName", "operator": "prefix", "value": "cluster-"}]},
        },
    })
    table = result["tables"]["workstationTable"]
    assert table["total"] == 2
    assert {r["DeviceName"] for r in table["items"]} == {"web", "Cluster"}
    assert sorted(r["InstanceCount"] for r in table["items"]) == [2, 2]
    assert sum(r["OpenFindings"] for r in table["items"]) == 4


def test_new_and_remediation_activity_have_independent_scope(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(1),
        finding(2, FindingStatus="PendingVerification", SlaStatus="FixedWithinSla",
                FirstObservedUtc="2026-01-01T00:00:00Z", EffectiveRemediationUtc="2026-10-24T03:00:00Z"),
        finding(3, FindingStatus="Fixed", FirstObservedUtc="2026-01-01T00:00:00Z", FixedUtc="2026-10-24T04:00:00Z"),
        finding(4, FirstObservedUtc="2026-10-24T13:00:00Z"),
    ]
    result = engine(tmp_path, data).query({"view": "overview", "filters": {"exposureStatus": "DetectedOnly", "newPeriodFilter": True}})
    assert result["activity"]["newFindings"] == 1
    assert result["activity"]["fixedFindings"] == 2
    assert result["scope"]["findings"] == 1


def test_missing_optional_is_explicit_but_missing_required_and_corruption_propagate(tmp_path):
    e = engine(tmp_path / "optional", {"findings": [finding()]})
    result = e.query({"view": "overview"})
    assert any("recommendations.json" in notice for notice in result["notices"])
    assert result["scope"]["findings"] == 1
    e = engine(tmp_path / "required", {})
    with pytest.raises(FileNotFoundError):
        e.query({"view": "overview"})
    e = engine(tmp_path / "invalid", {"findings": [42]})
    with pytest.raises(ValueError, match="non-object"):
        e.query({"view": "overview"})


def test_concurrent_lazy_queries_build_each_dataset_once(tmp_path):
    e = engine(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda page: e.query({"view": "overview", "page": page}), range(4)))
    assert all(result["scope"]["findings"] == 237 for result in results)
    assert e.reads["findings"] == e.reads["recommendations"] == 1


def test_reopening_and_report_period_counts_are_not_sampled(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(1, FirstSeenUtc="2026-10-01T00:00:00Z", FixedUtc="2026-10-20T00:00:00Z",
                ReopenedUtc="2026-10-22T00:00:00Z"),
        finding(2, FindingStatus="Fixed", FirstSeenUtc="2026-10-19T00:00:00Z",
                FixedUtc="2026-10-21T00:00:00Z"),
    ]
    result = engine(tmp_path, data).query({"view": "trend", "filters": {"statisticsPeriod": "30days"}})
    current = result["tables"]["statisticsPeriodTable"]["items"][0]
    assert current["New"] == 2
    assert current["Fixed"] == 2
    assert current["EndingOpen"] == 1
    assert len(result["charts"]["weeklyTrendChart"]["rows"]) == 90


def test_executive_report_independent_scope_and_snapshot_sla_policy(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(1, SubscriptionId="report-sub", OwnerTeam="ReportTeam", FindingStatus="Fixed",
                FixedUtc="2026-10-23T14:00:00Z", SlaDueUtc="2026-10-25T00:00:00Z"),
        finding(2),
    ]
    result = engine(tmp_path, data).query({"view": "executiveSnapshot", "filters": {
        "subscription": "workspace-sub", "team": "WorkspaceTeam", "exposureStatus": "PendingOnly",
        "executiveSnapshotSubscription": "report-sub", "executiveSnapshotOwner": "ReportTeam",
        "slaPolicy": {"complianceTargetPercent": 95},
    }})
    cards = {row[1]: row[0] for row in result["cards"]["executiveSnapshotKpis"]}
    assert cards["Findings fixed"] == 1
    assert cards["SLA compliance"] == "100%"
    assert result["metadata"]["slaPolicy"]["complianceTargetPercent"] == 95
    assert result["charts"]["executiveSlaMeterValue"]["target"] == 95
    assert "above" in result["texts"]["executiveSlaMeterText"]
    assert "executiveSnapshotSlaTable" in result["tables"]


def test_export_streams_all_matching_rows_and_exact_executive_findings(tmp_path):
    e = engine(tmp_path)
    rows = list(e.iter_export({"view": "overview", "table": "findingsTable"}))
    assert len(rows) == 237
    assert len({r["FindingKey"] for r in rows}) == 237
    rows = list(e.iter_export({"view": "executiveSnapshot", "table": "executiveSnapshotFindingTable"}))
    assert len(rows) == 237
    assert rows[0]["ReportRepresentation"] == "Finding instances"
    assert rows[0]["OpenAtPeriodEnd"] == 1
    assert "PeriodStart" in rows[0]


@pytest.mark.parametrize("kind,id", [
    ("finding", "finding-0001"), ("cve", "cve-2026-0001"),
    ("machine", "device-1"), ("recommendation", "rec-1"),
])
def test_detail_pivots_are_exact_and_paged(tmp_path, kind, id):
    result = engine(tmp_path).query({"view": "detail", "selection": {"type": kind, "id": id}, "limit": 5})
    assert result["detail"]["record"]
    assert all(len(table["items"]) <= 5 for table in result["tables"].values())
    assert result["tables"]["pivotFindingTable"]["total"] >= 1


def test_tracking_counts_use_exact_collector_contract_and_empty_timestamp_catalog(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(1), finding(2, FindingStatus="Reopened"), finding(3, FindingStatus="DetectionReturned"),
        finding(4, DataOrigin="Synthetic"), finding(5, LastObservedUtc="2026-10-23T00:00:00Z"),
    ]
    e = engine(tmp_path, data, snapshot_time="")
    assert e.dataset_info("findings")["rowCount"] == 5
    counts = e.active_recommendation_counts(SNAPSHOT)
    assert sum(counts.values()) == 2
    assert len(list(e.iter_dataset("recommendations"))) == 3
    with pytest.raises(ValueError, match="timestamp"):
        e.query({"view": "overview"})


def test_tracking_counts_are_single_flight_snapshot_pinned_and_return_copies(tmp_path, monkeypatch):
    e = engine(tmp_path)
    original, statements = e._connect, []

    @contextmanager
    def observe(*args, **kwargs):
        with original(*args, **kwargs) as db:
            db.set_trace_callback(statements.append)
            yield db

    monkeypatch.setattr(e, "_connect", observe)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(e.active_recommendation_counts, [SNAPSHOT, SNAPSHOT]))
    assert results[0] == results[1]
    assert results[0]
    results[0].clear()
    assert e.active_recommendation_counts(SNAPSHOT) == results[1]
    assert sum("SELECT RecommendationId,count(*) FROM findings" in sql for sql in statements) == 1
    assert e.active_recommendation_counts("2026-10-23T12:00:00Z") == {}
    assert e.active_recommendation_counts("2026-10-22T12:00:00Z") == {}
    assert len(e._tracking_counts) == 2
    other = engine(tmp_path / "other", datasets(0), "different-snapshot")
    assert other.active_recommendation_counts(SNAPSHOT) == {}


def test_snapshot_identity_and_derived_cache_are_pinned(tmp_path):
    first = engine(tmp_path, datasets(7), "snapshot-first")
    second = engine(tmp_path, datasets(9), "snapshot-second")
    assert first.query({"view": "overview"})["scope"]["findings"] == 7
    assert second.query({"view": "overview"})["scope"]["findings"] == 9
    assert first.query({"view": "overview", "page": 1})["scope"]["findings"] == 7
    assert first.path != second.path


def test_cached_pages_do_not_recompute_exact_header_aggregates(tmp_path, monkeypatch):
    e = engine(tmp_path)
    first = e.query({"view": "overview"})
    monkeypatch.setattr(e, "_header", lambda *args: pytest.fail("page navigation recomputed header"))
    second = e.query({"view": "overview", "page": 1, "table": "findingsTable"})
    assert second["activity"] == first["activity"]
    assert second["tables"]["findingsTable"]["offset"] == 100


def test_broad_activity_uses_covering_index_without_changing_counts(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(i, FindingStatus=status, EffectiveRemediationUtc=SNAPSHOT if i else None)
        for i, status in enumerate(("Open", "Fixed", "PendingVerification", "Reopened"))
    ]
    e = engine(tmp_path, data)
    broad = e.query({"view": "overview", "filters": {"origin": "Live"}})
    selective = e.query({
        "view": "overview", "filters": {"origin": "Live", "hideNonReporting": True},
    })
    assert broad["activity"] == selective["activity"]
    assert broad["activity"]["newFindings"] == 3
    assert broad["activity"]["fixedFindings"] == 3
    statements = []
    with e._connect() as db:
        db.set_trace_callback(statements.append)
        e._header(db, {key: {} for key in ("activity", "facets", "metadata", "texts")}, {"origin": "Live"})
        activity = [sql for sql in statements if "count(*) Findings" in sql]
        assert len(activity) == 2
        for sql in activity:
            plan = " ".join(row["detail"] for row in db.execute("EXPLAIN QUERY PLAN " + sql))
            assert "COVERING INDEX findings_recommendation_rank" in plan


def test_global_cve_exploit_evidence_is_union_of_all_finding_evidence(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(1, CveId="CVE-2026-0001", VerifiedExploitAvailable=True),
        finding(2, CveId="CVE-2026-0001", PublicExploitAvailable="True"),
        finding(3, CveId="CVE-2026-0001", PriorityScore=999),
    ]
    result = engine(tmp_path, data).query({"view": "overview"})
    assert result["tables"]["findingsTable"]["items"][0]["WatchlistEvidence"] == "Verified + Public"
    row = result["tables"]["exploitTable"]["items"][0]
    assert row["WatchlistEvidence"] == "Verified + Public"
    assert row["AffectedDevices"] == 3


@pytest.mark.parametrize("copies", [1, 3])
def test_daily_interval_aggregation_matches_legacy_history_predicates(tmp_path, copies):
    data = datasets(0)
    snapshot = datetime.fromisoformat(SNAPSHOT.replace("Z", "+00:00"))
    for i in range(120):
        first = snapshot - timedelta(days=120 - i, hours=i % 24)
        fixed = first + timedelta(days=i % 17) if i % 3 else None
        reopened = first + timedelta(days=i % 21) if i % 5 == 0 else None
        for copy in range(copies):
            data["findings"].append(finding(
                i * copies + copy, FirstObservedUtc=first.isoformat(), FirstSeenUtc=first.isoformat(),
                FixedUtc=fixed.isoformat() if fixed else "",
                ReopenedUtc=reopened.isoformat() if reopened else "",
                PublicExploitAvailable=i % 2 == 0,
                SlaDueUtc=(first + timedelta(days=7)).isoformat(),
            ))
    e = engine(tmp_path, data)
    points = e.query({"view": "trend"})["charts"]["weeklyTrendChart"]["rows"]
    for point in points:
        end = datetime.fromisoformat(point["date"]).replace(tzinfo=timezone.utc) + timedelta(days=1, milliseconds=-1)
        remaining = within = outside = backlog = 0
        for row in data["findings"]:
            first = datetime.fromisoformat(row["FirstObservedUtc"])
            fixed = datetime.fromisoformat(row["FixedUtc"]) if row["FixedUtc"] else None
            reopened = datetime.fromisoformat(row["ReopenedUtc"]) if row["ReopenedUtc"] else None
            due = datetime.fromisoformat(row["SlaDueUtc"])
            if first <= end and (not fixed or fixed > end or reopened and reopened <= end):
                remaining += 1
                backlog += row["PublicExploitAvailable"]
            if first <= end and fixed and fixed <= end and not (reopened and reopened <= end):
                within += fixed <= due
                outside += fixed > due
        assert point["remaining"] == remaining
        assert point["backlog"] == backlog
        assert point["fixedWithinSla"] == within
        assert point["fixedOutsideSla"] == outside
    buckets = e.query({"view": "executiveSnapshot"})["charts"]["executiveSnapshotTrend"]["rows"]
    earliest = datetime.min.replace(tzinfo=timezone.utc)
    for index, bucket in enumerate(buckets):
        start = datetime.fromisoformat(bucket["label"]).replace(tzinfo=timezone.utc)
        next_start = (
            datetime.fromisoformat(buckets[index + 1]["label"]).replace(tzinfo=timezone.utc)
            if index + 1 < len(buckets) else snapshot.replace(hour=0) + timedelta(days=1)
        )
        end = next_start - timedelta(milliseconds=1)
        new = fixed_count = opened = 0
        for row in data["findings"]:
            first = datetime.fromisoformat(row["FirstSeenUtc"])
            fixed = datetime.fromisoformat(row["FixedUtc"]) if row["FixedUtc"] else None
            reopened = datetime.fromisoformat(row["ReopenedUtc"]) if row["ReopenedUtc"] else None
            new += start <= first <= end
            fixed_count += bool(fixed and start <= fixed <= end)
            prior_open = max(first, reopened if reopened and reopened <= end else earliest)
            prior_fixed = fixed if fixed and fixed <= end else earliest
            opened += first <= end and prior_open > prior_fixed
        assert bucket["new"] == new
        assert bucket["fixed"] == fixed_count
        assert bucket["open"] == opened


def test_header_recommendation_scope_includes_machine_only_evidence_and_tracking(tmp_path):
    data = datasets(0)
    data["findings"] = [finding(0, RecommendationId="rec-0")]
    data["recommendation-machines"] = [finding(1, RecommendationId="rec-1")]
    e = engine(tmp_path, data)
    result = e.query({"view": "overview"})
    assert result["scope"]["recommendations"] == 2
    result = e.query({"view": "overview", "filters": {
        "recommendationTrackingEnabled": True, "recommendationTrackingFilter": "NeedsAttention",
        "recommendationTracking": [{"recommendationId": "rec-0", "effectiveStatus": "Confirmed"}],
    }})
    assert result["scope"]["recommendations"] == 1
    assert result["scope"]["findings"] == 1


def test_streaming_export_can_resume_on_another_worker_thread(tmp_path):
    iterator = engine(tmp_path).iter_export({"view": "overview", "table": "findingsTable"})
    with ThreadPoolExecutor(max_workers=1) as first:
        a = first.submit(next, iterator).result()
    with ThreadPoolExecutor(max_workers=1) as second:
        b = second.submit(next, iterator).result()
        second.submit(iterator.close).result()
    assert a["FindingKey"] != b["FindingKey"]


def test_grouped_machine_detail_preserves_all_underlying_instances(tmp_path):
    data = datasets(0)
    data["findings"] = [finding(i, DeviceName=f"group-{i}") for i in range(5)]
    result = engine(tmp_path, data).query({
        "view": "detail", "selection": {"type": "machine", "id": "rule:group"},
        "filters": {"workloadGrouping": {"rules": [{
            "id": "group", "label": "Group", "field": "DeviceName", "operator": "prefix", "value": "group-",
        }]}},
    })
    assert result["detail"]["record"]["DeviceId"] == "rule:group"
    assert result["tables"]["pivotFindingTable"]["total"] == 5
    assert result["tables"]["pivotTable"]["items"][0]["InstanceCount"] == 5


def test_single_run_summary_never_reads_full_finding_history(tmp_path):
    data = datasets()
    data["collection-runs"] = [data["collection-runs"][-1]]
    data.pop("finding-events")
    e = engine(tmp_path, data)
    result = e.query({"view": "executive"})
    assert result["scope"]["findings"] == 237
    assert result["cards"]["executiveWorkload"][0][0] == 237
    assert "previous comparable run is not available" in result["texts"]["executiveDeltaContext"]
    assert "finding-events" not in e.reads
    assert "recommendation-events" not in e.reads
    assert e.reads["devices"] == 1


def test_comparable_run_summary_uses_compact_history_and_finding_timestamps(tmp_path):
    data = datasets()
    data["collection-runs"] = [data["collection-runs"][-1]]
    data["run-history"] = [{
        "SnapshotTimeUtc": "2026-10-23T12:00:00Z", "DataOrigin": "Live",
        "CollectionRunId": "prior-run", "RunStatus": "Success",
    }]
    data.pop("finding-events")
    e = engine(tmp_path, data)
    result = e.query({"view": "executive"})
    movement = {label: value for value, label, *_ in result["cards"]["executiveRunMovement"]}
    assert movement["Previous open"] == 0
    assert movement["New / reopened"] == 237
    assert movement["Current detected"] == 237
    assert "finding-events" not in e.reads


@pytest.mark.parametrize("aggregated", [False, True])
@pytest.mark.parametrize("filters,prior,added,current", [
    ({}, 3, 2, 5),
    ({"severity": "High"}, 2, 1, 3),
    ({"severity": "Low"}, 1, 1, 2),
    ({"search": "finding-0003"}, 0, 1, 1),
])
def test_previous_run_excludes_newly_observed_findings_with_backdated_source_first_seen(
    tmp_path, aggregated, filters, prior, added, current,
):
    data = datasets(0)
    data["findings"] = [
        finding(
            index, Severity="Low" if index in (2, 4) else "High",
            FirstSeenUtc="2026-10-01T00:00:00Z",
            FirstObservedUtc="2026-10-24T11:00:00Z" if index >= 3 else "2026-10-22T00:00:00Z",
        )
        for index in range(5)
    ]
    data["run-history"] = [{
        "SnapshotTimeUtc": "2026-10-23T12:00:00Z", "DataOrigin": "Live",
        "CollectionRunId": "prior-run", "RunStatus": "Success", "OpenFindings": 3,
    }]
    e = engine(tmp_path, data)
    if aggregated:
        e.read_model.prepare({})
    result = e.query({"view": "executive", "filters": filters})
    movement = {label: value for value, label, *_ in result["cards"]["executiveRunMovement"]}
    assert movement["Previous open"] == prior
    assert movement["New / reopened"] == added
    assert movement["Current detected"] == current
    assert movement["Net detected change"] == current - prior == added
    assert "entered or left" not in result["texts"]["executiveRunEquation"]


def test_latest_change_filter_and_direct_export_do_not_index_events(tmp_path):
    data = datasets()
    data.pop("finding-events")
    e = engine(tmp_path, data)
    result = e.query({"view": "overview", "filters": {"latestRunChangesOnly": True}})
    assert result["scope"]["findings"] == 237
    assert "finding-events" not in e.reads
    direct = engine(tmp_path / "direct-export", data)
    rows = list(direct.iter_export({
        "view": "overview", "filters": {"latestRunChangesOnly": True}, "table": "findingsTable",
    }))
    assert len(rows) == 237
    assert "finding-events" not in direct.reads


@pytest.mark.parametrize("view,table", [
    ("trend", "weeklyRiskTable"),
    ("executiveSnapshot", "executiveSnapshotRecommendationTable"),
    ("executiveSnapshot", "executiveSnapshotRiskTable"),
])
def test_grouped_report_pagers_reuse_exact_aggregates_without_queries(tmp_path, monkeypatch, view, table):
    e = engine(tmp_path)
    request = {"view": view, "limit": 1}
    first = e.query(request)
    assert first["tables"][table]["total"] > 1
    monkeypatch.setattr(e, "_connect", lambda *args: pytest.fail("cached report pager opened SQLite"))
    monkeypatch.setattr(e, "_report", lambda *args: pytest.fail("cached report pager recomputed report"))
    page = e.query({**request, "table": table, "page": 1})
    assert page["tables"][table]["offset"] == 1
    assert page["tables"][table]["total"] == first["tables"][table]["total"]
    assert len(page["tables"][table]["items"]) == 1
    assert page["tables"][table]["items"] != first["tables"][table]["items"]
    assert page["cards"] == first["cards"]
    assert page["charts"] == first["charts"]
    page["tables"][table]["items"][0]["OpenFindings"] = -999
    assert e.query(request)["tables"][table]["items"] == first["tables"][table]["items"]


def test_raw_lifecycle_pager_does_not_recompute_period_or_chart_aggregates(tmp_path, monkeypatch):
    data = datasets()
    data["finding-events"] = [
        {**finding(i), "EventType": "New", "EffectiveTimeUtc": "2026-10-23T13:00:00Z"}
        for i in range(237)
    ]
    e = engine(tmp_path, data)
    request = {"view": "trend", "filters": {"reportingChange": "New"}, "limit": 50}
    first = e.query(request)
    assert first["tables"]["lifecycleHistoryTable"]["total"] == 237
    assert len(first["metadata"]["reportPeriods"]) == 2
    monkeypatch.setattr(e, "_summarize", lambda *args: pytest.fail("pager recomputed period summary"))
    monkeypatch.setattr(e, "_daily_points", lambda *args: pytest.fail("pager recomputed chart series"))
    monkeypatch.setattr(e, "_trend", lambda *args: pytest.fail("pager recomputed trend"))
    page = e.query({**request, "table": "lifecycleHistoryTable", "page": 4})
    assert page["tables"]["lifecycleHistoryTable"]["offset"] == 200
    assert len(page["tables"]["lifecycleHistoryTable"]["items"]) == 37
    assert page["cards"] == first["cards"]
    assert page["charts"] == first["charts"]


def historical_os_data():
    data = datasets(0)
    data["findings"] = [
        finding(0, DeviceId="win-a", OSPlatform="Windows11", OSVersion="22H2"),
        finding(1, DeviceId="win-a", OSPlatform="Windows11", OSVersion="22H2"),
        finding(2, DeviceId="win-b", OSPlatform="Windows11", OSVersion="23H2"),
        finding(3, DeviceId="linux", OSPlatform="Ubuntu", OSVersion="24.04"),
        finding(4, DeviceId="unknown", OSPlatform="", OSVersion=""),
        finding(5, DeviceId="low", OSPlatform="Ubuntu", OSVersion="22.04", Severity="Low"),
    ]
    for row in data["findings"]:
        row["RecommendationId"] = "rec-0"
    data["devices"] = [
        {**row} for row in data["findings"] if row["FindingKey"] != "finding-0001"
    ]
    data["finding-events"] = [
        {**{k: v for k, v in row.items() if k not in ("OSPlatform", "OSVersion")},
         "EventType": "New", "EffectiveTimeUtc": row["FirstSeenUtc"]}
        for row in data["findings"]
    ]
    data["recommendation-events"] = [
        {"RecommendationId": "rec-0", "EventType": "Baseline", "DataOrigin": "Live",
         "EffectiveTimeUtc": "2026-10-23T13:00:00Z", "SnapshotTimeUtc": SNAPSHOT}
    ]
    return data


@pytest.mark.parametrize("entity,windows_new", [("findings", 2), ("machines", 1), ("cves", 2)])
def test_historical_os_breakdown_preserves_entity_units_scope_and_exports(tmp_path, entity, windows_new):
    e = engine(tmp_path, historical_os_data())
    request = {
        "view": "trend", "limit": 1,
        "filters": {"reportingEntity": entity, "reportingBreakdown": "osVersion", "reportingChange": "New", "severity": "High"},
    }
    result = e.query(request)
    table = result["tables"]["lifecycleOsTable"]
    assert table["total"] == 4
    rows = list(e.iter_export({**request, "table": "lifecycleOsTable"}))
    assert len(rows) == 4
    windows = next(row for row in rows if row["OSPlatform"] == "Windows11" and row["OSVersion"] == "22H2")
    assert windows["New"] == windows_new
    assert windows["OSMetadataSource"] == "Snapshot attribution"
    assert any(row["OSPlatform"] == row["OSVersion"] == "Unknown" for row in rows)
    assert not any(row["OSVersion"] == "22.04" for row in rows)
    detail = list(e.iter_export({**request, "table": "lifecycleDetailTable"}))
    assert all("OSPlatform" in row and "OSVersion" in row and "OSMetadataSource" in row for row in detail)
    page = e.query({**request, "table": "lifecycleOsTable", "page": 1})
    assert page["tables"]["lifecycleOsTable"]["offset"] == 1
    assert page["tables"]["lifecycleOsTable"]["items"] != table["items"]


def test_recommendation_os_type_groups_do_not_duplicate_events_across_versions(tmp_path):
    e = engine(tmp_path, historical_os_data())
    request = {"view": "trend", "filters": {
        "reportingEntity": "recommendations", "reportingBreakdown": "osType", "reportingChange": "All",
    }}
    result = e.query(request)
    windows = next(row for row in result["tables"]["lifecycleOsTable"]["items"] if row["OSPlatform"] == "Windows11")
    assert windows["Baseline"] == windows["EvidenceRows"] == 1
    assert "Inactive" in result["tables"]["lifecycleOsTable"]["columns"]
    detail = list(e.iter_export({**request, "table": "lifecycleDetailTable"}))
    assert sum(row["OSPlatform"] == "Windows11" for row in detail) == 1
    assert "OSVersion" not in result["tables"]["lifecycleDetailTable"]["columns"]
    versions = e.query({**request, "filters": {**request["filters"], "reportingBreakdown": "osVersion"}})
    assert len([row for row in versions["tables"]["lifecycleOsTable"]["items"] if row["OSPlatform"] == "Windows11"]) == 2


def test_historical_event_os_is_not_replaced_by_current_device_metadata(tmp_path):
    data = historical_os_data()
    data["finding-events"][0].update(OSPlatform="Windows10", OSVersion="1909")
    data["finding-events"][1].update(OSPlatform="", OSVersion="")
    e = engine(tmp_path, data)
    result = e.query({"view": "trend", "filters": {"reportingBreakdown": "osVersion", "reportingChange": "New"}})
    rows = result["tables"]["lifecycleOsTable"]["items"]
    observed = [row for row in rows if row["OSMetadataSource"] == "Event observation"]
    assert {(row["OSPlatform"], row["OSVersion"]) for row in observed} == {("Windows10", "1909"), ("Unknown", "Unknown")}
    assert not any(row["OSPlatform"] == "Windows11" and row["OSVersion"] == "22H2" for row in rows)


def test_historical_os_working_table_does_not_duplicate_full_event_payloads(tmp_path, monkeypatch):
    e = engine(tmp_path, historical_os_data())
    original = e._table
    checked = []
    def bounded_table(db, response, payload, table_id, *args, **kwargs):
        if table_id == "lifecycleOsTable":
            columns = {row["name"] for row in db.execute("PRAGMA table_info(lifecycle_scoped_events)")}
            assert "data" not in columns
            assert "_event_rowid" in columns
            checked.append(True)
        return original(db, response, payload, table_id, *args, **kwargs)
    monkeypatch.setattr(e, "_table", bounded_table)
    e.query({"view": "trend", "filters": {"reportingBreakdown": "osType", "reportingChange": "All"}})
    assert checked


def test_historical_breakdown_all_is_backward_compatible_and_rejects_unknown_dimension(tmp_path):
    e = engine(tmp_path, historical_os_data())
    result = e.query({"view": "trend", "filters": {"reportingChange": "New"}})
    assert "lifecycleOsTable" not in result["tables"]
    assert result["tables"]["lifecycleHistoryTable"]["total"] == 6
    assert "OSPlatform" not in result["tables"]["lifecycleDetailTable"]["columns"]
    with pytest.raises(ValueError, match="Unknown historical breakdown"):
        e.query({"view": "trend", "filters": {"reportingBreakdown": "untrusted"}})


def test_executive_export_preflight_reuses_report_period_aggregates(tmp_path, monkeypatch):
    e = engine(tmp_path)
    request = {"view": "executiveSnapshot", "limit": 100}
    first = e.query(request)
    monkeypatch.setattr(e, "_summarize", lambda *args: pytest.fail("preflight recomputed period aggregates"))
    monkeypatch.setattr(e, "_executive_report", lambda *args: pytest.fail("preflight recomputed executive report"))
    page = e.query({**request, "table": "executiveSnapshotFindingTable", "page": 2})
    assert page["tables"]["executiveSnapshotFindingTable"]["total"] == 237
    assert len(page["tables"]["executiveSnapshotFindingTable"]["items"]) == 37
    assert page["cards"] == first["cards"]


def test_report_aggregate_cache_is_scope_and_period_specific(tmp_path):
    e = engine(tmp_path)
    current = e.query({"view": "trend", "limit": 1})
    assert current["tables"]["weeklyRiskTable"]["total"] == 12
    empty = e.query({"view": "trend", "limit": 1, "filters": {"severity": "Critical"}})
    assert empty["tables"]["weeklyRiskTable"]["total"] == 0
    prior = e.query({"view": "trend", "limit": 1, "filters": {
        "statisticsPeriod": "custom", "statisticsStartDate": "2020-01-01", "statisticsEndDate": "2020-01-02",
    }})
    assert prior["tables"]["weeklyRiskTable"]["total"] == 0
    page = e.query({"view": "trend", "limit": 1, "table": "weeklyRiskTable", "page": 1})
    assert page["tables"]["weeklyRiskTable"]["total"] == 12


def test_response_cache_enforces_byte_and_entry_budgets():
    cache = OrderedDict()
    for i in range(12):
        DashboardQueryEngine._cache_put(cache, str(i), {"label": "a" * 50}, 10000)
    assert len(cache) == 8
    DashboardQueryEngine._cache_put(cache, "oversized", {"label": "a" * 1000}, 256)
    assert not cache


def test_oversized_group_aggregates_are_not_admitted_to_memory_cache(tmp_path):
    e = engine(tmp_path, datasets(0))
    p = {"view": "trend", "_reportCacheKey": "bounded", "limit": 5}
    out = {"tables": {}}
    with e._connect() as db:
        e._table(db, out, p, "weeklyRiskTable", """
          WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<300)
          SELECT i DeviceId,printf('%010000d',i) DeviceName FROM n
        """, ["DeviceId", "DeviceName"], "machine")
    assert out["tables"]["weeklyRiskTable"]["total"] == 300
    assert len(out["tables"]["weeklyRiskTable"]["items"]) == 5
    assert "bounded:weeklyRiskTable" not in e._aggregates
