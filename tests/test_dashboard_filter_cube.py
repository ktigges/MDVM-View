import random

import pytest

from test_dashboard_queries import SNAPSHOT, datasets, engine, finding
from test_dashboard_read_model import canonical


@pytest.mark.parametrize("filters", [
    {"severity": "High"},
    {"severity": "Critical", "team": "Operations"},
    {"assetClass": "AzureCloud"},
    {"assetClass": "TraditionalIT", "severity": "Low"},
    {"subscription": "NoSubscription"},
    {"subscription": "subscription-1", "severity": "Medium", "team": "Operations"},
    {"exposureStatus": "All"},
    {"exposureStatus": "ConfirmedFixed"},
    {"hideNonReporting": True, "reportingDays": 10},
    {"newPeriod": "week"},
    {"newPeriod": "month", "exposureStatus": "PendingOnly"},
    {"origin": "Live", "domains": ["Cloud"]},
    {"recommendationTypes": ["Misconfiguration", "Vulnerability"]},
])
def test_categorical_rollups_preserve_exact_summary_matching_and_distinct_counts(tmp_path, filters):
    data = datasets(360)
    for index, row in enumerate(data["findings"]):
        row.update(
            Severity=["Critical", "High", "Medium", "Low"][index % 4],
            FindingStatus=["Open", "Fixed", "PendingVerification", "OutOfScope", "Reopened"][index % 5],
            AssetClass="AzureCloud" if index % 3 else "TraditionalIT",
            SubscriptionId="" if index % 7 else "subscription-1",
            SlaStatus=["FixedWithinSla", "FixedOutsideSla", "OpenWithinSla", "OpenOutsideSla"][index % 4],
            EffectiveRemediationUtc="2026-10-24T11:00:00Z" if index % 2 else None,
        )
    expected_engine = engine(tmp_path, data)
    requests = [
        {"view": view, "filters": filters}
        for view in ("executive", "recommendations", "priority", "help", "workstations", "sla", "overview")
    ] + [{"view": "overview", "mode": "cves", "filters": filters, "page": 1, "limit": 7}] + [
        {"view": "detail", "filters": filters, "selection": selection, "page": page, "limit": 7}
        for selection in (
            {"type": "recommendation", "id": "rec-0"},
            {"type": "recommendation", "id": "missing"},
            {"type": "machine", "id": "device-0"},
            {"type": "cve", "id": "CVE-2026-0000"},
        )
        for page in (0, 1)
    ]
    expected = [canonical(expected_engine.query(payload)) for payload in requests]
    expected_engine.read_model.prepare({})
    actual_engine = engine(tmp_path, data)
    for payload, reference in zip(requests, expected, strict=True):
        actual = actual_engine.query(payload)
        assert actual["metadata"]["readModel"] == "filtered-aggregate"
        assert canonical(actual) == reference, payload


def test_incompatible_date_search_and_grouping_scopes_do_not_use_rollups(tmp_path):
    e = engine(tmp_path)
    e.read_model.prepare({})
    for filters in (
        {"search": "finding-0001"}, {"newPeriodFilter": True, "newPeriod": "week"},
        {"remediationPeriodFilter": True}, {"latestRunChangesOnly": True},
        {"workloadGrouping": {"rules": []}}, {"slaPolicy": {"version": "changed"}},
    ):
        result = e.query({"view": "overview", "filters": filters})
        assert result["metadata"]["readModel"] == "exact-query"


def test_filtered_cve_representatives_empty_identifiers_and_latest_outcomes(tmp_path):
    rng = random.Random(47)
    data = datasets(0)
    data["findings"] = [
        finding(
            index, CveId=rng.choice(["", None, "CVE-2026-0001", "CVE-2026-0002"]),
            DeviceId=rng.choice(["", None, "device-1", "device-2"]),
            FindingStatus=rng.choice(["Open", "Fixed", "Reopened", "PendingVerification", None]),
            CvssScore=rng.choice([None, 5.2, 8.1]), Severity=rng.choice(["High", "Medium", None]),
            FixedUtc=rng.choice([None, SNAPSHOT, "2026-10-23T11:00:00Z"]),
            FirstSeenUtc=rng.choice([None, SNAPSHOT]), ReopenedUtc=rng.choice([None, SNAPSHOT]),
            PublicExploitAvailable=rng.choice([True, False]),
        )
        for index in range(500)
    ]
    requests = [
        {"view": view, "filters": filters, "mode": "cves"}
        for filters in (
            {"severity": "High"}, {"exposureStatus": "All"},
            {"exposureStatus": "DetectedOnly"}, {"exposureStatus": "ConfirmedFixed"},
            {"origin": "Live", "exposureStatus": "PendingOnly"},
        )
        for view in ("overview", "sla")
    ]
    e = engine(tmp_path, data)
    expected = [canonical(e.query(payload)) for payload in requests]
    exports = [list(e.iter_export({**payload, "table": "findingsTable"}))
               for payload in requests if payload["view"] == "overview"]
    e.read_model.prepare({})
    restored = engine(tmp_path, data)
    for payload, reference in zip(requests, expected, strict=True):
        actual = canonical(restored.query(payload))
        for name, table in reference["tables"].items():
            for left, right in zip(actual["tables"][name]["items"], table["items"], strict=True):
                assert left == right, (payload, name, {
                    key: (left.get(key), right.get(key)) for key in left.keys() | right.keys()
                    if left.get(key) != right.get(key)
                })
        assert actual == reference, payload
    for payload, reference in zip(
        (payload for payload in requests if payload["view"] == "overview"), exports, strict=True,
    ):
        assert list(restored.iter_export({**payload, "table": "findingsTable"})) == reference


def test_filtered_cve_plan_uses_membership_and_primary_evidence_locators(tmp_path):
    e = engine(tmp_path, datasets(1200))
    e.read_model.prepare({})
    filters = {"severity": "High"}
    with e._connect(filters) as db:
        assert e.read_model.attach(db, filters)
        where, args = e._scope(filters)
        e._finding_scope(db, "scoped", where, args, filters)
        e._view(db, "cube_scoped", "SELECT f.*,f.rowid _bucket_id FROM filter_model.filter_buckets f WHERE " + where, args)
        sql = e._overview_cves_sql(db)
        assert "filter_members" in sql
        plan = [row["detail"] for row in db.execute("EXPLAIN QUERY PLAN " + sql)]
        assert any("SEARCH f USING INTEGER PRIMARY KEY" in step for step in plan)
        assert not any("filter_cves" in step for step in plan)
