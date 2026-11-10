import random

import pytest

from vulnerability_view import dashboard_filter_cube as cube
from vulnerability_view.dashboard_queries import DAY, OBSERVED_FIX_STATUSES, RESOLVED

from test_dashboard_queries import SNAPSHOT, datasets, engine, finding
from test_dashboard_read_model import canonical


@pytest.mark.parametrize("filters", [
    {"severity": "High"},
    {"severity": "Critical", "team": "Operations"},
    {"assetClass": "AzureCloud"},
    {"assetClass": "TraditionalIT", "severity": "Low"},
    {"osType": "Windows11"},
    {"osType": "Linux", "subscription": "NoSubscription"},
    {"osType": "Unknown"},
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
            OSPlatform=["Windows11", "Linux", None, ""][index % 4],
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


@pytest.mark.parametrize("filters", [
    {"search": "finding-0001"},
    {"newPeriodFilter": True, "newPeriod": "custom", "newPeriodStart": "2026-10-24", "newPeriodEnd": "2026-10-24"},
    {"remediationPeriodFilter": True}, {"latestRunChangesOnly": True},
    {"workloadGrouping": {"rules": []}}, {"slaPolicy": {"version": "changed"}},
])
def test_incompatible_date_search_and_grouping_scopes_do_not_use_rollups(tmp_path, filters):
    e = engine(tmp_path)
    e.read_model.prepare({})
    payload = {"view": "overview", "filters": filters}
    expected = canonical(engine(tmp_path / "exact").query(payload))
    result = e.query(payload)
    assert result["metadata"]["readModel"] == "exact-query"
    assert canonical(result) == expected


@pytest.mark.parametrize("severity", ["All", "High"])
def test_equivalent_first_seen_period_uses_rollups_with_exact_results(tmp_path, severity):
    payload = {
        "view": "overview",
        "filters": {"newPeriodFilter": True, "newPeriod": "week", "severity": severity},
    }
    expected = canonical(engine(tmp_path / "exact").query(payload))
    e = engine(tmp_path / "aggregate")
    e.read_model.prepare({})
    result = e.query(payload)
    assert result["metadata"]["readModel"] == "filtered-aggregate"
    assert canonical(result) == expected


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


def test_rollups_hash_groups_not_findings_and_skip_empty_period_histograms(tmp_path, monkeypatch):
    data = datasets(0)
    data["findings"] = [
        finding(
            index, DeviceId="same-device", DeviceName="same-host", RecommendationId="rec-0",
            CveId="" if index % 3 == 0 else f"CVE-2026-{index % 2:04d}",
            FirstObservedUtc="2026-01-01T00:00:00Z", FirstSeenUtc="2026-01-01T00:00:00Z",
            FindingStatus="Open", FixedUtc=None, EffectiveRemediationUtc=None,
        )
        for index in range(600)
    ]
    calls = {"key": 0, "histogram": 0}
    original_key = cube._key

    def key(*values):
        calls["key"] += 1
        return original_key(*values)

    class Histogram(cube.Histogram):
        def step(self, cve, rowid):
            calls["histogram"] += 1
            super().step(cve, rowid)

    monkeypatch.setattr(cube, "_key", key)
    monkeypatch.setattr(cube, "Histogram", Histogram)
    e = engine(tmp_path, data)
    e.read_model.prepare({})
    with e._connect() as db:
        assert e.read_model.attach(db, {})
        count = db.execute("SELECT count(*) FROM read_model.filter_buckets").fetchone()[0]
        assert calls["key"] == count
        assert calls["histogram"] == 400
        for row in db.execute("SELECT * FROM read_model.filter_buckets"):
            for label in cube.PERIODS:
                for prefix in ("new", "fixed"):
                    assert row[f"{prefix}_{label}_count"] == 0
                    assert row[f"{prefix}_{label}_hist"] == b""


def test_dimension_grouping_preserves_original_hash_groups_and_period_memberships(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(
            index, DeviceId="same-device", DeviceName="same-host", RecommendationId="rec-0",
            SubscriptionId=(1, 1.0, "1", "", None)[index % 5],
            CveId=("", None, "CVE-2026-0001", "CVE-2026-0002")[index % 4],
            FirstObservedUtc=("2026-01-01T00:00:00Z", SNAPSHOT)[index % 2],
            EffectiveRemediationUtc=(None, SNAPSHOT)[index % 2],
            FindingStatus=("Open", "Fixed", "PendingVerification")[index % 3],
        )
        for index in range(120)
    ]
    e = engine(tmp_path, data)
    e.read_model.prepare({})
    with e._connect() as db:
        assert e.read_model.attach(db, {})
        cube.register(db)
        e._finding_scope(db, "reference_findings", "1", [], {})
        db.execute(f"CREATE TEMP VIEW reference_source AS SELECT f.*,({RESOLVED}) _resolved FROM reference_findings f")
        dimensions = ",".join("s." + field for field in cube.DIMENSIONS)
        periods = []
        for label, days in cube.PERIODS.items():
            for prefix, field in (("new", "_observed"), ("fixed", "_effective")):
                condition = f"s.{field} BETWEEN {e.snapshot - days * DAY} AND {e.snapshot}"
                if prefix == "fixed":
                    condition += f" AND s.FindingStatus IN {OBSERVED_FIX_STATUSES}"
                periods.extend((
                    f"sum(coalesce({condition},0)) {prefix}_{label}_count",
                    f"cube_histogram(CASE WHEN {condition} THEN c.id END,s._rowid) {prefix}_{label}_hist",
                ))
        expected = db.execute(f"""
            SELECT cube_key({dimensions}) _key,{dimensions},
              min(s._rowid) _sample_finding,count(*) findings,cube_histogram(c.id,s._rowid) cve_hist,
              {','.join(periods)}
            FROM reference_source s LEFT JOIN read_model.filter_cves c ON c.CveId=s._cve
            GROUP BY _key ORDER BY _key
        """).fetchall()
        actual = db.execute("SELECT * FROM read_model.filter_buckets ORDER BY _key").fetchall()
        assert len(actual) == len(expected)
        for left, right in zip(actual, expected, strict=True):
            for name in right.keys():
                if name.endswith("_hist"):
                    assert sorted(cube.members(left[name])) == sorted(cube.members(right[name]))
                else:
                    assert left[name] == right[name], name
