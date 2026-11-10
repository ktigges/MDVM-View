from datetime import datetime

import pytest

from test_dashboard_queries import SNAPSHOT, datasets, engine, finding, historical_os_data
from vulnerability_view import dashboard_management
from vulnerability_view.live_collector import reconcile_live_findings


def management_data():
    data = datasets(0)
    rows = [
        finding(0, DeviceId="one", CveId="CVE-X", RecommendationId="rec-0",
                FindingStatus="Fixed", FixedUtc="2026-10-20T12:00:00Z"),
        finding(1, DeviceId="one", CveId="CVE-Y", RecommendationId="rec-0",
                Severity="Critical", SlaDueUtc="2026-10-22T00:00:00Z"),
        finding(2, DeviceId="two", CveId="CVE-X", RecommendationId="rec-0", KnownExploit=True),
        finding(3, DeviceId="three", CveId="CVE-Z", RecommendationId="rec-1",
                FindingStatus="Fixed", FixedUtc="2026-10-20T12:00:00Z"),
        finding(4, DeviceId="four", CveId="CVE-PENDING", RecommendationId="rec-2",
                FindingStatus="PendingVerification", FixedUtc="2026-10-20T12:00:00Z",
                SlaDueUtc="2026-10-19T00:00:00Z"),
        finding(5, DeviceId="five", CveId="CVE-RETURN", RecommendationId="rec-2",
                FindingStatus="Reopened", FixedUtc="2026-10-20T12:00:00Z", ReopenedUtc="2026-10-22T00:00:00Z"),
        finding(6, DeviceId="six", CveId="CVE-UNKNOWN", RecommendationId="rec-2", SlaDueUtc=None),
    ]
    for row in rows:
        row["FirstSeenUtc"] = row["FirstObservedUtc"] = "2026-10-17T00:00:00Z"
    data["findings"] = [dict(row, FindingKey=f"evidence-{index}-{copy}") for index, row in enumerate(rows) for copy in range(40)]
    return data


def request(view="executiveSnapshot", **filters):
    return {"view": view, "filters": {"managementReporting": True, **filters}}


@pytest.mark.parametrize(("snapshot", "week", "month", "preceding_month"), [
    ("2026-03-02T12:00:00Z", ("2026-02-23", "2026-03-01"), ("2026-02-01", "2026-02-28"), ("2026-01-01", "2026-01-31")),
    ("2024-03-01T12:00:00Z", ("2024-02-19", "2024-02-25"), ("2024-02-01", "2024-02-29"), ("2024-01-01", "2024-01-31")),
    ("2026-01-01T12:00:00Z", ("2025-12-22", "2025-12-28"), ("2025-12-01", "2025-12-31"), ("2025-11-01", "2025-11-30")),
])
def test_sla_dashboard_compares_completed_calendar_periods(snapshot, week, month, preceding_month):
    periods = dashboard_management.sla_calendar_periods(datetime.fromisoformat(snapshot).timestamp())
    assert (periods[1]["start"], periods[1]["end"]) == week
    assert (periods[3]["start"], periods[3]["end"]) == month
    assert (periods[4]["start"], periods[4]["end"]) == preceding_month


def test_dedicated_sla_dashboard_counts_entities_and_keeps_confirmed_rates_separate(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(0, CveId="CVE-PENDING", FindingStatus="PendingConfirmation",
                EffectiveRemediationUtc="2026-10-24T11:00:00Z"),
        finding(1, CveId="CVE-OVERDUE", SlaDueUtc="2026-10-23T00:00:00Z"),
        finding(2, CveId="CVE-UNKNOWN", SlaDueUtc=None),
        finding(3, CveId="CVE-FIXED", FindingStatus="Fixed", FixedUtc="2026-10-24T11:00:00Z"),
    ] * 20
    data["run-history"] = [{"DataOrigin": "Live", "SnapshotTimeUtc": SNAPSHOT,
                            "FindingHistoryStartUtc": "2026-08-01T00:00:00Z"}]
    result = engine(tmp_path, data).query(request("slaDashboard"))
    report = result["metadata"]["slaDashboard"]
    assert report["unit"] == "distinct-entities"
    assert report["periods"][0]["machines"] == report["periods"][0]["cves"]
    current = report["periods"][0]["cves"]
    assert current["openWithin"] == current["openOverdue"] == current["unknownOpen"] == 1
    assert current["openWithinPercent"] == 50
    assert current["completedWithin"] == current["awaitingConfirmation"] == 1
    assert current["completionPercent"] == 100
    assert current["observedFixes"] == 2
    assert len(report["periods"]) == 5
    assert all(row["coverage"] == "complete" for row in report["periods"])
    assert not result["tables"]
    assert "management" not in result["metadata"]
    assert not engine(tmp_path, data).is_interactive(request("slaDashboard"))


def test_sla_calendar_history_gaps_are_not_zero_or_success(tmp_path):
    data = datasets(0)
    data["findings"] = [finding(0)]
    data["run-history"] = [{"DataOrigin": "Live", "SnapshotTimeUtc": SNAPSHOT,
                            "FindingHistoryStartUtc": "2026-10-23T00:00:00Z"}]
    report = engine(tmp_path, data).query(request("slaDashboard"))["metadata"]["slaDashboard"]
    assert report["periods"][0]["coverage"] == "partial"
    assert report["periods"][0]["cves"]["completionPercent"] is None
    for period in report["periods"][1:]:
        assert period["coverage"] == "unavailable"
        for entity in ("cves", "machines"):
            assert period[entity]["openWithinPercent"] is None
            assert period[entity]["completionPercent"] is None
            assert period[entity]["openWithin"] is None
    filtered = engine(tmp_path, data).query(request("slaDashboard", severity="Low"))
    assert filtered["metadata"]["slaDashboard"]["periods"][0]["cves"]["openWithinPercent"] is None


def test_sla_dashboard_calendar_outcomes_use_their_own_period_and_deadline(tmp_path):
    data = datasets(0)
    fixed = [
        ("2026-08-15T12:00:00Z", "2026-08-15T12:00:00Z"),
        ("2026-09-11T12:00:00Z", "2026-09-10T12:00:00Z"),
        ("2026-10-07T12:00:00Z", "2026-10-07T12:00:00Z"),
        ("2026-10-14T12:00:00Z", "2026-10-13T12:00:00Z"),
    ]
    data["findings"] = [
        finding(index, FindingStatus="Fixed", FixedUtc=completed, SlaDueUtc=due,
                FirstObservedUtc="2026-07-01T00:00:00Z", FirstSeenUtc="2026-07-01T00:00:00Z")
        for index, (completed, due) in enumerate(fixed)
    ] * 3
    data["run-history"] = [{"DataOrigin": "Live", "SnapshotTimeUtc": SNAPSHOT,
                            "FindingHistoryStartUtc": "2026-07-01T00:00:00Z"}]
    periods = engine(tmp_path, data).query(request("slaDashboard"))["metadata"]["slaDashboard"]["periods"]
    periods = [period["cves"] for period in periods]
    assert periods[0]["completionPercent"] == 50
    assert [period["completionPercent"] for period in periods[1:]] == [0, 100, 0, 100]
    assert all(period["confirmedFixes"] == 1 for period in periods[1:])
    assert periods[2]["completedWithin"] == 1


def test_sla_dashboard_partial_calendar_period_is_withheld(tmp_path):
    data = datasets(0)
    data["findings"] = [finding(0)]
    data["run-history"] = [{"DataOrigin": "Live", "SnapshotTimeUtc": SNAPSHOT,
                            "FindingHistoryStartUtc": "2026-10-08T00:00:00Z"}]
    periods = engine(tmp_path, data).query(request("slaDashboard"))["metadata"]["slaDashboard"]["periods"]
    assert periods[1]["coverage"] == "complete"
    assert periods[2]["coverage"] == "partial"
    assert periods[2]["cves"]["completionPercent"] is None
    assert periods[2]["cves"]["openWithin"] is None
    assert periods[2]["cves"]["severity"] == []


def test_sla_dashboard_unknown_only_and_no_history_never_claim_compliance(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(0, SlaDueUtc=None),
        finding(1, SlaDueUtc=None, FindingStatus="PendingConfirmation",
                EffectiveRemediationUtc="2026-10-24T11:00:00Z"),
    ]
    report = engine(tmp_path, data).query(request("slaDashboard"))["metadata"]["slaDashboard"]
    assert report["periods"][0]["coverage"] == "unavailable"
    current = report["periods"][0]["cves"]
    assert current["unknownOpen"] == 2
    assert current["openWithinPercent"] is current["completionPercent"] is None
    assert current["confirmedFixes"] == 0
    assert current["awaitingConfirmation"] == current["observedFixes"] == 1
    assert all(period["cves"]["completionPercent"] is None for period in report["periods"][1:])


def test_sla_dashboard_does_not_multiply_cves_machines_or_software(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(0, DeviceId="one", CveId="CVE-SHARED", Severity="High"),
        finding(1, DeviceId="two", CveId="CVE-SHARED", Severity="High"),
        finding(2, DeviceId="one", CveId="CVE-OTHER", Severity="Medium", SlaDueUtc="2026-10-23T00:00:00Z"),
        finding(3, DeviceId="three", CveId="CVE-UNKNOWN", Severity="Medium", SlaDueUtc=None),
        finding(4, DeviceId="one", CveId="CVE-UNKNOWN", Severity="Medium", SlaDueUtc=None),
    ] * 100
    report = engine(tmp_path, data).query(request("slaDashboard"))["metadata"]["slaDashboard"]
    current = report["periods"][0]
    for entity in ("cves", "machines"):
        assert current[entity]["totalOpen"] == 3
        assert sum(row["totalOpen"] for row in current[entity]["severity"]) == 3
        assert current[entity]["openWithin"] == current[entity]["openOverdue"] == current[entity]["unknownOpen"] == 1
    assert {row["label"]: row["totalOpen"] for row in current["cves"]["severity"]} == {
        "Critical": 0, "High": 1, "Medium": 2, "Low": 0,
    }
    assert {row["label"]: row["totalOpen"] for row in current["machines"]["severity"]} == {
        "Critical": 0, "High": 2, "Medium": 1, "Low": 0,
    }
    assert "totalOpen" not in current


@pytest.mark.parametrize("view", ["executive", "overview", "sla", "trend", "executiveSnapshot"])
def test_shared_sla_panels_use_distinct_entities_even_after_cache_restore(tmp_path, view):
    data = datasets(0)
    data["findings"] = [
        finding(0, DeviceId="one", CveId="CVE-SHARED"),
        finding(1, DeviceId="two", CveId="CVE-SHARED"),
    ] * 100
    result = engine(tmp_path, data).query(request(view))
    restored = engine(tmp_path, data).query(request(view))
    prefix = view + "Management"
    graph = result["charts"][prefix + "SlaSnapshot"]
    assert graph == restored["charts"][prefix + "SlaSnapshot"]
    assert graph["kind"] == "entity-sla-status"
    assert [(row["label"], row["totalOpen"]) for row in graph["rows"]] == [("CVEs", 1), ("Machines", 2)]
    assert all(value == 0 for value, _ in result["cards"][prefix + "FixActivity"])
    assert not any("MachineCve" in column for column in result["tables"][prefix + "ComparisonTable"]["columns"])


def test_sla_entity_full_clearance_is_not_partial_or_pending_progress(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(0, DeviceId="one", CveId="CVE-SHARED", FindingStatus="Fixed", FixedUtc="2026-10-24T11:00:00Z"),
        finding(1, DeviceId="two", CveId="CVE-SHARED"),
        finding(2, DeviceId="one", CveId="CVE-OPEN"),
        finding(3, DeviceId="three", CveId="CVE-FIXED", FindingStatus="Fixed", FixedUtc="2026-10-24T11:00:00Z"),
        finding(4, DeviceId="four", CveId="CVE-PENDING", FindingStatus="PendingConfirmation",
                EffectiveRemediationUtc="2026-10-24T11:00:00Z"),
    ] * 30
    current = engine(tmp_path, data).query(request("slaDashboard"))["metadata"]["slaDashboard"]["periods"][0]
    for entity in ("cves", "machines"):
        assert current[entity]["totalOpen"] == 3
        assert current[entity]["confirmedFixes"] == current[entity]["completedWithin"] == 1
        assert current[entity]["improved"] == current[entity]["awaitingConfirmation"] == 1
        assert current[entity]["observedFixes"] == 3


def test_full_clearance_assesses_earlier_late_and_unknown_components(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(0, DeviceId="one", CveId="CVE-SHARED", FindingStatus="Fixed",
                FirstObservedUtc="2026-08-01T00:00:00Z", FixedUtc="2026-09-20T00:00:00Z",
                SlaDueUtc="2026-09-19T00:00:00Z"),
        finding(1, DeviceId="two", CveId="CVE-SHARED", FindingStatus="Fixed",
                FixedUtc="2026-10-24T11:00:00Z"),
        finding(2, DeviceId="three", CveId="CVE-UNKNOWN", FindingStatus="Fixed",
                FirstObservedUtc="2026-08-01T00:00:00Z", FixedUtc="2026-09-20T00:00:00Z", SlaDueUtc=None),
        finding(3, DeviceId="four", CveId="CVE-UNKNOWN", FindingStatus="Fixed",
                FixedUtc="2026-10-24T11:00:00Z"),
    ]
    current = engine(tmp_path, data).query(request("slaDashboard"))["metadata"]["slaDashboard"]["periods"][0]
    assert current["cves"]["confirmedFixes"] == 2
    assert current["cves"]["completedLate"] == current["cves"]["completedUnknown"] == 1
    assert current["cves"]["completedWithin"] == 0
    assert current["machines"]["confirmedFixes"] == current["machines"]["completedWithin"] == 2


@pytest.mark.parametrize("view", ["executive", "executiveSnapshot", "trend", "overview"])
def test_observed_progress_totals_include_pending_without_claiming_completed_sla(tmp_path, view):
    data = datasets(0)
    data["findings"] = [
        finding(0, DeviceId="one", CveId="CVE-PENDING", FindingStatus="PendingConfirmation",
                EffectiveRemediationUtc="2026-10-24T11:00:00Z"),
        finding(1, DeviceId="one", CveId="CVE-FIXED", FindingStatus="Fixed",
                FixedUtc="2026-10-24T11:00:00Z"),
        finding(2, DeviceId="one", CveId="CVE-OVERDUE", SlaDueUtc="2026-10-23T00:00:00Z"),
        finding(3, DeviceId="one", CveId="CVE-UNKNOWN", SlaDueUtc=None),
    ] * 10
    result = engine(tmp_path, data).query(request(view))
    prefix = view + "Management"
    assert result["cards"][prefix + "FixActivity"] == [
        [1, "CVEs fully cleared"], [0, "CVEs improved, still unresolved"],
        [1, "CVEs with fixes awaiting confirmation"],
        [0, "Machines fully cleared"], [1, "Machines improved, still unresolved"],
        [1, "Machines with fixes awaiting confirmation"],
    ]
    row = result["tables"][prefix + "MachineTable"]["items"][0]
    assert row["TotalObservedFixes"] == 2
    assert row["FixedCVEs"] == row["FixesAwaitingConfirmation"] == 1
    assert row["OpenWithinSLA"] == row["OverdueOutcomes"] == row["UnknownOpenSLA"] == 1
    assert row["OpenSLAWithinRate"] == "50.0%"
    assert row["SLACompliance"] == "100.0%"
    comparison = result["tables"][prefix + "ComparisonTable"]["items"][0]
    assert comparison["TotalObservedMachineCveFixes"] == 2
    assert comparison["OpenMachineCveWithinSLA"] == "50%"
    assert result["metadata"]["management"]["sla"]["periods"][0]["outcomes"]["Remaining"] == 3
    exported = list(engine(tmp_path, data).iter_export({**request(view), "table": prefix + "MachineTable"}))
    assert exported[0]["TotalObservedFixes"] == 2
    assert exported[0]["OpenSLAWithinRate"] == "50.0%"


@pytest.mark.parametrize("view", ["executive", "overview", "executiveSnapshot", "trend", "sla"])
def test_management_counts_unique_entities_and_separates_progress_from_resolution(tmp_path, view):
    result = engine(tmp_path, management_data()).query(request(view, statisticsPeriod="30days"))
    current = result["metadata"]["management"]["periods"][0]
    for entity in ("machines", "cves"):
        assert {key: current[entity][key] for key in ("Open", "Improved", "FullyResolved", "Overdue", "Pending", "UnknownSla")} == {
            "Open": 5, "Improved": 1, "FullyResolved": 1, "Overdue": 2, "Pending": 1, "UnknownSla": 1,
        }
    assert current["recommendations"]["Open"] == 2
    assert current["recommendations"]["Improved"] == 1
    assert current["recommendations"]["FullyResolved"] == 1
    prefix = view + "Management"
    machine_rows = {row["DeviceId"]: row for row in result["tables"][prefix + "MachineTable"]["items"]}
    assert machine_rows["one"]["ProgressStatus"] == "Improved"
    assert machine_rows["three"]["ProgressStatus"] == "Fully resolved"
    assert machine_rows["four"]["ProgressStatus"] == "Still open"
    assert machine_rows["five"]["ProgressStatus"] == "Still open"
    assert machine_rows["six"]["SlaStatus"] == "Unknown SLA"
    assert machine_rows["one"]["DeviceName"]
    cves = {row["CveId"]: row for row in result["tables"][prefix + "CveTable"]["items"]}
    assert cves["CVE-X"]["ProgressStatus"] == "Improved"
    assert cves["CVE-X"]["AffectedMachines"] == 1
    assert cves["CVE-X"]["Severity"] == "High"
    for name in ("Machine", "Cve", "Recommendation"):
        columns = result["tables"][prefix + name + "Table"]["columns"]
        assert not any("Finding" in column for column in columns)
    assert "finding instances" not in result["texts"]["filterCount"]
    severity = result["charts"][prefix + "Severity"]["rows"]
    assert sum(row["machines"] for row in severity) == 5
    assert sum(row["cves"] for row in severity) == 5
    assert "executiveSnapshotKpis" not in result["cards"]


def test_management_resolution_uses_full_scope_not_only_changed_rows(tmp_path):
    data = management_data()
    e = engine(tmp_path, data)
    expected = e.query(request())["metadata"]["management"]
    actual = e.query(request(latestRunChangesOnly=True, exposureStatus="FixedOnly"))["metadata"]["management"]
    assert actual == expected
    scoped = e.query(request(severity="High"))["metadata"]["management"]["periods"][0]
    assert scoped["machines"]["FullyResolved"] == 2
    assert scoped["machines"]["Improved"] == 0


def test_management_historical_resolution_precedes_later_confirmed_reopening(tmp_path):
    result = engine(tmp_path, management_data()).query(request(
        executiveSnapshotPeriod="custom", executiveSnapshotStart="2026-10-20", executiveSnapshotEnd="2026-10-21",
    ))
    rows = result["tables"]["executiveSnapshotManagementMachineTable"]["items"]
    assert next(row for row in rows if row["DeviceId"] == "five")["ProgressStatus"] == "Fully resolved"
    assert next(row for row in rows if row["DeviceId"] == "four")["ProgressStatus"] == "Still open"


def test_management_does_not_backdate_machine_risk_to_cve_catalog_first_seen(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(0, FirstSeenUtc="2023-01-01T00:00:00Z",
                FirstObservedUtc="2026-10-23T13:00:00Z"),
        finding(1, DeviceId="pending", CveId="CVE-PENDING",
                FindingStatus="PendingVerification", FirstSeenUtc="2023-01-01T00:00:00Z",
                FirstObservedUtc="2026-10-23T13:00:00Z"),
    ]
    data["run-history"] = [{
        "DataOrigin": "Live", "SnapshotTimeUtc": "2026-10-24T12:00:00Z",
        "FindingHistoryStartUtc": "2026-10-23T13:00:00Z",
    }]
    e = engine(tmp_path, data)
    before = e.query(request(executiveSnapshotPeriod="custom", executiveSnapshotStart="2026-10-20",
                             executiveSnapshotEnd="2026-10-21"))
    assert before["metadata"]["management"]["periods"][0]["machines"]["Open"] == 0
    assert before["metadata"]["management"]["periods"][0]["cves"]["Open"] == 0
    assert before["metadata"]["management"]["sla"]["periods"][0]["CompliancePercent"] is None
    assert before["metadata"]["management"]["periods"][0]["Coverage"] == "No retained observations"
    assert before["cards"]["executiveSnapshotManagementCards"][0][0] == "Not observed"
    assert before["charts"]["executiveSnapshotManagementSeverity"]["available"] is False
    assert before["charts"]["executiveSnapshotManagementMovement"]["rows"] == []
    current = e.query(request())
    assert current["metadata"]["management"]["periods"][0]["machines"]["Open"] == 2


def test_management_sla_completion_denominator_excludes_open_and_unknown_outcomes(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(0, DeviceId="fixed", CveId="CVE-FIXED", Severity="Critical",
                FindingStatus="Fixed", FixedUtc="2026-10-24T11:00:00Z"),
        finding(1, DeviceId="open", CveId="CVE-OPEN", Severity="Critical"),
        finding(2, DeviceId="unknown", CveId="CVE-UNKNOWN", Severity="Unknown",
                FindingStatus="Fixed", FixedUtc="2026-10-24T11:00:00Z", SlaDueUtc=None),
    ]
    result = engine(tmp_path, data).query(request())
    sla = result["metadata"]["management"]["sla"]["periods"][0]
    assert sla["CompliancePercent"] == 100
    assert sla["outcomes"] == {"WithinSLA": 1, "LateSLA": 0, "UnknownSLA": 1, "Remaining": 1, "Fixed": 2,
                               "AwaitingConfirmation": 0}
    severity = {row["label"]: row for row in sla["severity"]}
    assert severity["Critical"]["assessed"] == severity["Critical"]["completedWithin"] == 1
    assert severity["Critical"]["within"] == 100
    assert severity["High"]["within"] is None
    assert severity["Unknown"]["assessed"] == 0
    assert severity["Unknown"]["completedUnknown"] == 1
    assert result["charts"]["executiveSnapshotManagementSlaSeverity"]["kind"] == "entity-sla-status"


def test_recommendation_type_scope_classifies_catalog_once_not_per_evidence_row(tmp_path):
    data = datasets(1000)
    data["recommendations"][1].update(RecommendationName="Harden TLS", RemediationType="Configuration")
    e = engine(tmp_path, data)
    e._ensure("findings")
    e._ensure("recommendations")
    calls = []
    with e._connect() as db:
        db.create_function("counted_kind", 1, lambda kind: calls.append(kind) or kind)
        db.execute("""CREATE TEMP VIEW recommendations AS
          SELECT RecommendationId,_rowid,counted_kind(_kind) _kind FROM main.recommendations""")
        where, args = e._scope({}, exposure=False, periods=False, remediation=False)
        count = db.execute(f"SELECT count(*) FROM findings f WHERE {where}", args).fetchone()[0]
    assert count == 667
    assert len(calls) <= len(data["recommendations"])


@pytest.mark.parametrize("kinds", [["Vulnerability"], ["Misconfiguration"], [], ["Vulnerability", "Misconfiguration"]])
def test_recommendation_type_scope_preserves_scalar_identity_and_first_catalog_row(tmp_path, kinds):
    data = datasets(0)
    identities = [None, "", 0, "0", 1, 1.0, "1", "duplicate", "unmapped"]
    data["findings"] = [finding(i, RecommendationId=value) for i, value in enumerate(identities)]
    data["recommendations"] = [
        {"RecommendationId": identity, "RecommendationName": name, "RemediationType": remediation}
        for identity, name, remediation in [
            (None, "Harden", "Configuration"), ("", "Harden", "Configuration"),
            (0, "Update", "Update"), ("0", "Harden", "Configuration"),
            (1, "Harden", "Configuration"), ("1", "Update", "Update"),
            ("duplicate", "Update", "Update"), ("duplicate", "Harden", "Configuration"),
        ]
    ]
    e = engine(tmp_path, data)
    e._ensure("findings")
    e._ensure("recommendations")
    with e._connect() as db:
        where, args = e._scope({"recommendationTypes": kinds}, exposure=False, periods=False, remediation=False)
        actual = [row[0] for row in db.execute(f"SELECT f._rowid FROM findings f WHERE {where} ORDER BY f._rowid", args)]
        expected = [row[0] for row in db.execute(
            "SELECT f._rowid FROM findings f WHERE coalesce((SELECT r._kind FROM recommendations r "
            "WHERE r.RecommendationId=f.RecommendationId LIMIT 1),'Vulnerability') "
            f"IN ({','.join('?' for _ in kinds) or 'NULL'}) ORDER BY f._rowid", kinds)]
    assert actual == expected


def test_management_missing_identifiers_do_not_create_phantom_machines_or_cves(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(index, DeviceId=device, CveId=cve)
        for index, (device, cve) in enumerate([(None, None), ("", ""), (0, "CVE-A"), ("0", "CVE-A"), (1, "CVE-A"), (1.0, "CVE-A")])
    ]
    summary = engine(tmp_path, data).query(request())["metadata"]["management"]["periods"][0]
    assert summary["machines"]["Open"] == 3
    assert summary["cves"]["Open"] == 1


def test_management_pending_unknown_clock_and_future_deadline_remain_honest(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(0, DeviceId="pending", FindingStatus="PendingConfirmation", FixedUtc="2026-10-24T11:00:00Z"),
        finding(1, DeviceId="unknown-clock", FirstSeenUtc=None, FirstObservedUtc=None, SlaDueUtc=None),
        finding(2, DeviceId="future-deadline", SlaDueUtc="2026-10-24T18:00:00Z"),
    ]
    result = engine(tmp_path, data).query(request())
    current = result["metadata"]["management"]["periods"][0]["machines"]
    assert current["Open"] == 3
    assert current["FullyResolved"] == 0
    assert current["Overdue"] == 0
    assert current["UnknownSla"] == 1


def test_management_pages_and_streamed_exports_are_unique_entity_rows(tmp_path):
    data = datasets(65)
    for index, row in enumerate(data["findings"]):
        row["DeviceId"] = f"machine-{index:03}"
    e = engine(tmp_path, data)
    payload = request()
    first = e.query(payload)
    table = "executiveSnapshotManagementMachineTable"
    page = e.query({**payload, "table": table, "page": 1, "limit": 10})
    assert len(first["tables"][table]["items"]) == len(page["tables"][table]["items"]) == 10
    assert page["tables"][table]["offset"] == 10
    assert not {row["DeviceId"] for row in first["tables"][table]["items"]} & {
        row["DeviceId"] for row in page["tables"][table]["items"]
    }
    exported = list(e.iter_export({**payload, "table": table}))
    assert len(exported) == len({row["DeviceId"] for row in exported}) == 65
    assert all(row.get("DeviceName") and "OpenFindings" not in row for row in exported)
    assert all(row["ReportRepresentation"] == "Unique machines" and row["PeriodEnd"] == "2026-10-24" for row in exported)
    assert all('"recommendationTypes": ["Vulnerability"]' in row["ResolutionScope"] for row in exported)
    restored = engine(tmp_path, data).query(payload)
    assert restored["metadata"]["management"] == first["metadata"]["management"]
    assert restored["tables"][table] == first["tables"][table]


def test_management_prepared_read_model_does_not_change_entity_counts(tmp_path):
    data = management_data()
    e = engine(tmp_path, data)
    expected = e.query(request())["metadata"]["management"]
    e.read_model.prepare({})
    result = engine(tmp_path, data).query(request(executiveSnapshotOwner="Operations"))
    assert result["metadata"]["management"] == expected


def test_management_finding_evidence_is_explicit_opt_in(tmp_path):
    result = engine(tmp_path, management_data()).query(request(includeFindingEvidence=True))
    assert "executiveSnapshotKpis" in result["cards"]
    assert result["metadata"]["management"]["periods"][0]["machines"]["Open"] == 5


@pytest.mark.parametrize("entity,expected", [("machines", 4), ("cves", 5)])
@pytest.mark.parametrize("breakdown", ["All", "osType", "osVersion"])
def test_management_activity_and_os_exports_respect_scope_without_claiming_resolution(tmp_path, entity, expected, breakdown):
    e = engine(tmp_path, historical_os_data())
    payload = request("trend", statisticsPeriod="30days", reportingEntity=entity,
                      reportingChange="New", reportingBreakdown=breakdown, severity="High")
    result = e.query(payload)
    assert result["tables"]["lifecycleDetailTable"]["total"] == expected
    columns = result["tables"]["lifecycleDetailTable"]["columns"]
    assert not any("Findings" in column for column in columns)
    rows = list(e.iter_export({**payload, "table": "lifecycleDetailTable"}))
    assert len(rows) == expected
    assert all(not any("Findings" in key for key in row) for row in rows)
    assert all(row.get("DeviceId") != "low" and row.get("CveId") != "CVE-2026-0005" for row in rows)
    assert result["cards"]["lifecycleCards"][2][0] == 0
    if breakdown != "All":
        assert all("OSPlatform" in row and "OSMetadataSource" in row for row in rows)


def test_management_evaluates_each_period_clock_once_per_source_row(tmp_path, monkeypatch):
    data = management_data()
    e = engine(tmp_path, data)
    e._ensure("findings")
    periods = [{"label": "Selected", "start": "2026-10-01", "end": "2026-10-24"},
               {"label": "Previous", "start": "2026-09-01", "end": "2026-09-30"}]
    calls = []
    with e._connect() as db:
        e._finding_scope(db, "management_scope", "1", [], {})
        db.create_function("counted_open", 2, lambda rowid, end: calls.append((rowid, end)) or 1)
        monkeypatch.setattr(dashboard_management, "unresolved_at", lambda end: f"counted_open(_rowid,{end})")
        dashboard_management.build_entities(db, periods, e.snapshot)
        dashboard_management.build_sla(db, periods, e.snapshot)
    assert len(calls) == len(data["findings"]) * len(periods)


def test_management_fixed_evidence_with_unknown_first_seen_can_still_be_resolved(tmp_path):
    data = datasets(0)
    data["findings"] = [finding(0, FindingStatus="Fixed", FirstSeenUtc=None, FirstObservedUtc=None,
                                FixedUtc="2026-10-23T12:00:00Z")]
    current = engine(tmp_path, data).query(request())["metadata"]["management"]["periods"][0]
    assert current["machines"]["FullyResolved"] == current["cves"]["FullyResolved"] == 1


def test_management_empty_scope_does_not_invent_entities_or_resolution(tmp_path):
    result = engine(tmp_path, datasets(0)).query(request())
    current = result["metadata"]["management"]["periods"][0]
    assert all(value == 0 for entity in dashboard_management.ENTITIES for value in current[entity].values())
    assert result["tables"]["executiveSnapshotManagementMachineTable"]["total"] == 0
    assert result["texts"]["executiveSnapshotContext"] == result["texts"]["executiveSnapshotManagementContext"]


def test_management_vulnerability_csv_omits_technical_instance_counts(tmp_path):
    e = engine(tmp_path, management_data())
    payload = {**request("overview"), "mode": "cves", "table": "findingsTable"}
    rows = list(e.iter_export(payload))
    assert len(rows) == len({row["CveId"] for row in rows})
    assert all(not {"OpenFindings", "PendingFindings", "FixedFindings", "EvidenceRows"} & row.keys() for row in rows)


def test_management_recommendation_activity_csv_does_not_leak_instance_counters(tmp_path):
    data = historical_os_data()
    data["recommendation-events"][0].update(OpenFindings=1000000, FixedFindings=12345)
    e = engine(tmp_path, data)
    payload = request("trend", statisticsPeriod="30days", reportingEntity="recommendations", reportingChange="All")
    rows = list(e.iter_export({**payload, "table": "lifecycleDetailTable"}))
    assert len(rows) == 1
    assert rows[0]["RecommendationId"] == "rec-0"
    assert "OpenFindings" not in rows[0] and "FixedFindings" not in rows[0]


@pytest.mark.parametrize("prepared", [False, True])
@pytest.mark.parametrize("view,table", [
    ("recommendations", "recommendationTable"), ("priority", "priorityTable"), ("workstations", "workstationTable"),
])
def test_management_operational_lists_keep_machine_cve_units_and_exports(tmp_path, prepared, view, table):
    data = management_data()
    e = engine(tmp_path, data)
    if prepared:
        e.read_model.prepare({})
    result = e.query(request(view))
    assert not {"OpenFindings", "PendingFindings", "CurrentThingsToFix", "VulnerabilityMix", "FixImpact"} & set(
        result["tables"][table]["columns"]
    )
    rows = list(e.iter_export({**request(view), "table": table}))
    assert all(not {"OpenFindings", "PendingFindings", "CurrentThingsToFix", "VulnerabilityMix", "FixImpact"} & row.keys() for row in rows)
    if view != "workstations":
        cards = {card[1]: card[0] for card in result["cards"]["recommendationCards"]}
        assert cards["Machines with open risk"] == cards["Open vulnerabilities (unique CVEs)"] == 5
    else:
        assert not any(card[1] == "Detected endpoint findings" for card in result["cards"]["workstationCards"])


def machine_sla_data():
    data = datasets(0)
    data["findings"] = [
        finding(0, DeviceId="machine-x", CveId="CVE-A", FindingStatus="Fixed",
                FixedUtc="2026-10-20T12:00:00Z", SlaDueUtc="2026-10-21T00:00:00Z"),
        finding(1, DeviceId="machine-x", CveId="CVE-B", FindingStatus="Fixed",
                FixedUtc="2026-10-22T12:00:00Z", SlaDueUtc="2026-10-21T00:00:00Z"),
        finding(2, DeviceId="machine-x", CveId="CVE-C", SlaDueUtc="2026-11-01T00:00:00Z"),
        finding(3, DeviceId="machine-y", CveId="CVE-A"),
    ]
    for row in data["findings"]:
        row["FirstSeenUtc"] = row["FirstObservedUtc"] = "2026-10-17T00:00:00Z"
    data["findings"] = [dict(row, FindingKey=f"{row['FindingKey']}-{copy}", SoftwareVersion=str(copy))
                        for row in data["findings"] for copy in range(25)]
    return data


@pytest.mark.parametrize("view", ["executive", "executiveSnapshot", "sla", "overview", "trend"])
def test_machine_cve_sla_three_cves_two_fixed_one_remaining(tmp_path, view):
    e = engine(tmp_path, machine_sla_data())
    payload = request(view, statisticsPeriod="30days")
    result = e.query(payload)
    rows = result["tables"][view + "ManagementMachineTable"]["items"]
    machine = next(row for row in rows if row["DeviceId"] == "machine-x")
    assert machine["OpenCVEs"] == 1
    assert machine["FixedCVEs"] == 2
    assert machine["CompletedWithinSLA"] == machine["CompletedLate"] == 1
    assert machine["SLACompliance"] == "50.0%"
    assert "ExecutiveStatus" not in machine
    assert machine["ProgressStatus"] == "Improved"
    sla = result["metadata"]["management"]["sla"]
    assert sla["unit"] == "machine-cve"
    assert sla["periods"][0]["CompliancePercent"] == 50
    # CVE-A is fixed on X, but remains open on Y.
    cve = next(row for row in result["tables"][view + "ManagementCveTable"]["items"] if row["CveId"] == "CVE-A")
    assert cve["ProgressStatus"] == "Improved" and cve["FixedMachines"] == 1
    assert "ExecutiveStatus" not in sla["periods"][0]
    for suffix in ("SlaSeverity", "Movement"):
        assert view + "Management" + suffix in result["charts"]
    assert not any(key.endswith(("MachinesStatus", "CVEsStatus")) for key in result["charts"])
    exported = list(e.iter_export({**payload, "table": view + "ManagementMachineTable"}))
    assert next(row for row in exported if row["DeviceId"] == "machine-x")["FixedCVEs"] == 2
    assert all("OpenFindings" not in row for row in exported)


def test_machine_cve_sla_partial_software_fix_does_not_count_as_cve_fixed(tmp_path):
    data = machine_sla_data()
    data["findings"].append(finding(1000, DeviceId="machine-x", CveId="CVE-A",
                                    FirstSeenUtc="2026-10-17T00:00:00Z"))
    result = engine(tmp_path, data).query(request())
    row = next(row for row in result["tables"]["executiveSnapshotManagementMachineTable"]["items"] if row["DeviceId"] == "machine-x")
    assert row["OpenCVEs"] == 2 and row["FixedCVEs"] == 1
    assert row["SLACompliance"] == "0.0%"


def test_machine_cve_sla_uses_earliest_deadline_and_last_confirmed_removal(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(0, DeviceId="x", CveId="CVE-A", FindingStatus="Fixed",
                FirstSeenUtc="2026-10-17T00:00:00Z", FixedUtc="2026-10-20T00:00:00Z",
                SlaDueUtc="2026-10-21T00:00:00Z"),
        finding(1, DeviceId="x", CveId="CVE-A", FindingStatus="Fixed",
                FirstSeenUtc="2026-10-17T00:00:00Z", FixedUtc="2026-10-22T00:00:00Z",
                SlaDueUtc="2026-11-01T00:00:00Z"),
    ]
    result = engine(tmp_path, data).query(request())
    row = result["tables"]["executiveSnapshotManagementMachineTable"]["items"][0]
    assert row["FixedCVEs"] == 1 and row["CompletedLate"] == 1
    assert row["SLACompliance"] == "0.0%" and row["CompletedLate"] == 1


@pytest.mark.parametrize("status", ["PendingVerification", "PendingConfirmation"])
def test_machine_cve_sla_pending_is_never_completed(tmp_path, status):
    data = datasets(0)
    data["findings"] = [finding(0, FindingStatus=status, FixedUtc="2026-10-24T11:00:00Z")]
    result = engine(tmp_path, data).query(request())
    assert result["metadata"]["management"]["sla"]["periods"][0]["CompliancePercent"] is None
    row = result["tables"]["executiveSnapshotManagementMachineTable"]["items"][0]
    assert row["FixedCVEs"] == 0 and row["PendingEvidence"] == "Yes"

@pytest.mark.parametrize("view", ["executive", "overview", "sla", "trend", "executiveSnapshot"])
def test_observed_fixes_are_visible_before_confirmation_without_completed_sla(tmp_path, view):
    data = datasets(0)
    row = finding(
        0, FindingStatus="PendingConfirmation", EffectiveRemediationUtc="2026-10-24T11:00:00Z",
        SlaStatus="FixedWithinSla", FixedUtc="",
    )
    data["findings"] = [dict(row, FindingKey=f"duplicate-{i}") for i in range(10)]
    result = engine(tmp_path, data).query(request(view))
    prefix = view + "Management"
    sla = result["metadata"]["management"]["sla"]["periods"][0]
    assert sla["outcomes"]["AwaitingConfirmation"] == 1
    assert sla["outcomes"]["Fixed"] == sla["outcomes"]["WithinSLA"] == sla["outcomes"]["LateSLA"] == 0
    assert sla["CompliancePercent"] is None
    machine = result["tables"][prefix + "MachineTable"]["items"][0]
    assert machine["FixesAwaitingConfirmation"] == 1
    assert machine["SLACompliance"] == "Waiting for data"
    assert machine["ProgressStatus"] == "Fix observed — awaiting confirmation"
    severity = next(row for row in sla["severity"] if row["label"] == "High")
    assert severity["awaitingConfirmation"] == 1 and severity["assessed"] == 0
    assert result["cards"][prefix + "FixActivity"] == [
        [0, "CVEs fully cleared"], [0, "CVEs improved, still unresolved"],
        [1, "CVEs with fixes awaiting confirmation"],
        [0, "Machines fully cleared"], [0, "Machines improved, still unresolved"],
        [1, "Machines with fixes awaiting confirmation"],
    ]
    exported = list(engine(tmp_path, data).iter_export({**request(view), "table": prefix + "MachineTable"}))
    assert exported[0]["FixesAwaitingConfirmation"] == 1


@pytest.mark.parametrize("status", ["Open", "DetectionReturned", "PendingVerification", "StaleDevice", "Unknown"])
def test_observed_fix_requires_all_machine_cve_evidence_to_clear(tmp_path, status):
    data = datasets(0)
    data["findings"] = [
        finding(0, FindingStatus="PendingConfirmation", EffectiveRemediationUtc="2026-10-24T11:00:00Z"),
        finding(1, DeviceId="device-0", CveId="CVE-2026-0000", FindingStatus=status),
    ]
    result = engine(tmp_path, data).query(request())
    sla = result["metadata"]["management"]["sla"]["periods"][0]
    assert sla["outcomes"]["AwaitingConfirmation"] == 0
    assert sla["outcomes"]["Fixed"] == 0 and sla["CompliancePercent"] is None


def test_confirmed_fix_is_attributed_to_first_absence_not_confirmation(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(0, FindingStatus="Fixed", FirstObservedUtc="2026-10-20T00:00:00Z",
                FixedUtc="2026-10-24T11:00:00Z", FixedConfirmedUtc="2026-10-24T11:00:00Z",
                EffectiveRemediationUtc="2026-10-23T11:00:00Z", SlaDueUtc="2026-10-23T12:00:00Z"),
    ]
    e = engine(tmp_path, data)
    result = e.query(request(executiveSnapshotPeriod="custom", executiveSnapshotStart="2026-10-23",
                             executiveSnapshotEnd="2026-10-23"))
    sla = result["metadata"]["management"]["sla"]["periods"][0]
    assert sla["outcomes"]["WithinSLA"] == 1
    assert sla["outcomes"]["LateSLA"] == sla["outcomes"]["AwaitingConfirmation"] == 0
    assert sla["CompliancePercent"] == 100
    machine = result["tables"]["executiveSnapshotManagementMachineTable"]["items"][0]
    assert machine["FixedCVEs"] == 1


def test_daily_collection_to_dashboard_confirmation_and_returned_detection(tmp_path):
    observed = "2026-10-22T11:00:00Z"
    first_absence = "2026-10-23T11:00:00Z"
    confirmed_at = "2026-10-24T11:00:00Z"
    previous = [
        finding(0, DeviceId="one", FirstObservedUtc=observed, SnapshotTimeUtc=observed,
                SlaDueUtc="2026-10-23T12:00:00Z", SlaPolicyVersion="retained"),
        finding(1, DeviceId="one", FirstObservedUtc=observed, SnapshotTimeUtc=observed),
    ]
    devices = [{"DeviceId": "one", "HealthStatus": "Active", "OnboardingStatus": "Onboarded",
                "LastSeenUtc": first_absence}]
    pending = reconcile_live_findings(
        [previous[1]], previous, datetime.fromisoformat(first_absence), "day-2", devices,
    )
    data = datasets(0)
    data["findings"] = pending
    result = engine(tmp_path / "pending", data, snapshot_time=first_absence).query(request())
    sla = result["metadata"]["management"]["sla"]["periods"][0]
    assert sla["outcomes"]["AwaitingConfirmation"] == 1
    assert sla["outcomes"]["Fixed"] == 0 and sla["CompliancePercent"] is None

    devices[0]["LastSeenUtc"] = confirmed_at
    confirmed = reconcile_live_findings(
        [previous[1]], pending, datetime.fromisoformat(confirmed_at), "day-3", devices,
    )
    data["findings"] = confirmed
    result = engine(tmp_path / "confirmed", data, snapshot_time=confirmed_at).query(request(
        executiveSnapshotPeriod="custom", executiveSnapshotStart="2026-10-23", executiveSnapshotEnd="2026-10-23",
    ))
    sla = result["metadata"]["management"]["sla"]["periods"][0]
    assert sla["outcomes"]["WithinSLA"] == sla["outcomes"]["Fixed"] == 1
    assert sla["outcomes"]["LateSLA"] == sla["outcomes"]["AwaitingConfirmation"] == 0

    data["findings"] = reconcile_live_findings(
        previous, pending, datetime.fromisoformat(confirmed_at), "day-3-returned", devices,
    )
    result = engine(tmp_path / "returned", data, snapshot_time=confirmed_at).query(request())
    sla = result["metadata"]["management"]["sla"]["periods"][0]
    assert sla["outcomes"]["AwaitingConfirmation"] == sla["outcomes"]["Fixed"] == 0
    assert sla["CompliancePercent"] is None
    assert next(row for row in data["findings"] if row["FindingKey"] == previous[0]["FindingKey"])["FindingStatus"] == "DetectionReturned"


def test_unqualified_or_undated_absence_never_becomes_observed_fix(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(0, FindingStatus="PendingVerification", EffectiveRemediationUtc="2026-10-24T11:00:00Z"),
        finding(1, FindingStatus="PendingConfirmation", EffectiveRemediationUtc=""),
        finding(2, FindingStatus="DetectionReturned", EffectiveRemediationUtc=""),
    ]
    sla = engine(tmp_path, data).query(request())["metadata"]["management"]["sla"]["periods"][0]
    assert sla["outcomes"]["AwaitingConfirmation"] == sla["outcomes"]["Fixed"] == 0
    assert sla["CompliancePercent"] is None


def test_summary_headlines_exclude_sla_and_snapshot_status_categories_do_not_overlap(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(0, DeviceId="within", CveId="CVE-WITHIN"),
        finding(1, DeviceId="overdue", CveId="CVE-OVERDUE", SlaDueUtc="2026-10-23T00:00:00Z"),
        finding(2, DeviceId="fixed", CveId="CVE-FIXED", FindingStatus="Fixed", FixedUtc="2026-10-24T11:00:00Z"),
        finding(3, DeviceId="late", CveId="CVE-LATE", FindingStatus="Fixed",
                FixedUtc="2026-10-24T11:00:00Z", SlaDueUtc="2026-10-23T00:00:00Z"),
        finding(4, DeviceId="unknown", CveId="CVE-UNKNOWN", SlaDueUtc=None),
        finding(5, DeviceId="unknown-fixed", CveId="CVE-UNKNOWN-FIXED",
                FindingStatus="Fixed", FixedUtc="2026-10-24T11:00:00Z", SlaDueUtc=None),
        finding(6, DeviceId="overdue", CveId="CVE-OVERDUE", SlaDueUtc=None),
        finding(7, DeviceId="pending", CveId="CVE-PENDING", FindingStatus="PendingVerification"),
    ]
    data["findings"] *= 20
    result = engine(tmp_path, data).query(request("executive"))
    assert [label for _, label in result["cards"]["executiveManagementCards"]] == [
        "Machines with open risk", "Open vulnerabilities (unique CVEs)",
    ]
    graph = result["charts"]["executiveManagementSlaSnapshot"]
    assert graph["kind"] == "entity-sla-status"
    cves = next(row for row in graph["rows"] if row["label"] == "CVEs")
    assert {key: cves[key] for key in ("openWithin", "openOverdue", "completedWithin", "completedLate", "unknownOpen", "completedUnknown")} == {
        "openWithin": 2, "openOverdue": 1, "completedWithin": 1, "completedLate": 1, "unknownOpen": 1, "completedUnknown": 1,
    }
    assert cves["totalOpen"] + cves["confirmedFixes"] == 7


def test_machine_cve_sla_unknown_deadlines_do_not_become_success(tmp_path):
    data = datasets(0)
    data["findings"] = [finding(0, FindingStatus="Fixed", FixedUtc="2026-10-24T11:00:00Z", SlaDueUtc=None)]
    result = engine(tmp_path, data).query(request())
    row = result["tables"]["executiveSnapshotManagementMachineTable"]["items"][0]
    assert row["FixedCVEs"] == row["CompletedUnknownSLA"] == 1
    assert row["SLACompliance"] == "Waiting for data"


@pytest.mark.parametrize(("due", "status", "rate"), [
    ("2026-10-25T00:00:00Z", "Within deadline", "100.0%"),
    ("2026-10-24T12:00:00Z", "Within deadline", "100.0%"),
    ("2026-10-23T00:00:00Z", "Overdue", "0.0%"),
    (None, "Unknown SLA", "Waiting for data"),
])
def test_pending_fix_has_real_open_deadline_status_until_confirmed(tmp_path, due, status, rate):
    data = datasets(0)
    data["findings"] = [
        finding(0, FindingStatus="PendingConfirmation", EffectiveRemediationUtc="2026-10-24T11:00:00Z",
                SlaDueUtc=due),
    ]
    e = engine(tmp_path, data)
    result = e.query(request())
    row = result["tables"]["executiveSnapshotManagementMachineTable"]["items"][0]
    assert row["OpenSLAWithinRate"] == rate
    detail = e.query({**request("detail"), "selection": {"type": "machine", "id": "device-0"}})
    pair = detail["tables"]["pivotSlaCveTable"]["items"][0]
    assert pair["ProgressStatus"] == "Fix observed — awaiting confirmation"
    assert pair["SlaStatus"] == status
    cards = dict((label, value) for value, label in detail["cards"]["pivotCards"])
    assert cards["CVEs with confirmed or pending fixes"] == 1
    assert cards["Confirmed CVEs on time"] == "Waiting for data"


def test_machine_cve_sla_machine_detail_and_csv_include_fixed_and_remaining(tmp_path):
    e = engine(tmp_path, machine_sla_data())
    payload = {**request("detail"), "selection": {"type": "machine", "id": "machine-x"}}
    result = e.query(payload)
    rows = result["tables"]["pivotSlaCveTable"]["items"]
    assert len(rows) == 3
    assert {row["CveId"]: row["SlaStatus"] for row in rows} == {
        "CVE-A": "Fixed within SLA", "CVE-B": "Fixed late", "CVE-C": "Within deadline",
    }
    assert all(row["DeviceName"] for row in rows)
    assert all("Finding" not in label for _, label in result["cards"]["pivotCards"])
    exported = list(e.iter_export({**payload, "table": "pivotSlaCveTable"}))
    assert len(exported) == 3 and all("SoftwareVersion" not in row for row in exported)


def test_machine_cve_sla_cache_restore_and_empty_assessment(tmp_path):
    e = engine(tmp_path, machine_sla_data())
    expected = e.query(request())
    actual = engine(tmp_path, machine_sla_data()).query(request())
    assert actual["metadata"]["management"] == expected["metadata"]["management"]
    empty = engine(tmp_path / "empty", datasets(0)).query(request())["metadata"]["management"]["sla"]["periods"][0]
    assert "ExecutiveStatus" not in empty and empty["CompliancePercent"] is None


def test_machine_cve_sla_known_completion_and_missing_identifiers_remain_explicit(tmp_path):
    data = datasets(0)
    data["findings"] = [finding(0, FindingStatus="Fixed", FixedUtc="2026-10-24T11:00:00Z")]
    e = engine(tmp_path / "green", data)
    green = e.query(request())["metadata"]["management"]["sla"]["periods"][0]
    assert green["CompliancePercent"] == 100
    data["findings"].append(finding(1, DeviceId="device-0", CveId=None))
    result = engine(tmp_path / "gap", data).query(request())
    sla = result["metadata"]["management"]["sla"]
    assert sla["coverageGap"]
    assert result["metadata"]["management"]["periods"][0]["machines"]["UnknownSla"] == 1
    row = result["tables"]["executiveSnapshotManagementMachineTable"]["items"][0]
    assert row["OpenWithinSLA"] == 0
    assert row["OpenSLAWithinRate"] == "Waiting for data"


def test_machine_cve_sla_detail_uses_executive_custom_period_and_resolution_scope(tmp_path):
    e = engine(tmp_path, machine_sla_data())
    result = e.query({
        **request("detail", managementSourceView="executiveSnapshot", executiveSnapshotPeriod="custom",
                  executiveSnapshotStart="2026-10-19", executiveSnapshotEnd="2026-10-21",
                  exposureStatus="FixedOnly", latestRunChangesOnly=True),
        "selection": {"type": "machine", "id": "machine-x"},
    })
    rows = result["tables"]["pivotSlaCveTable"]["items"]
    assert {row["CveId"]: row["ProgressStatus"] for row in rows} == {
        "CVE-A": "Confirmed fixed", "CVE-B": "Open", "CVE-C": "Open",
    }


def test_machine_cve_sla_keeps_earliest_deadline_after_partial_software_removal(tmp_path):
    data = datasets(0)
    data["findings"] = [
        finding(0, CveId="CVE-A", FindingStatus="Fixed", FixedUtc="2026-10-23T12:00:00Z",
                SlaDueUtc="2026-10-23T00:00:00Z"),
        finding(1, DeviceId="device-0", CveId="CVE-A", SlaDueUtc="2026-11-01T00:00:00Z"),
    ]
    result = engine(tmp_path, data).query(request())
    row = result["tables"]["executiveSnapshotManagementMachineTable"]["items"][0]
    assert row["FixedCVEs"] == 0 and row["ProgressStatus"] == "Still open"
    assert row["SlaStatus"] == "Overdue"
    assert result["metadata"]["management"]["periods"][0]["machines"]["Overdue"] == 1


def test_recommendation_catalog_filters_sorts_and_exports_independently_of_priority(tmp_path):
    data = datasets(0)
    data["findings"] = [finding(0, RecommendationId="rec-1"), finding(1, RecommendationId="rec-2", FindingStatus="PendingVerification")]
    e = engine(tmp_path, data)
    catalog = e.query(request("recommendations"))
    assert [row["RecommendationId"] for row in catalog["tables"]["recommendationTable"]["items"]] == ["rec-0", "rec-1", "rec-2"]
    assert "ExposureStatus" in catalog["tables"]["recommendationTable"]["columns"]
    payload = request("recommendations", recommendationCatalogStatus="No current exposure", recommendationCatalogSort="cves")
    rows = list(e.iter_export({**payload, "table": "recommendationTable"}))
    assert [row["RecommendationId"] for row in rows] == ["rec-0"]
    priority = e.query(request("priority", recommendationCatalogStatus="No current exposure"))
    assert {row["RecommendationId"] for row in priority["tables"]["priorityTable"]["items"]} == {"rec-1", "rec-2"}
    with pytest.raises(ValueError, match="Invalid recommendation catalog"):
        e.query(request("recommendations", recommendationCatalogSort="invalid"))


def test_management_machine_and_cve_severity_totals_are_independent_deduplicated_buckets(tmp_path):
    data = datasets(0)
    evidence = [
        finding(0, DeviceId="a", CveId="CVE-SHARED", Severity="Critical"),
        finding(1, DeviceId="a", CveId="CVE-H", Severity="High"),
        finding(2, DeviceId="b", CveId="CVE-H", Severity="High"),
        finding(3, DeviceId="c", CveId="CVE-M", Severity="Medium"),
        finding(4, DeviceId="d", CveId="CVE-L", Severity="Low"),
        finding(5, DeviceId="d", CveId="CVE-SHARED", Severity="Low"),
        finding(6, DeviceId="u", CveId="CVE-U", Severity="Unknown"),
    ]
    data["findings"] = [dict(row, FindingKey=f"{row['FindingKey']}-{copy}") for row in evidence for copy in range(25)]
    e = engine(tmp_path, data)
    result = e.query(request("executive"))
    severity = result["charts"]["executiveManagementSeverity"]["rows"]
    assert {row["label"]: row["machines"] for row in severity} == {
        "Critical": 1, "High": 1, "Medium": 1, "Low": 1, "Unknown": 1,
    }
    assert {row["label"]: row["cves"] for row in severity} == {
        "Critical": 1, "High": 1, "Medium": 1, "Low": 1, "Unknown": 1,
    }
    for entity, column in (("machines", "machines"), ("cves", "cves")):
        assert sum(row[column] for row in severity) == result["metadata"]["management"]["periods"][0][entity]["Open"]
    rows = list(e.iter_export({**request("executive"), "table": "executiveManagementMachineTable"}))
    assert all("ExecutiveStatus" not in row for row in rows)


def test_recommendations_priority_sort_puts_unresolved_work_first_and_ignores_duplicate_volume(tmp_path):
    data = datasets(0)
    data["recommendations"][0]["SeverityScore"] = 10
    data["findings"] = [
        finding(0, RecommendationId="rec-1", DeviceId="a", CveId="CVE-A"),
        *[finding(i + 1, RecommendationId="rec-2", DeviceId="b", CveId="CVE-B", FindingStatus="PendingVerification") for i in range(80)],
    ]
    e = engine(tmp_path, data)
    payload = request("recommendations", recommendationCatalogSort="priority")
    result = e.query(payload)
    assert [row["RecommendationId"] for row in result["tables"]["recommendationTable"]["items"]] == ["rec-1", "rec-2", "rec-0"]
    assert "RecommendationSeverity" in result["tables"]["recommendationTable"]["columns"]
    exported = list(e.iter_export({**payload, "table": "recommendationTable"}))
    assert [row["RecommendationId"] for row in exported] == ["rec-1", "rec-2", "rec-0"]
    filtered = e.query(request("recommendations", recommendationCatalogSort="priority", recommendationCatalogStatus="Unresolved exposure"))
    assert {row["RecommendationId"] for row in filtered["tables"]["recommendationTable"]["items"]} == {"rec-1", "rec-2"}
