from concurrent.futures import ThreadPoolExecutor
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vulnerability_view.dashboard_queries import DashboardQueryEngine


SNAPSHOT = "2026-10-24T12:00:00Z"


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
    assert result["cards"]["pivotCards"][1] == [185, "Active finding instances"]
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
        assert not {"devices", "vulnerabilities", "recommendation-events", "daily-summary"} & e.reads.keys()


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


def test_daily_interval_aggregation_matches_legacy_history_predicates(tmp_path):
    data = datasets(0)
    snapshot = datetime.fromisoformat(SNAPSHOT.replace("Z", "+00:00"))
    for i in range(120):
        first = snapshot - timedelta(days=120 - i, hours=i % 24)
        fixed = first + timedelta(days=i % 17) if i % 3 else None
        reopened = first + timedelta(days=i % 21) if i % 5 == 0 else None
        data["findings"].append(finding(
            i, FirstObservedUtc=first.isoformat(), FirstSeenUtc=first.isoformat(),
            FixedUtc=fixed.isoformat() if fixed else "",
            ReopenedUtc=reopened.isoformat() if reopened else "",
            PublicExploitAvailable=i % 2 == 0,
            SlaDueUtc=(first + timedelta(days=7)).isoformat(),
        ))
    points = engine(tmp_path, data).query({"view": "trend"})["charts"]["weeklyTrendChart"]["rows"]
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
    assert "devices" not in e.reads


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
