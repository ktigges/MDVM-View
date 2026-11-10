"""Verify retained evidence-query contracts against fixed lifecycle cases."""

from vulnerability_view.dashboard_queries import DashboardQueryEngine


SNAPSHOT = "2026-10-24T00:59:46Z"


def test_evidence_queries_preserve_cve_and_sla_lifecycle_arithmetic(tmp_path):
    common = {
        "DataOrigin": "Live", "AssetClass": "TraditionalIT", "OwnerTeam": "Endpoints",
        "SubscriptionId": "", "SnapshotTimeUtc": SNAPSHOT, "LastSeenUtc": SNAPSHOT,
        "RecommendationId": "rec-1", "FirstObservedUtc": "2026-10-23T01:00:00Z",
        "CveId": "CVE-2026-1001", "Severity": "High", "CvssScore": 8.8,
        "PublicExploitAvailable": False,
        "DeviceName": "", "NullableField": None,
    }
    variants = [
        {"FindingStatus": "Open", "SlaStatus": "OpenOutsideSla", "DeviceId": "a", "DeviceName": "MÜNCHEN_100%"},
        {"FindingStatus": "Reopened", "SlaStatus": "OpenWithinSla", "DeviceId": "a"},
        {"FindingStatus": "PendingConfirmation", "SlaStatus": "FixedWithinSla",
         "EffectiveRemediationUtc": "2026-10-23T12:00:00Z", "DeviceId": "b"},
        {"FindingStatus": "PendingVerification", "SlaStatus": "FixedOutsideSla", "DeviceId": "c"},
        {"FindingStatus": "Fixed", "SlaStatus": "FixedOutsideSla",
         "FixedUtc": "2026-10-23T12:00:00Z", "DeviceId": "d"},
        {"FindingStatus": "DetectionReturned", "SlaStatus": "OpenWithinSla", "DeviceId": "e",
         "CveId": "CVE-2026-1002", "PublicExploitAvailable": True},
        {"FindingStatus": "StaleDevice", "SlaStatus": "Unknown", "DeviceId": "f",
         "CveId": "CVE-2026-1002", "PublicExploitAvailable": True},
    ]
    findings = [{**common, **row, "FindingKey": f"finding-{index}"} for index, row in enumerate(variants)]
    datasets = {
        "findings": findings,
        "recommendations": [{
            "RecommendationId": "rec-1", "RecommendationName": "Update software",
            "RemediationType": "Update", "DataOrigin": "Live",
        }],
        "collection-runs": [{"CollectionRunId": "run-a", "SnapshotTimeUtc": SNAPSHOT, "DataOrigin": "Live"}],
    }

    def rows(name):
        return iter(datasets.get(name, []))

    engine = DashboardQueryEngine(tmp_path, "parity", SNAPSHOT, rows)
    request = {
        "filters": {"exposureStatus": "All", "origin": "Both", "severity": "All",
                    "domains": ["Devices", "Cloud"], "recommendationTypes": ["Vulnerability"]},
        "page": 0, "limit": 100,
    }
    expected_cves = [
        {"CveId": "CVE-2026-1001", "Severity": "High", "CvssScore": 8.8,
         "KnownExploit": False, "OpenFindings": 2, "PendingFindings": 2,
         "FixedFindings": 1, "DetectedMachines": 1, "EvidenceRows": 5},
        {"CveId": "CVE-2026-1002", "Severity": "High", "CvssScore": 8.8,
         "KnownExploit": True, "OpenFindings": 1, "PendingFindings": 0,
         "FixedFindings": 0, "DetectedMachines": 1, "EvidenceRows": 2},
    ]
    overview = engine.query({**request, "view": "overview", "mode": "cves"})
    actual = overview["tables"]["findingsTable"]["items"]
    fields = [
        "CveId", "Severity", "CvssScore", "KnownExploit", "OpenFindings",
        "PendingFindings", "FixedFindings", "DetectedMachines", "EvidenceRows",
    ]
    assert [{field: row[field] for field in fields} for row in actual] == [
        {field: row[field] for field in fields} for row in expected_cves
    ]
    sla = engine.query({**request, "view": "sla"})
    assert sla["cards"]["slaCards"] == [
        [7, "Finding instances observed"],
        [1, "Findings confirmed fixed"],
        [2, "SLA remediations pending verification"],
        [0, "Remediation observed within policy SLA"],
        [1, "Remediation observed outside policy SLA"],
        [1, "Detected findings overdue"],
    ]
    expected_searches = {
        "%": ["finding-0"], "_": ["finding-0"], "münchen": ["finding-0"],
        "null": [], "none": [], "findingkey": [],
        "CVE-2026-1001": [f"finding-{index}" for index in range(5)],
    }
    for search, keys in expected_searches.items():
        result = engine.query({
            **request, "view": "overview", "mode": "findings",
            "filters": {**request["filters"], "search": search.lower()},
        })
        page = result["tables"]["findingsTable"]
        assert page["total"] == len(keys), search
        assert sorted(row["FindingKey"] for row in page["items"]) == keys, search
