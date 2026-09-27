import json
import gzip
from datetime import datetime, timezone

import requests

from vulnerability_view.defender_client import ENDPOINTS, DefenderClient, collection_endpoints
from vulnerability_view.live_collector import normalize_live, recommendation_requires_api_enrichment, reconcile_live_findings, replay_raw_snapshot


class Credential:
    def get_token(self, scope):
        return type("Token", (), {"token": "not-a-real-token"})()


def test_experimental_endpoints_are_disabled_by_default():
    assert {endpoint.name for endpoint in collection_endpoints()} == {
        "machine_vulnerabilities",
        "machines",
        "vulnerabilities",
        "recommendations",
    }
    assert {endpoint.name for endpoint in collection_endpoints(True)} == {endpoint.name for endpoint in ENDPOINTS}


def response(payload, url="https://example.test/page"):
    value = requests.Response()
    value.status_code = 200
    value.url = url
    value._content = json.dumps(payload).encode()
    value.headers["Content-Type"] = "application/json"
    return value


def test_pagination_archives_before_normalization(monkeypatch):
    archived = []
    progress = []
    client = DefenderClient(
        "https://example.test",
        Credential(),
        lambda name, page, content: archived.append((name, page, json.loads(content))),
        progress_callback=progress.append,
    )
    pages = iter([response({"value": [{"id": 1}], "@odata.nextLink": "https://example.test/page2"}), response({"value": [{"id": 2}]})])
    monkeypatch.setattr(client, "request", lambda url: next(pages))
    rows, status = client.collect(ENDPOINTS[1])
    assert [row["id"] for row in rows] == [1, 2]
    assert status["PageCount"] == 2
    assert [page for _, page, _ in archived] == [1, 2]
    assert any("1 rows downloaded; more data available" in message for message in progress)
    assert all("page 1" not in message for message in progress)


def test_pagination_reports_percentage_when_defender_supplies_total(monkeypatch):
    progress = []
    client = DefenderClient("https://example.test", Credential(), progress_callback=progress.append)
    pages = iter([
        response({"@odata.count": 2, "value": [{"id": 1}], "@odata.nextLink": "https://example.test/page2"}),
        response({"@odata.count": 2, "value": [{"id": 2}]}),
    ])
    monkeypatch.setattr(client, "request", lambda url: next(pages))

    client.collect(ENDPOINTS[1])

    assert any("1/2 rows (50.0%)" in message for message in progress)
    assert any("2/2 rows (100.0%)" in message for message in progress)


def test_targeted_enrichment_skips_derivable_vulnerability_recommendations():
    vulnerability = {"id": "va-_-vendor-_-product", "exposedMachinesCount": 10}
    configuration = {"id": "sca-_-scid-1", "exposedMachinesCount": 10}

    assert recommendation_requires_api_enrichment(vulnerability, "targeted") is False
    assert recommendation_requires_api_enrichment(configuration, "targeted") is True
    assert recommendation_requires_api_enrichment(vulnerability, "full") is True
    assert recommendation_requires_api_enrichment(configuration, "none") is False


def test_live_normalization_uses_collector_first_observation_for_sla():
    payloads = {
        "machine_vulnerabilities": [{"id": "finding-1", "machineId": "device-1", "cveId": "CVE-2026-0001", "productVendor": "Vendor", "productName": "Product", "productVersion": "1.0", "severity": "High"}],
        "machines": [{"id": "device-1", "computerDnsName": "live-device", "osPlatform": "Windows11", "version": "24H2", "riskScore": "High", "exposureLevel": "Medium", "lastSeen": "2026-09-16T00:00:00Z", "machineTags": []}],
        "vulnerabilities": [{"id": "CVE-2026-0001", "severity": "High", "cvssV3": 8.2, "publicExploit": True, "exploitVerified": False, "exploitInKit": False}],
        "recommendations": [],
    }
    result = normalize_live(payloads, datetime(2026, 9, 16, tzinfo=timezone.utc), "live-run")
    row = result["findings"][0]
    assert row["DataOrigin"] == "Live"
    assert row["FirstSeenUtc"] == ""
    assert row["FirstObservedUtc"] == "2026-09-16T00:00:00Z"
    assert row["SlaStartUtc"] == "2026-09-16T00:00:00Z"
    assert row["SlaPolicyVersion"] == "vulnerability-view-2026-09-21"
    assert row["SlaStatus"] == "OpenWithinSla"
    assert row["AssignedEngineer"] == ""


def test_live_normalization_extracts_subscription_and_classifies_direct_resource_metadata():
    payloads = {
        "machine_vulnerabilities": [{"id": "finding-1", "machineId": "device-1", "cveId": "CVE-2026-0001", "severity": "High"}],
        "machines": [{"id": "device-1", "computerDnsName": "azure-vm", "resourceId": "/subscriptions/subscription-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/azure-vm", "subscriptionId": "subscription-1"}],
        "vulnerabilities": [], "recommendations": [],
        "azure_subscriptions": [{"subscriptionId": "subscription-1", "displayName": "Production", "state": "Enabled", "tenantId": "tenant-1"}],
    }

    row = normalize_live(payloads, datetime(2026, 9, 17, tzinfo=timezone.utc), "live-run")["findings"][0]

    assert row["AssetClass"] == "AzureCloud"
    assert row["SubscriptionId"] == "subscription-1"
    assert row["AzureResourceId"].startswith("/subscriptions/subscription-1/")
    assert normalize_live(payloads, datetime(2026, 9, 17, tzinfo=timezone.utc), "live-run")["subscriptions"] == [{
        "SubscriptionId": "subscription-1",
        "SubscriptionName": "Production",
        "State": "Enabled",
        "TenantId": "tenant-1",
        "DataOrigin": "Live",
        "ScenarioId": "LIVE-AZURE-SUBSCRIPTION-INVENTORY",
        "SnapshotTimeUtc": "2026-09-17T00:00:00Z",
        "CollectionRunId": "live-run",
    }]


def test_live_normalization_extracts_subscription_from_vm_metadata():
    payloads = {
        "machine_vulnerabilities": [{"id": "finding-1", "machineId": "device-1", "cveId": "CVE-2026-0001", "severity": "Critical"}],
        "machines": [{"id": "device-1", "computerDnsName": "azure-vm", "vmMetadata": {"cloudProvider": "Azure", "resourceId": "/subscriptions/subscription-2/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/azure-vm", "subscriptionId": None}}],
        "vulnerabilities": [], "recommendations": [],
    }

    row = normalize_live(payloads, datetime(2026, 9, 17, tzinfo=timezone.utc), "live-run")["findings"][0]

    assert row["AssetClass"] == "AzureCloud"
    assert row["SubscriptionId"] == "subscription-2"
    assert row["AzureResourceId"].startswith("/subscriptions/subscription-2/")


def test_live_reconciliation_requires_two_fresh_absences_to_confirm_fixed():
    snapshot = datetime(2026, 9, 17, 17, 5, 9, tzinfo=timezone.utc)
    previous = normalize_live({
        "machine_vulnerabilities": [
            {"id": "fixed-key", "machineId": "device-1", "cveId": "CVE-2026-0001", "productName": "windows_11", "severity": "High"},
            {"id": "open-key", "machineId": "device-1", "cveId": "CVE-2026-0002", "productName": "openssl", "severity": "Medium"},
        ],
        "machines": [{"id": "device-1", "computerDnsName": "sample-ws11", "machineTags": []}],
        "vulnerabilities": [],
        "recommendations": [],
    }, datetime(2026, 9, 17, 14, 23, 47, tzinfo=timezone.utc), "live-20260917T142347Z")["findings"]
    current = [dict(previous[1], SnapshotTimeUtc="2026-09-17T17:05:09Z", CollectionRunId="live-20260917T170509Z")]

    devices = [{"DeviceId": "device-1", "LastSeenUtc": "2026-09-17T16:30:00Z", "HealthStatus": "Active", "OnboardingStatus": "Onboarded"}]
    first_reconciliation = reconcile_live_findings(current, previous, snapshot, "live-20260917T170509Z", devices)
    by_key = {row["FindingKey"]: row for row in first_reconciliation}

    assert by_key["fixed-key"]["FindingStatus"] == "PendingConfirmation"
    assert by_key["fixed-key"]["FirstAbsentUtc"] == "2026-09-17T17:05:09Z"
    assert by_key["fixed-key"]["ConsecutiveAbsentCount"] == 1
    assert by_key["open-key"]["FindingStatus"] == "Open"

    second_snapshot = datetime(2026, 9, 18, 17, 5, 9, tzinfo=timezone.utc)
    devices[0]["LastSeenUtc"] = "2026-09-18T16:30:00Z"
    second_reconciliation = reconcile_live_findings(current, first_reconciliation, second_snapshot, "live-20260918T170509Z", devices)
    fixed = {row["FindingKey"]: row for row in second_reconciliation}["fixed-key"]

    assert fixed["FindingStatus"] == "Fixed"
    assert fixed["FixedUtc"] == "2026-09-17T17:05:09Z"
    assert fixed["FixedConfirmedUtc"] == "2026-09-18T17:05:09Z"
    assert fixed["ConsecutiveAbsentCount"] == 2


def test_live_reconciliation_does_not_fix_stale_device():
    snapshot = datetime(2026, 9, 20, tzinfo=timezone.utc)
    previous = [{
        "FindingKey": "finding-1", "DeviceId": "device-1", "DataOrigin": "Live", "FindingStatus": "Open",
        "Severity": "High", "PublicExploitAvailable": False, "VerifiedExploitAvailable": False,
        "ExploitKitAvailable": False, "FirstSeenUtc": "2026-09-01T00:00:00Z", "FirstObservedUtc": "2026-09-10T00:00:00Z",
        "FixedUtc": "", "ReopenedUtc": "", "FirstAbsentUtc": "", "FixedConfirmedUtc": "",
        "ConsecutiveAbsentCount": 0, "SnapshotTimeUtc": "2026-09-19T00:00:00Z", "CollectionRunId": "live-20260919T000000Z",
    }]
    devices = [{"DeviceId": "device-1", "LastSeenUtc": "2026-09-10T00:00:00Z", "HealthStatus": "Inactive", "OnboardingStatus": "Onboarded"}]

    reconciled = reconcile_live_findings([], previous, snapshot, "live-20260920T000000Z", devices)

    assert reconciled[0]["FindingStatus"] == "StaleDevice"
    assert reconciled[0]["FixedUtc"] == ""
    assert reconciled[0]["ConsecutiveAbsentCount"] == 0


def test_live_reconciliation_reopens_confirmed_finding():
    snapshot = datetime(2026, 9, 20, tzinfo=timezone.utc)
    current = [{
        "FindingKey": "finding-1", "DeviceId": "device-1", "DataOrigin": "Live", "FindingStatus": "Open",
        "Severity": "High", "PublicExploitAvailable": False, "VerifiedExploitAvailable": False,
        "ExploitKitAvailable": False, "FirstSeenUtc": "2026-09-01T00:00:00Z", "FirstObservedUtc": "2026-09-10T00:00:00Z",
        "FixedUtc": "", "ReopenedUtc": "", "FirstAbsentUtc": "", "FixedConfirmedUtc": "",
        "ConsecutiveAbsentCount": 0, "SnapshotTimeUtc": "2026-09-20T00:00:00Z", "CollectionRunId": "live-20260920T000000Z",
    }]
    previous = [dict(current[0], FindingStatus="Fixed", FixedUtc="2026-09-18T00:00:00Z", FixedConfirmedUtc="2026-09-19T00:00:00Z")]

    reconciled = reconcile_live_findings(current, previous, snapshot, "live-20260920T000000Z")

    assert reconciled[0]["FindingStatus"] == "Reopened"
    assert reconciled[0]["ReopenedUtc"] == "2026-09-20T00:00:00Z"
    assert reconciled[0]["ConsecutiveAbsentCount"] == 0


def test_live_reconciliation_preserves_assigned_sla_policy_version():
    snapshot = datetime(2026, 9, 20, tzinfo=timezone.utc)
    current = [{
        "FindingKey": "finding-1", "DeviceId": "device-1", "DataOrigin": "Live", "FindingStatus": "Open",
        "Severity": "Critical", "PublicExploitAvailable": True, "VerifiedExploitAvailable": False,
        "ExploitKitAvailable": False, "FirstSeenUtc": "", "FirstObservedUtc": "2026-09-10T00:00:00Z",
        "SlaPolicyName": "CriticalKnownExploit", "SlaPolicyVersion": "vulnerability-view-2026-09-21", "SlaDays": 7,
        "SlaStartUtc": "2026-09-10T00:00:00Z", "SlaDueUtc": "2026-09-17T00:00:00Z", "SlaStatus": "OpenWithinSla",
        "FixedUtc": "", "ReopenedUtc": "", "SnapshotTimeUtc": "2026-09-20T00:00:00Z", "CollectionRunId": "current",
    }]
    previous = [dict(current[0], SlaPolicyName="LegacyCritical", SlaPolicyVersion="legacy-v1", SlaDays=30, SlaDueUtc="2026-10-10T00:00:00Z")]

    reconciled = reconcile_live_findings(current, previous, snapshot, "live-20260920T000000Z")

    assert reconciled[0]["SlaPolicyName"] == "LegacyCritical"
    assert reconciled[0]["SlaPolicyVersion"] == "legacy-v1"
    assert reconciled[0]["SlaDueUtc"] == "2026-10-10T00:00:00Z"
    assert reconciled[0]["SlaStatus"] == "OpenWithinSla"


def test_live_normalization_links_recommendation_remediation_status():
    payloads = {
        "machine_vulnerabilities": [],
        "machines": [],
        "vulnerabilities": [],
        "recommendations": [{
            "id": "recommendation-1", "recommendationName": "Update Product", "productName": "Product",
            "vendor": "Vendor", "recommendedVersion": "2.0", "severityScore": 9.0, "status": "Active",
            "remediationType": "Update", "recommendationCategory": "Software", "subCategory": "Security update",
            "relatedComponent": "Runtime", "exposedMachinesCount": 12, "totalMachineCount": 20,
            "publicExploit": True, "activeAlert": False, "hasUnpatchableCve": False,
            "exposureImpact": 0.25, "configScoreImpact": 4.0, "associatedThreats": ["Threat"],
            "weaknesses": ["CWE-1"], "tags": ["InternetFacing"],
        }],
        "remediation_tasks": [{
            "id": "task-1", "recommendationReference": "recommendation-1", "title": "Deploy update",
            "status": "Active", "priority": "High", "targetDevices": 12, "fixedDevices": 5,
            "rbacGroupNames": ["Endpoints"],
        }],
    }

    result = normalize_live(payloads, datetime(2026, 9, 17, tzinfo=timezone.utc), "live-run")

    recommendation = result["recommendations"][0]
    assert recommendation["RecommendationId"] == "recommendation-1"
    assert recommendation["ExposedMachinesCount"] == 12
    assert recommendation["RemediationTriggered"] is True
    assert recommendation["RemediationStatus"] == "Active"
    assert result["remediationActivities"][0]["RecommendationId"] == "recommendation-1"


def test_live_normalization_prefers_vulnerability_recommendation_for_product_findings():
    payloads = {
        "machine_vulnerabilities": [
            {"id": f"finding-{index}", "machineId": f"device-{index}", "cveId": "CVE-2026-20941", "productVendor": "microsoft", "productName": "windows_11", "severity": "High"}
            for index in range(4)
        ],
        "machines": [{"id": f"device-{index}", "computerDnsName": f"device-{index}", "osPlatform": "Windows11", "machineTags": []} for index in range(4)],
        "vulnerabilities": [{"id": "CVE-2026-20941", "severity": "High", "exposedMachines": 4}],
        "recommendations": [
            {"id": "va-_-microsoft-_-windows_11", "recommendationName": "Update Microsoft Windows 11", "productName": "windows_11", "remediationType": "Update"},
            {"id": "sca-_-scid-2501", "recommendationName": "Block child processes", "productName": "windows_11", "remediationType": "ConfigurationChange"},
        ],
    }

    result = normalize_live(payloads, datetime(2026, 9, 17, tzinfo=timezone.utc), "live-run")

    assert {row["RecommendationId"] for row in result["findings"]} == {"va-_-microsoft-_-windows_11"}
    assert {row["DeviceId"] for row in result["findings"]} == {"device-0", "device-1", "device-2", "device-3"}


def test_live_normalization_emits_recommendation_machine_without_cve_finding():
    payloads = {
        "machine_vulnerabilities": [],
        "machines": [{"id": "device-1", "computerDnsName": "device-1", "osPlatform": "Windows11", "exposureLevel": "High", "machineTags": []}],
        "vulnerabilities": [],
        "recommendations": [{"id": "sca-_-scid-2501", "recommendationName": "Block child processes", "productName": "windows_11"}],
        "recommendation_machines": [{"_recommendationId": "sca-_-scid-2501", "id": "device-1", "computerDnsName": "device-1", "osPlatform": "Windows11", "rbacGroupName": "Endpoints"}],
    }

    result = normalize_live(payloads, datetime(2026, 9, 17, tzinfo=timezone.utc), "live-run")

    assert result["recommendationMachines"] == [{
        "RecommendationId": "sca-_-scid-2501", "DeviceId": "device-1", "DeviceName": "device-1",
        "OSPlatform": "Windows11", "DeviceGroupName": "Endpoints", "DeviceExposureLevel": "High",
        "LastSeenUtc": "", "AssetClass": "TraditionalIT", "AzureResourceId": "", "SubscriptionId": "", "OwnerTeam": "Endpoint Operations",
        "ClassificationReason": "Onboarded device without Azure resource evidence", "DataOrigin": "Live",
        "ScenarioId": "LIVE-DEFENDER-SNAPSHOT", "SnapshotTimeUtc": "2026-09-17T00:00:00Z",
        "CollectionRunId": "live-run",
    }]


def test_live_normalization_emits_actual_secure_score():
    payloads = {
        "machine_vulnerabilities": [], "machines": [], "vulnerabilities": [], "recommendations": [],
        "secure_scores": [{
            "currentScore": 42.0, "maxScore": 60.0, "createdDateTime": "2026-09-17T00:00:00Z",
            "activeUserCount": 90, "licensedUserCount": 100, "enabledServices": ["HasIntune"],
            "averageComparativeScores": [{"basis": "AllTenants", "averageScore": 35.0}],
            "controlScores": [{"controlCategory": "Device", "score": 12.0}],
        }],
    }

    result = normalize_live(payloads, datetime(2026, 9, 17, tzinfo=timezone.utc), "live-run")

    assert result["secureScores"][0]["ScorePercent"] == 70.0
    assert result["secureScores"][0]["DeviceScore"] == 12.0
    assert result["secureScores"][0]["DataOrigin"] == "Live"


def test_live_normalization_emits_vulnerability_detail_rows():
    payloads = {
        "machine_vulnerabilities": [], "machines": [], "recommendations": [],
        "vulnerabilities": [{
            "id": "CVE-2026-0001", "name": "CVE-2026-0001", "description": "Important vulnerability",
            "severity": "High", "cvssV3": 8.4, "cvssVector": "CVSS:3.1/AV:N", "epss": 0.12,
            "exposedMachines": 3, "publishedOn": "2026-09-01T00:00:00Z", "updatedOn": "2026-09-02T00:00:00Z",
            "firstDetected": "2026-09-03T00:00:00Z", "patchFirstAvailable": "2026-09-04T00:00:00Z",
            "publicExploit": True, "exploitVerified": False, "exploitInKit": True,
            "exploitTypes": ["Remote"], "exploitUris": ["https://example.invalid"],
            "cveSupportability": "Supported", "status": "RemediationRequired", "tags": ["tag"],
        }],
    }

    row = normalize_live(payloads, datetime(2026, 9, 17, tzinfo=timezone.utc), "live-run")["vulnerabilities"][0]

    assert row["CveId"] == "CVE-2026-0001"
    assert row["Description"] == "Important vulnerability"
    assert row["CvssScore"] == 8.4
    assert row["Epss"] == 0.12
    assert row["ExploitTypes"] == "Remote"
    assert row["Status"] == "RemediationRequired"


def test_raw_snapshot_replay(tmp_path):
    run_folder = tmp_path / "live-20260916T120000Z"
    run_folder.mkdir()
    payloads = {
        "machine_vulnerabilities": [{"id": "finding-1", "machineId": "device-1", "cveId": "CVE-2026-0001", "severity": "Unknown"}],
        "machines": [{"id": "device-1", "computerDnsName": "device", "machineTags": []}],
        "vulnerabilities": [{"id": "CVE-2026-0001", "severity": "Unknown"}],
        "recommendations": [], "remediation_tasks": [], "vulnerability_changes": [],
    }
    for endpoint, rows in payloads.items():
        with gzip.open(run_folder / f"{endpoint}-page-0001.json.gz", "wt", encoding="utf-8") as handle:
            json.dump({"value": rows}, handle)
    with gzip.open(run_folder / "recommendation_machines--va-_-vendor-_-product-page-0001.json.gz", "wt", encoding="utf-8") as handle:
        json.dump({"value": [{"id": "device-1", "computerDnsName": "device", "osPlatform": "Windows11", "rbacGroupName": "Endpoints"}]}, handle)
    data, statuses = replay_raw_snapshot(run_folder)
    assert len(data["findings"]) == 1
    assert data["findings"][0]["Severity"] == "Unknown"
    assert data["recommendationMachines"][0]["RecommendationId"] == "va-_-vendor-_-product"
    assert data["recommendationMachines"][0]["DeviceId"] == "device-1"
    statuses_by_endpoint = {status["Endpoint"]: status for status in statuses}
    assert statuses_by_endpoint["secure_scores"]["Status"] == "OptionalUnavailable"
    assert statuses_by_endpoint["azure_subscriptions"]["Status"] == "OptionalUnavailable"


def test_raw_snapshot_replay_can_allow_missing_required_pages(tmp_path):
    run_folder = tmp_path / "live-20260916T120000Z"
    run_folder.mkdir()
    payloads = {
        "machine_vulnerabilities": [{"id": "finding-1", "machineId": "device-1", "cveId": "CVE-2026-0001", "severity": "High"}],
        "machines": [{"id": "device-1", "computerDnsName": "device", "machineTags": []}],
        "vulnerabilities": [{"id": "CVE-2026-0001", "severity": "High"}],
    }
    for endpoint, rows in payloads.items():
        with gzip.open(run_folder / f"{endpoint}-page-0001.json.gz", "wt", encoding="utf-8") as handle:
            json.dump({"value": rows}, handle)

    data, statuses = replay_raw_snapshot(run_folder, allow_missing_required=True)

    assert len(data["findings"]) == 1
    assert {status["Endpoint"]: status["Status"] for status in statuses}["recommendations"] == "HistoricalUnavailable"
    assert statuses[-1]["Status"] == "OptionalUnavailable"