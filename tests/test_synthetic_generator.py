from datetime import datetime, timezone

from vulnerability_view.synthetic_generator import SEVERITIES, generate_synthetic


SNAPSHOT = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
REAL_CVE_CATALOG = [
    {"CveId": "CVE-2024-0001", "Severity": "High", "CvssScore": 8.8},
    {"CveId": "CVE-2025-0002", "Severity": "Critical", "CvssScore": 9.8},
]


def test_fixed_seed_is_stable():
    first = generate_synthetic(seed=17, snapshot_time=SNAPSHOT, cve_catalog=REAL_CVE_CATALOG)
    second = generate_synthetic(seed=17, snapshot_time=SNAPSHOT, cve_catalog=REAL_CVE_CATALOG)
    assert first == second


def test_synthetic_integrity():
    data = generate_synthetic(snapshot_time=SNAPSHOT, cve_catalog=REAL_CVE_CATALOG)
    records = data["findings"]
    keys = [record["FindingKey"] for record in records]
    assert len(keys) == len(set(keys))
    assert {record["Severity"] for record in records} == set(SEVERITIES)
    assert {record["DataOrigin"] for record in records} == {"Synthetic"}
    assert all(record["DeviceName"].startswith("SAMPLE-") for record in records)
    assert any(record["FindingStatus"] == "Reopened" for record in records)
    assert {"Open", "Fixed", "Reopened", "PendingConfirmation", "StaleDevice", "OutOfScope", "Unknown"} <= {
        record["FindingStatus"] for record in records
    }
    assert any(not record["AssignedEngineer"] for record in records)
    assert any(not record["ExternalTicketId"] for record in records)
    assert {"New", "PendingConfirmation", "Fixed", "Reopened", "StaleDevice", "OutOfScope", "Unknown"} <= {
        event["EventType"] for event in data["findingEvents"]
    }


def test_remediation_progress_covers_boundaries():
    rows = generate_synthetic(snapshot_time=SNAPSHOT, cve_catalog=REAL_CVE_CATALOG)["remediationActivities"]
    assert all(0 <= row["ProgressPercent"] <= 100 for row in rows)
    assert any(row["ProgressPercent"] == 100 for row in rows)
    assert any(0 < row["ProgressPercent"] < 100 for row in rows)
    assert {"Active", "Completed", "Canceled"} <= {row["Status"] for row in rows}
    completed = [row for row in rows if row["Status"] == "Completed"]
    assert any(row["StatusLastModifiedUtc"] <= row["DueOnUtc"] for row in completed)
    assert any(row["StatusLastModifiedUtc"] > row["DueOnUtc"] for row in completed)
    assert any(row["Status"] == "Active" and not row["DueOnUtc"] for row in rows)


def test_synthetic_devices_cover_operational_states():
    rows = generate_synthetic(snapshot_time=SNAPSHOT, cve_catalog=REAL_CVE_CATALOG)["devices"]

    assert {"Active", "Inactive"} <= {row["HealthStatus"] for row in rows}
    assert {"Onboarded", "Unsupported", "CanBeOnboarded", "InsufficientInfo"} <= {
        row["OnboardingStatus"] for row in rows
    }
    assert {"TraditionalIT", "AzureCloud", "Unknown"} <= {row["AssetClass"] for row in rows}
    assert {"None", "Informational", "Medium", "High"} <= {row["DeviceRiskScore"] for row in rows}


def test_synthetic_inventory_defaults_to_2500_distinct_devices():
    data = generate_synthetic(snapshot_time=SNAPSHOT, cve_catalog=REAL_CVE_CATALOG)

    assert len(data["devices"]) == 2500
    assert len({row["DeviceId"] for row in data["findings"]}) == 2500


def test_synthetic_recommendations_include_remediation_state():
    rows = generate_synthetic(snapshot_time=SNAPSHOT, cve_catalog=REAL_CVE_CATALOG)["recommendations"]

    assert rows
    assert {row["DataOrigin"] for row in rows} == {"Synthetic"}
    assert any(row["RemediationTriggered"] for row in rows)
    assert any(not row["RemediationTriggered"] for row in rows)
    assert all(row["RecommendationName"] and row["ExposedMachinesCount"] >= 0 for row in rows)


def test_synthetic_cve_details_and_secure_score_are_explicitly_labeled():
    data = generate_synthetic(snapshot_time=SNAPSHOT, cve_catalog=REAL_CVE_CATALOG)
    vulnerabilities = data["vulnerabilities"]
    scores = data["secureScores"]

    assert vulnerabilities
    assert {row["DataOrigin"] for row in vulnerabilities} == {"Synthetic"}
    assert all("Real CVE reference" in row["Description"] for row in vulnerabilities)
    assert all("SYNTHETIC ASSOCIATION" in row["Tags"] for row in vulnerabilities)
    assert scores[0]["DataOrigin"] == "Synthetic"
    assert 0 <= scores[0]["ScorePercent"] <= 100


def test_synthetic_can_use_real_cve_references_without_claiming_real_exposure():
    catalog = [
        {"CveId": "CVE-2024-0001", "Severity": "High", "CvssScore": 8.8},
        {"CveId": "CVE-2025-0002", "Severity": "Critical", "CvssScore": 9.8},
    ]

    data = generate_synthetic(seed=17, snapshot_time=SNAPSHOT, cve_catalog=catalog)

    assert {row["CveId"] for row in data["findings"]} == {"CVE-2024-0001", "CVE-2025-0002"}
    assert all(row["DataOrigin"] == "Synthetic" for row in data["findings"])
    assert all("Real CVE reference" in row["Description"] for row in data["vulnerabilities"])
    assert all("SYNTHETIC ASSOCIATION" in row["Tags"] for row in data["vulnerabilities"])
