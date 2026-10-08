"""Last modified: 2026-10-08.
Purpose: Verify finding, recommendation, run-history, summary, and reconciliation behavior.
"""

from datetime import datetime, timedelta, timezone

from vulnerability_view.summary_builder import build_daily_summary, build_recommendation_events, build_reconciliation, build_run_history
from vulnerability_view.synthetic_generator import generate_synthetic


REAL_CVE_CATALOG = [{"CveId": "CVE-2025-1234", "Severity": "High", "CvssScore": 8.8}]


def test_recommendation_events_are_persistent_and_idempotent():
    first = datetime(2026, 10, 1, tzinfo=timezone.utc)
    recommendation = {
        "RecommendationId": "rec-1", "RecommendationName": "Update software",
        "DataOrigin": "Live", "ScenarioId": "LIVE", "SnapshotTimeUtc": first.isoformat(),
    }
    events = build_recommendation_events([recommendation], [], [], first, "run-1")
    events = build_recommendation_events([], [recommendation], events, first + timedelta(days=1), "run-2")
    events = build_recommendation_events([recommendation], [], events, first + timedelta(days=2), "run-3")
    repeated = build_recommendation_events([recommendation], [], events, first + timedelta(days=2), "run-3")

    assert [row["EventType"] for row in events] == ["Baseline", "Inactive", "Reopened"]
    assert repeated == events


def test_run_history_separates_entity_units():
    snapshot = datetime(2026, 10, 1, tzinfo=timezone.utc)
    finding = {
        "FindingKey": "device-1|CVE-2026-0001|software", "DeviceId": "device-1",
        "CveId": "CVE-2026-0001", "FindingStatus": "Open", "SlaStatus": "OpenOutsideSla",
    }
    event = {**finding, "EventId": "event-1", "EventType": "New", "EffectiveTimeUtc": snapshot.isoformat(), "CollectionRunId": "run-1"}
    recommendation = {"RecommendationId": "rec-1"}
    recommendation_event = {
        "EventId": "rec-event-1", "RecommendationId": "rec-1", "EventType": "New",
        "EffectiveTimeUtc": snapshot.isoformat(), "CollectionRunId": "run-1",
    }
    history = build_run_history(
        [finding], [], [event], [recommendation], [], [recommendation_event], [],
        [{"RunStatus": "Success"}], snapshot, "run-1",
    )

    assert history[0]["OpenFindings"] == 1
    assert history[0]["AffectedMachines"] == 1
    assert history[0]["ActiveCves"] == 1
    assert history[0]["ActiveRecommendations"] == 1
    assert history[0]["OpenOutsideSla"] == 1


def test_summary_and_reconciliation_are_nonnegative():
    findings = generate_synthetic(
        snapshot_time=datetime(2026, 9, 16, tzinfo=timezone.utc),
        cve_catalog=REAL_CVE_CATALOG,
    )["findings"]
    summaries = build_daily_summary(findings)
    assert summaries
    assert all(row["NewCount"] >= 0 and row["FixedCount"] >= 0 and row["RemainingCount"] >= 0 for row in summaries)
    reconciliation = build_reconciliation(findings)
    assert all(row["PreviousRemaining"] + row["New"] - row["Fixed"] + row["Reopened"] == row["CurrentRemaining"] for row in reconciliation)
    assert all(row["CurrentRemaining"] >= 0 for row in reconciliation)


def test_daily_summary_has_consecutive_dates_through_snapshot():
    snapshot = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
    findings = generate_synthetic(snapshot_time=snapshot, cve_catalog=REAL_CVE_CATALOG)["findings"]
    summaries = build_daily_summary(findings)
    summary_dates = sorted({datetime.fromisoformat(row["SummaryDate"]).date() for row in summaries})

    assert len(summary_dates) == 90
    assert summary_dates[-1] == snapshot.date()
    assert all(current - previous == timedelta(days=1) for previous, current in zip(summary_dates, summary_dates[1:]))
    assert any(row["NewCount"] > 0 for row in summaries)
    assert any(row["FixedCount"] > 0 for row in summaries)
    assert any(row["KnownExploitCount"] > 0 for row in summaries)
    assert any(row["FixedWithinSlaCount"] > 0 for row in summaries)
    assert any(row["FixedOutsideSlaCount"] > 0 for row in summaries)

    today = [row for row in summaries if row["SummaryDate"] == snapshot.date().isoformat()]
    yesterday = [row for row in summaries if row["SummaryDate"] == (snapshot.date() - timedelta(days=1)).isoformat()]
    assert sum(row["NewCount"] for row in today) > 0
    assert sum(row["FixedCount"] for row in today) > 0
    assert sum(row["NewCount"] for row in yesterday) > 0
    assert sum(row["FixedCount"] for row in yesterday) > 0

    daily_remaining = {
        summary_date: sum(row["RemainingCount"] for row in summaries if row["SummaryDate"] == summary_date)
        for summary_date in {row["SummaryDate"] for row in summaries}
    }
    assert len(set(daily_remaining.values())) > 1


def test_daily_summary_reports_lifecycle_evidence_states():
    snapshot = datetime(2026, 9, 20, tzinfo=timezone.utc)
    base = {
        "AssetClass": "TraditionalIT", "SubscriptionId": "", "OwnerTeam": "Endpoint Operations", "Severity": "High",
        "DataOrigin": "Live", "FirstSeenUtc": "", "FirstObservedUtc": "2026-09-20T00:00:00Z", "FixedUtc": "",
        "ReopenedUtc": "", "SlaDueUtc": "2026-10-20T00:00:00Z", "AssignmentStatus": "NotAssigned",
        "PublicExploitAvailable": False, "VerifiedExploitAvailable": False, "ExploitKitAvailable": False,
        "ScenarioId": "LIVE", "SnapshotTimeUtc": "2026-09-20T00:00:00Z", "CollectionRunId": "live-20260920T000000Z",
    }
    findings = [
        dict(base, FindingKey="pending", FindingStatus="PendingConfirmation"),
        dict(base, FindingKey="stale", FindingStatus="StaleDevice"),
        dict(base, FindingKey="unknown", FindingStatus="Unknown"),
        dict(base, FindingKey="out", FindingStatus="OutOfScope"),
        dict(base, FindingKey="reopened", FindingStatus="Reopened", ReopenedUtc="2026-09-20T00:00:00Z"),
    ]

    row = build_daily_summary(findings, history_days=1)[0]

    assert row["RemainingCount"] == 4
    assert row["ReopenedCount"] == 1
    assert row["PendingConfirmationCount"] == 1
    assert row["StaleDeviceCount"] == 1
    assert row["UnknownStateCount"] == 1
    assert row["OutOfScopeCount"] == 1
