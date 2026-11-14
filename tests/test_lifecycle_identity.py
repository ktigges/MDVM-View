"""Step 2 lifecycle rules: identity matching, Defender dates, inactive devices, and reopen episodes."""

from datetime import datetime, timezone

from vulnerability_view.bounded_processing import Workspace
from vulnerability_view.live_collector import delta_fixed_events, finding_match_identity, reconcile_live_findings


SNAP = datetime(2026, 11, 5, tzinfo=timezone.utc)
ACTIVE = [{"DeviceId": "d1", "HealthStatus": "Active", "OnboardingStatus": "Onboarded", "LastSeenUtc": "2026-11-05T00:00:00Z"}]


def row(key, **changes):
    base = {
        "FindingKey": key, "DeviceId": "d1", "CveId": "CVE-1", "SoftwareName": "app", "SoftwareVersion": "1",
        "DataOrigin": "Live", "FindingStatus": "Open", "Severity": "High",
        "FirstObservedUtc": "2026-11-01T00:00:00Z", "FirstSeenUtc": "2026-11-01T00:00:00Z",
        "SnapshotTimeUtc": "2026-11-01T00:00:00Z", "SlaPolicyName": "High", "SlaPolicyVersion": "v1", "SlaDays": 7,
        "SlaStartUtc": "2026-11-01T00:00:00Z", "SlaDueUtc": "2026-11-08T00:00:00Z",
        "FixedUtc": "", "ReopenedUtc": "", "FirstAbsentUtc": "", "ConsecutiveAbsentCount": 0,
    }
    base.update(changes)
    return base


def current_row(key, **changes):
    """A row detected now; FirstSeenUtc equal to FirstObservedUtc means Defender supplied no first-seen time."""
    return row(key, **{
        "FirstObservedUtc": "2026-11-05T00:00:00Z", "FirstSeenUtc": "2026-11-05T00:00:00Z",
        "SnapshotTimeUtc": "2026-11-05T00:00:00Z", **changes,
    })


def test_changed_api_id_keeps_existing_key_and_clock():
    result = reconcile_live_findings([current_row("delta-key")], [row("full-key")], SNAP, "run", ACTIVE)
    assert len(result) == 1
    assert result[0]["FindingKey"] == "full-key"
    assert result[0]["FindingStatus"] == "Open"
    assert (result[0]["SlaStartUtc"], result[0]["SlaDueUtc"]) == ("2026-11-01T00:00:00Z", "2026-11-08T00:00:00Z")


def test_legacy_key_swap_artifact_is_merged_into_original_clock():
    previous = [
        row("old", FindingStatus="Fixed", FixedUtc="2026-11-03T00:00:00Z"),
        row("new", FirstObservedUtc="2026-11-03T00:00:00Z", SlaStartUtc="2026-11-03T00:00:00Z", SlaDueUtc="2026-11-10T00:00:00Z"),
    ]
    result = reconcile_live_findings([current_row("new")], previous, SNAP, "run", ACTIVE)
    assert len(result) == 1
    assert result[0]["FindingKey"] == "new"
    assert result[0]["FindingStatus"] == "Open"
    assert result[0]["FirstObservedUtc"] == result[0]["SlaStartUtc"] == "2026-11-01T00:00:00Z"
    assert result[0]["SlaDueUtc"] == "2026-11-08T00:00:00Z"


def test_defender_first_seen_rebaselines_open_clock():
    current = [current_row("k", FirstSeenUtc="2026-10-20T00:00:00Z")]
    result = reconcile_live_findings(current, [row("k")], SNAP, "run", ACTIVE)
    assert result[0]["FirstSeenUtc"] == result[0]["SlaStartUtc"] == "2026-10-20T00:00:00Z"
    assert result[0]["SlaDueUtc"] == "2026-10-27T00:00:00Z"
    assert result[0]["SlaStatus"] == "OpenOutsideSla"


def test_defender_fixed_event_sets_fixed_date_even_for_inactive_device():
    previous = [row("k")]
    devices = [{"DeviceId": "d1", "HealthStatus": "Inactive", "OnboardingStatus": "Onboarded", "LastSeenUtc": "2026-10-01T00:00:00Z"}]
    events = {finding_match_identity(previous[0]): datetime(2026, 11, 4, 6, tzinfo=timezone.utc)}
    result = reconcile_live_findings([], previous, SNAP, "run", devices, fixed_events=events)
    assert result[0]["FindingStatus"] == "Fixed"
    assert result[0]["FixedUtc"] == "2026-11-04T06:00:00Z"
    assert result[0]["SlaStatus"] == "FixedWithinSla"


def test_absence_on_device_inactive_for_seven_days_keeps_vulnerability_open():
    devices = [{"DeviceId": "d1", "HealthStatus": "Active", "OnboardingStatus": "Onboarded", "LastSeenUtc": "2026-10-28T23:00:00Z"}]
    result = reconcile_live_findings([], [row("k")], SNAP, "run", devices)
    assert (result[0]["FindingStatus"], result[0]["FixedUtc"]) == ("Open", "")
    assert "inactive" in result[0]["LifecycleReason"]
    devices[0]["LastSeenUtc"] = "2026-10-29T01:00:00Z"
    result = reconcile_live_findings([], [row("k")], SNAP, "run", devices)
    assert (result[0]["FindingStatus"], result[0]["FixedUtc"]) == ("Fixed", "2026-11-05T00:00:00Z")


def test_return_after_fix_starts_new_episode():
    previous = [row("k", FindingStatus="Fixed", FixedUtc="2026-11-03T00:00:00Z")]
    result = reconcile_live_findings([current_row("k")], previous, SNAP, "run", ACTIVE)
    assert len(result) == 2
    fixed_row = next(item for item in result if item["FindingStatus"] == "Fixed")
    open_row = next(item for item in result if item["FindingStatus"] == "Open")
    assert (fixed_row["FindingKey"], fixed_row["FixedUtc"]) == ("k", "2026-11-03T00:00:00Z")
    assert open_row["FindingKey"] == "k#e2"
    assert open_row["SlaStartUtc"] == open_row["ReopenedUtc"] == "2026-11-05T00:00:00Z"


def test_delta_fixed_events_keep_latest_fix_per_identity():
    change = {"deviceId": "d1", "cveId": "cve-1", "softwareName": "App", "softwareVersion": "1"}
    changes = [
        {**change, "status": "Fixed", "eventTimestamp": "2026-11-02T00:00:00Z"},
        {**change, "status": "Fixed", "eventTimestamp": "2026-11-04T00:00:00Z"},
        {**change, "status": "New", "eventTimestamp": "2026-11-05T00:00:00Z"},
    ]
    assert delta_fixed_events(changes) == {finding_match_identity(row("x")): "2026-11-04T00:00:00Z"}


def test_defender_timestamps_without_offset_are_utc():
    from vulnerability_view.live_collector import _parse_defender_time

    assert _parse_defender_time("2026-11-06 21:21:15") == datetime(2026, 11, 6, 21, 21, 15, tzinfo=timezone.utc)
    assert _parse_defender_time("2026-11-08T18:51:49.897923Z") == datetime(2026, 11, 8, 18, 51, 49, 897923, tzinfo=timezone.utc)
    assert _parse_defender_time("not a time") is None


def test_disk_backed_reconcile_matches_in_memory(tmp_path):
    previous = [
        row("old", FindingStatus="Fixed", FixedUtc="2026-11-03T00:00:00Z"),
        row("new", FirstObservedUtc="2026-11-03T00:00:00Z", SlaStartUtc="2026-11-03T00:00:00Z", SlaDueUtc="2026-11-10T00:00:00Z"),
        row("k", FindingStatus="Fixed", FixedUtc="2026-11-03T00:00:00Z", DeviceId="d2"),
        row("gone", CveId="CVE-9"),
    ]
    current = [current_row("new"), current_row("k", DeviceId="d2")]
    devices = ACTIVE + [{"DeviceId": "d2", "HealthStatus": "Active", "OnboardingStatus": "Onboarded", "LastSeenUtc": "2026-11-05T00:00:00Z"}]
    expected = reconcile_live_findings(current, previous, SNAP, "run", devices)
    store = Workspace(tmp_path / "w.sqlite")
    try:
        actual = list(reconcile_live_findings(store.rows(current), store.rows(previous), SNAP, "run", devices, workspace=store))
    finally:
        store.close()
    assert actual == expected
    assert {row["FindingKey"] for row in actual} == {"new", "k", "k#e2", "gone"}
