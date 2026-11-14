import gc
import gzip
import json
import random
import sqlite3
import subprocess
import sys
import shutil
import tracemalloc
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from vulnerability_view import bounded_summary
from vulnerability_view import live_collector
from vulnerability_view.bounded_processing import Workspace, iter_json_rows, write_json_rows
from vulnerability_view.config import Settings
from vulnerability_view.dashboard_queries import QUERY_INDEX_PAGE_BYTES
from vulnerability_view.dataprep_cli import _collection_run_rows, finalize_raw_snapshot, process_archived_run
from vulnerability_view.defender_client import ENDPOINTS
from vulnerability_view.live_collector import apply_vulnerability_delta, normalize_live, reconcile_live_findings, replay_raw_snapshot
from vulnerability_view.normalizer import iso_utc, load_sla_policy_config
from vulnerability_view.storage_writer import DATASET_FILES, archive_raw_page, archive_raw_rows, verify_run_bundle
from vulnerability_view.summary_builder import (
    build_daily_summary, build_finding_events, build_recommendation_events,
    build_reconciliation, build_run_history,
)
from test_collection_identity import TENANT, credential as tenant_credential


SNAPSHOT = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
RUN_ID = f"live-{SNAPSHOT:%Y%m%dT%H%M%SZ}"


@pytest.fixture
def work():
    path = Path(".bounded-test-work") / uuid4().hex
    path.mkdir(parents=True)
    try:
        yield path
    finally:
        shutil.rmtree(path)
        try:
            path.parent.rmdir()
        except OSError:
            pass


@pytest.fixture
def store(work):
    value = Workspace(work / "rows.sqlite")
    try:
        yield value
    finally:
        value.close()


def test_processing_workspace_matches_query_page_geometry_without_increasing_cache(store):
    assert store.connection.execute("PRAGMA page_size").fetchone()[0] == QUERY_INDEX_PAGE_BYTES
    assert store.connection.execute("PRAGMA cache_size").fetchone()[0] == -4096


def payloads(count=30):
    return {
        "machines": [{
            "id": f"device-{i}", "computerDnsName": f"host-{i}", "osPlatform": "Windows11",
            "healthStatus": "Active", "onboardingStatus": "Onboarded", "lastSeen": iso_utc(SNAPSHOT),
        } for i in range(5)],
        "recommendations": [{"id": "va-_-browser", "productName": "Browser", "recommendationName": "Upgrade"}],
        "machine_vulnerabilities": [{
            "id": f"finding-{i}", "machineId": f"device-{i % 5}",
            "cveId": f"CVE-2026-{i % 4:04d}", "productName": "Browser",
            "productVersion": "1", "severity": ("Critical", "High", "Medium", "Low")[i % 4],
        } for i in range(count)],
        "vulnerabilities": [{
            "id": f"CVE-2026-{i:04d}", "severity": "High", "cvssV3": 8,
            "firstDetected": "2000-01-01T00:00:00Z", "publicExploit": i % 2 == 0,
        } for i in range(4)],
    }


def test_streaming_parser_handles_chunk_boundaries_unicode_and_api_metadata(work):
    rows = [{"id": 1, "text": "☃" * 100000}, {"id": 2, "nested": {"a": [1, 2, None]}}]
    path = work / "raw.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump({"metadata": {"before": "value", "nested": []}, "value": rows, "@odata.nextLink": "next"}, handle, ensure_ascii=False)
    assert list(iter_json_rows(path, field="value")) == rows
    write_json_rows(work / "rows.json.gz", iter(rows))
    assert list(iter_json_rows(work / "rows.json.gz")) == rows


def test_checkpoint_compression_prioritizes_throughput_and_stays_deterministic(work, monkeypatch):
    original = gzip.GzipFile
    levels = []

    def observe(*args, **kwargs):
        levels.append(kwargs.get("compresslevel", 9))
        return original(*args, **kwargs)

    monkeypatch.setattr(gzip, "GzipFile", observe)
    rows = [{"FindingKey": "finding-1", "Description": "retained evidence"}]
    first, second = work / "first.json.gz", work / "second.json.gz"
    assert write_json_rows(first, rows) == write_json_rows(second, rows) == 1
    assert levels == [1, 1]
    assert first.read_bytes() == second.read_bytes()
    assert list(iter_json_rows(first)) == rows


@pytest.mark.parametrize("text,field", [
    ('[{}] invalid', None), ('[{},]', None), ('{"value":[{}],"next":', "value"),
    ('{"value":[]} invalid', "value"), ('{"other":1} invalid', "value"),
])
def test_streaming_parser_does_not_accept_malformed_trailing_content(work, text, field):
    path = work / "invalid.json"
    path.write_text(text)
    with pytest.raises((ValueError, json.JSONDecodeError)):
        list(iter_json_rows(path, field=field))


def test_ordered_disk_dedup_retains_first_position_and_last_value(store):
    mapping = store.mapping((("b", {"n": 1}), ("a", {"n": 2}), ("b", {"n": 3})))
    assert list(mapping.items()) == [("b", {"n": 3}), ("a", {"n": 2})]
    assert list(mapping.rows()) == [{"n": 3}, {"n": 2}]
    rows = store.rows([{"id": "b"}, {"id": "a"}, {"id": "b"}])
    assert list(rows.sorted(("id",))) == [{"id": "a"}, {"id": "b"}, {"id": "b"}]
    ordered = rows.sorted(("id",))
    plan = store.connection.execute(
        f"EXPLAIN QUERY PLAN SELECT value FROM {ordered.table} ORDER BY {ordered.order}"
    ).fetchall()
    assert not any("TEMP B-TREE" in item[3] for item in plan)


def test_disk_membership_does_not_read_or_decode_values(store, monkeypatch):
    keys = [None, False, True, 0, 1, 1.0, "1", ("x", 1), ["x", 1], {"id": "x"}]
    mapping = store.mapping((key, {"retained": index}) for index, key in enumerate(keys))
    statements = []
    store.connection.set_trace_callback(statements.append)
    with monkeypatch.context() as patch:
        patch.setattr(json, "loads", lambda *args, **kwargs: pytest.fail("Membership must not decode a value"))
        for key in keys:
            assert key in mapping
        assert "missing" not in mapping
    selects = [sql for sql in statements if sql.startswith("SELECT")]
    assert len(selects) == len(keys) + 1
    assert all(sql.startswith("SELECT 1 FROM ") for sql in selects)
    assert mapping[["x", 1]] == {"retained": 8}
    del mapping[["x", 1]]
    assert ("x", 1) not in mapping
    with pytest.raises(KeyError):
        mapping["missing"]
    with pytest.raises(TypeError):
        object() in mapping


def test_bulk_loads_use_streaming_executemany_and_bounded_transactions(work, monkeypatch):
    from vulnerability_view import bounded_processing

    calls = {"execute": 0, "executemany": 0, "commit": 0}
    connect = sqlite3.connect

    class TrackedConnection(sqlite3.Connection):
        def execute(self, *args, **kwargs):
            calls["execute"] += 1
            return super().execute(*args, **kwargs)

        def executemany(self, *args, **kwargs):
            calls["executemany"] += 1
            return super().executemany(*args, **kwargs)

        def commit(self):
            calls["commit"] += 1
            return super().commit()

    monkeypatch.setattr(bounded_processing.sqlite3, "connect", lambda path: connect(path, factory=TrackedConnection))
    path = work / "bulk.sqlite"
    workspace = Workspace(path)
    try:
        rows = workspace.rows({"id": i} for i in range(10001))
        mapping = workspace.mapping((str(i), {"id": i}) for i in range(10001))
        assert calls["executemany"] == 2
        assert calls["execute"] < 20
        assert calls["commit"] == 2
        assert workspace.writes == 20002
        assert len(rows) == len(mapping) == 10001
        assert rows[-1] == mapping["10000"] == {"id": 10000}
        with connect(path) as reader:
            assert reader.execute(f"SELECT count(*) FROM {rows.table}").fetchone()[0] == 10001
            assert reader.execute(f"SELECT count(*) FROM {mapping.table}").fetchone()[0] == 9999
    finally:
        workspace.close()
    assert calls["commit"] == 3
    with connect(path) as reader:
        assert reader.execute(f"SELECT count(*) FROM {mapping.table}").fetchone()[0] == 10001


def test_bulk_generators_see_each_prior_write_in_the_same_transaction(store):
    rows = store.rows()

    def row_source():
        for index in range(12):
            assert len(rows) == index
            if index:
                assert rows[-1] == {"id": index - 1}
            yield {"id": index}

    rows.extend(row_source())

    def pair_source():
        table = f"rows_{store.counter}"
        for index in range(12):
            assert store.connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == index
            yield str(index), index

    mapping = store.mapping(pair_source())
    assert list(rows) == [{"id": i} for i in range(12)]
    assert list(mapping.items()) == [(str(i), i) for i in range(12)]


def test_bulk_map_preserves_duplicate_order_and_last_value_across_commits(store):
    pairs = [(str(i), {"id": i}) for i in range(10001)]
    pairs.extend([("2", {"id": "updated"}), ("new", {"id": "new"}), ("0", None)])
    mapping = store.mapping(iter(pairs))
    expected = dict(pairs)
    assert list(mapping.items()) == list(expected.items())
    assert "0" in mapping and mapping["0"] is None
    mapping["2"] = {"id": "single-write"}
    assert mapping["2"] == {"id": "single-write"}
    assert list(mapping)[:3] == ["0", "1", "2"]


def test_bulk_sql_failure_preserves_successful_prefix_and_propagates(store):
    rows = store.rows()
    store.connection.execute(
        f"CREATE TRIGGER reject_bad BEFORE INSERT ON {rows.table} "
        "WHEN json_extract(NEW.value, '$.id') = 'bad' "
        "BEGIN SELECT RAISE(ABORT, 'rejected test row'); END"
    )
    consumed = []

    def source():
        for key in ("first", "bad", "last"):
            consumed.append(key)
            yield {"id": key}

    before = store.writes
    with pytest.raises(sqlite3.IntegrityError, match="rejected test row"):
        rows.extend(source())
    assert consumed == ["first", "bad"]
    assert list(rows) == [{"id": "first"}]
    assert store.writes == before + 1
    rows.append({"id": "recovered"})
    assert list(rows) == [{"id": "first"}, {"id": "recovered"}]


def test_bulk_serialization_failure_keeps_successful_prefix(store):
    rows = store.rows()
    before = store.writes
    with pytest.raises(TypeError):
        rows.extend([{"id": 1}, {"unsupported": object()}, {"id": 3}])
    assert list(rows) == [{"id": 1}]
    assert store.writes == before + 1


def test_disk_sort_copies_rows_in_sql_without_python_replay(store, monkeypatch):
    from vulnerability_view.bounded_processing import DiskRows

    source = store.rows([{"id": "b", "n": 1}, {"id": "a", "n": 2}, {"id": "b", "n": 3}])
    source.reverse()
    with monkeypatch.context() as patch:
        patch.setattr(DiskRows, "__iter__", lambda self: pytest.fail("Sort must not decode and re-encode every row"))
        sorted_rows = source.sorted(("id",))
    source.append({"id": "a", "n": 4})
    assert list(sorted_rows) == [{"id": "a", "n": 2}, {"id": "b", "n": 3}, {"id": "b", "n": 1}]


def test_daily_summaries_do_not_rescan_event_rows_for_every_day(store):
    data = normalize_live(payloads(1), SNAPSHOT, RUN_ID)
    findings = data["findings"]
    first = iso_utc(SNAPSHOT - timedelta(days=89))
    findings[0].update(FirstSeenUtc=first, FirstObservedUtc=first)
    events = [{
        "EventId": f"event-{i}", "FindingKey": findings[0]["FindingKey"],
        "EventType": "New", "EffectiveTimeUtc": iso_utc(SNAPSHOT - timedelta(days=i % 90)),
        **{key: findings[0][key] for key in ("AssetClass", "SubscriptionId", "OwnerTeam", "Severity", "DataOrigin")},
    } for i in range(900)]
    queries = []
    store.connection.set_trace_callback(queries.append)
    daily, _ = bounded_summary.summaries(findings, events, store)
    rows = list(daily)
    assert len(rows) == 90
    assert all(row["NewCount"] == 10 for row in rows)
    event_scans = [sql for sql in queries if "FROM events_" in sql]
    assert len(event_scans) == 1, "Event history must be reduced once, not once per day"
    plan = store.connection.execute("EXPLAIN QUERY PLAN " + event_scans[0]).fetchall()
    assert not any("TEMP B-TREE" in row[3] for row in plan)


def test_bounded_normalization_matches_every_legacy_dataset(store):
    sources = payloads()
    sources["machine_vulnerabilities"].append({**sources["machine_vulnerabilities"][0], "severity": "Medium"})
    expected = normalize_live(deepcopy(sources), SNAPSHOT, RUN_ID)
    actual = normalize_live(deepcopy(sources), SNAPSHOT, RUN_ID, workspace=store)
    assert {key: list(rows) for key, rows in actual.items()} == expected


def lifecycle_fixture():
    data = normalize_live(payloads(40), SNAPSHOT, RUN_ID)
    previous = deepcopy(data["findings"])
    previous_time = iso_utc(SNAPSHOT - timedelta(days=40))
    statuses = ("Open", "PendingConfirmation", "PendingVerification", "Fixed", "Reopened", "StaleDevice", "OutOfScope", "Unknown")
    for i, row in enumerate(previous):
        row.update({
            "SnapshotTimeUtc": previous_time, "CollectionRunId": "prior",
            "FirstObservedUtc": iso_utc(SNAPSHOT - timedelta(days=40 - i)),
            "FindingStatus": statuses[i % len(statuses)], "ConsecutiveAbsentCount": i % 3,
            "FixedUtc": iso_utc(SNAPSHOT - timedelta(days=4)) if i % 4 == 0 else "",
            "ReopenedUtc": iso_utc(SNAPSHOT - timedelta(days=2)) if i % 8 == 0 else "",
            "SlaPolicyVersion": "frozen-policy", "SlaDueUtc": iso_utc(SNAPSHOT - timedelta(days=i % 8)),
        })
    # A duplicate key on a different device checks global, not partition-local,
    # last-value-wins semantics and original insertion ordering.
    previous.append({**previous[5], "DeviceId": "device-3", "LifecycleReason": "last duplicate wins"})
    data["findings"] = [row for i, row in enumerate(data["findings"]) if i % 3 == 0]
    data["findings"].append({**data["findings"][0], "DeviceId": "device-4", "Severity": "Low"})
    data["devices"][1]["OnboardingStatus"] = "Offboarded"
    data["devices"][2]["LastSeenUtc"] = iso_utc(SNAPSHOT - timedelta(days=5))
    data["devices"] = data["devices"][:4]
    return data, previous


def test_lifecycle_events_summaries_and_history_are_exactly_equivalent(store):
    data, previous = lifecycle_fixture()
    expected = reconcile_live_findings(data["findings"], previous, SNAPSHOT, RUN_ID, data["devices"])
    actual = reconcile_live_findings(
        store.rows(data["findings"]), store.rows(previous), SNAPSHOT, RUN_ID, store.rows(data["devices"]), workspace=store,
    )
    assert list(actual) == expected
    old_event = build_finding_events(previous, [], [], SNAPSHOT - timedelta(days=40), "prior")[0]
    existing = [old_event, {**old_event, "Severity": "Low"}]
    events = bounded_summary.finding_events(actual, previous, existing, SNAPSHOT, RUN_ID, store)
    expected_events = build_finding_events(expected, previous, existing, SNAPSHOT, RUN_ID)
    assert list(events) == expected_events
    daily, reconciliation = bounded_summary.summaries(actual, events, store)
    assert list(daily) == build_daily_summary(expected, events=expected_events)
    assert list(reconciliation) == build_reconciliation(expected)
    recs = data["recommendations"]
    rec_events = bounded_summary.recommendation_events(recs, [], [], SNAPSHOT, RUN_ID, store)
    expected_recs = build_recommendation_events(recs, [], [], SNAPSHOT, RUN_ID)
    assert list(rec_events) == expected_recs
    expected_history = build_run_history(expected, previous, expected_events, recs, [], expected_recs, [], [], SNAPSHOT, RUN_ID)
    assert list(bounded_summary.run_history(actual, previous, events, recs, [], rec_events, [], [], SNAPSHOT, RUN_ID, store)) == expected_history


def test_bounded_finding_events_preserve_existing_observed_os_on_retry(store):
    row = {"FindingKey": "os-event", "FindingStatus": "Open", "OSPlatform": "Windows10", "OSVersion": "22H2"}
    existing = build_finding_events([row], [], [], SNAPSHOT, RUN_ID)
    repeated = bounded_summary.finding_events(
        [{**row, "OSPlatform": "Windows11", "OSVersion": "24H2"}], [], existing,
        SNAPSHOT, RUN_ID, store,
    )
    assert list(repeated) == existing


@pytest.mark.parametrize("has_history", [False, True])
def test_recommendation_global_history_idempotency_and_order(store, has_history):
    current = [{"RecommendationId": key} for key in ("c", "a", "b", "a")]
    previous = [{"RecommendationId": key} for key in ("a", "removed")]
    existing = [
        {"EventId": "z", "RecommendationId": "a", "EffectiveTimeUtc": "2026-01-01", "LifecycleStatus": "Active"},
        {"EventId": "a", "RecommendationId": "b", "EffectiveTimeUtc": "2026-01-01", "LifecycleStatus": "Inactive"},
        {"EventId": "b", "RecommendationId": "c", "EffectiveTimeUtc": "2026-01-01", "CollectionRunId": RUN_ID},
    ] if has_history else []
    assert list(bounded_summary.recommendation_events(current, previous, existing, SNAPSHOT, RUN_ID, store)) == build_recommendation_events(current, previous, existing, SNAPSHOT, RUN_ID)


@pytest.mark.parametrize("seed", range(4))
def test_summary_equivalence_including_fallback_events_medians_and_multiple_scopes(store, seed):
    rng = random.Random(seed)
    findings = normalize_live(payloads(60), SNAPSHOT, RUN_ID)["findings"]
    for row in findings:
        row.update({
            "FirstObservedUtc": iso_utc(SNAPSHOT - timedelta(days=rng.randrange(140))),
            "FixedUtc": iso_utc(SNAPSHOT - timedelta(days=rng.randrange(140))) if rng.randrange(2) else "",
            "ReopenedUtc": iso_utc(SNAPSHOT - timedelta(days=rng.randrange(100))) if rng.randrange(3) == 0 else "",
            "EffectiveRemediationUtc": iso_utc(SNAPSHOT - timedelta(days=4)) if rng.randrange(3) == 0 else "",
            "FindingStatus": rng.choice(("Open", "Fixed", "OutOfScope", "PendingVerification", "StaleDevice")),
            "AssignmentStatus": rng.choice(("Assigned", "InProgress", "WaitingForDefender", "ConfirmedFixed")),
            "SubscriptionId": rng.choice(("", "sub-1")), "OwnerTeam": rng.choice(("Å-team", "Operations")),
            "SlaDueUtc": iso_utc(SNAPSHOT - timedelta(days=rng.randrange(10))) if rng.randrange(2) else "",
        })
    events = build_finding_events(findings[:30], [], [], SNAPSHOT, RUN_ID)
    for row in events[::3]:
        row["EffectiveTimeUtc"] = ""
    daily, reconciliation = bounded_summary.summaries(store.rows(findings), store.rows(events), store)
    assert list(daily) == build_daily_summary(findings, events=events)
    assert list(reconciliation) == build_reconciliation(findings)


@pytest.mark.parametrize("derived", [False, True])
def test_streaming_replay_preserves_full_and_reconstructed_delta_order(work, store, derived):
    raw = work / RUN_ID
    raw.mkdir()
    sources = payloads()
    for endpoint in ENDPOINTS:
        name = f"derived_{endpoint.name}" if derived and endpoint.name in {"machine_vulnerabilities", "vulnerabilities"} else endpoint.name
        with gzip.open(raw / f"{name}-page-0001.json.gz", "wt", encoding="utf-8") as handle:
            json.dump({"value": sources.get(endpoint.name, [])}, handle)
    expected, statuses = replay_raw_snapshot(raw)
    actual, actual_statuses = replay_raw_snapshot(raw, workspace=store)
    assert {key: list(rows) for key, rows in actual.items()} == expected
    assert actual_statuses == statuses


def test_disk_backed_delta_preserves_timestamp_fixed_first_and_reinsertion_order(store):
    previous = normalize_live(payloads(12), SNAPSHOT, RUN_ID)["findings"]
    changes = [
        {"machineId": "device-0", "cveId": "CVE-2026-0000", "softwareName": "Browser", "softwareVersion": "1", "status": status, "eventTimestamp": timestamp}
        for status, timestamp in (("new", "2"), ("fixed", "2"), ("updated", "1"), ("fixed", "0"))
    ]
    changes += [{"machineId": "new", "cveId": "CVE-2026-OTHER", "status": "new", "eventTimestamp": "1"}]
    assert list(apply_vulnerability_delta(store.rows(previous), store.rows(changes), workspace=store)) == apply_vulnerability_delta(previous, changes)


def test_referenced_cve_batch_size_is_configurable_and_url_bounded(work):
    import re

    raw = work / RUN_ID
    archive_raw_rows("machine_vulnerabilities", ({"cveId": f"CVE-2026-{i:06d}"} for i in range(121)), RUN_ID, work)
    calls = []

    class Client:
        def collect(self, endpoint, query, **kwargs):
            calls.append(query["$filter"])
            rows = [{"id": value} for value in re.findall("id eq '([^']+)'", query["$filter"])]
            return rows, {"PageCount": 1}

    endpoint = next(endpoint for endpoint in ENDPOINTS if endpoint.name == "vulnerabilities")
    _, status = live_collector._collect_referenced_catalog(Client(), endpoint, raw, cve_batch_size=100)
    assert [call.count("id eq") for call in calls] == [100, 21]
    assert all(len(call) < 7000 for call in calls)
    assert status["RequestedCveCount"] == status["RowCount"] == 121


def test_raw_only_freezes_snapshot_and_retains_derived_relationships_without_normalizing(work, store, monkeypatch):
    import re

    sources = payloads()
    root = work / "raw"
    captured = []

    class Client:
        def collect(self, endpoint, query=None, **kwargs):
            rows = sources.get(endpoint.name, [])
            if endpoint.name == "vulnerabilities":
                requested = re.findall("id eq '([^']+)'", query["$filter"])
                rows = [row for row in rows if row["id"] in requested]
            archive_raw_rows(endpoint.name, rows, RUN_ID, root)
            return rows, {"Endpoint": endpoint.name, "Status": "Success", "RowCount": len(rows), "PageCount": 1}

        def collect_machine_vulnerabilities(self, machines):
            rows = sources["machine_vulnerabilities"]
            archive_raw_rows("machine_vulnerabilities", rows, RUN_ID, root)
            return [], {"Endpoint": "machine_vulnerabilities", "Status": "Success", "RowCount": len(rows), "PageCount": 1}

    def create_client(base_url, run_id, *args, **kwargs):
        captured.append(run_id)
        return Client()

    def optional(name):
        def collect(credential, archive, *args):
            content = b'{"value":[]}'
            archive(1, content) if name == "azure_subscriptions" else archive(content)
            return [], {"Endpoint": name, "Status": "Success", "RowCount": 0, "PageCount": 1, "DurationSeconds": 0}
        return collect

    monkeypatch.setattr(live_collector, "create_client", create_client)
    monkeypatch.setattr(live_collector, "Path", lambda value: root if str(value) == "output/raw" else Path(value))
    monkeypatch.setattr(live_collector, "archive_raw_page", lambda name, page, content, run_id: archive_raw_page(name, page, content, run_id, root))
    monkeypatch.setattr(live_collector, "archive_raw_rows", lambda name, rows, run_id: archive_raw_rows(name, rows, run_id, root))
    monkeypatch.setattr(live_collector, "collect_secure_scores", optional("secure_scores"))
    monkeypatch.setattr(live_collector, "collect_azure_subscriptions", optional("azure_subscriptions"))
    monkeypatch.setattr(live_collector, "normalize_live", lambda *args, **kwargs: pytest.fail("raw_only must not normalize"))
    data, statuses = live_collector.collect_live(
        "https://example.invalid", credential=tenant_credential(TENANT), snapshot=SNAPSHOT, raw_only=True,
        recommendation_enrichment_mode="none", cve_batch_size=100,
    )
    assert data == {}
    assert captured == [RUN_ID]
    relationships = list(iter_json_rows(root / RUN_ID / "derived_recommendation_machines-page-0001.json.gz", field="value"))
    assert [row["id"] for row in relationships] == [f"device-{i}" for i in range(5)]
    assert all(row["_recommendationId"] == "va-_-browser" for row in relationships)
    assert not list((root / RUN_ID).glob("*.sqlite"))


def test_processing_api_uses_frozen_policy_clock_and_explicit_paths(work):
    raw = work / "raw" / RUN_ID
    raw.mkdir(parents=True)
    sources = payloads()
    for endpoint in ENDPOINTS:
        with gzip.open(raw / f"{endpoint.name}-page-0001.json.gz", "wt", encoding="utf-8") as handle:
            json.dump({"value": sources.get(endpoint.name, [])}, handle)
    policy_path = work / "sla-policies.json"
    policy = load_sla_policy_config(Path("config/sla-policies.json"))
    policy["policyVersion"] = "frozen-test-version"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    before = Path.cwd()
    bundle = process_archived_run(raw, Settings(), {}, policy_path, work / "processing", snapshot=SNAPSHOT, run_id=RUN_ID)
    assert Path.cwd() == before
    assert verify_run_bundle(bundle, raw) == []
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["snapshotTimeUtc"] == iso_utc(SNAPSHOT)
    assert manifest["slaPolicyVersion"] == "frozen-test-version"
    findings = list(iter_json_rows(bundle / "curated/findings.json.gz"))
    assert {row["SlaPolicyVersion"] for row in findings} == {"frozen-test-version"}
    collection = list(iter_json_rows(bundle / "curated/collection-runs.json.gz"))
    assert {row["RunTimeUtc"] for row in collection} == {SNAPSHOT.isoformat()}
    assert {row["dataset"] for row in manifest["files"] if row["kind"] == "curated"} == set(DATASET_FILES)
    assert not list((work / "processing").glob("*.sqlite"))


def test_processing_persists_first_absence_clearance_for_fully_patched_machine(work):
    raw = work / "raw" / RUN_ID
    for endpoint in ENDPOINTS:
        archive_raw_rows(endpoint.name, payloads(0).get(endpoint.name, []), RUN_ID, raw.parent)
    previous_time = SNAPSHOT - timedelta(days=1)
    previous = normalize_live(payloads(1), previous_time, "previous")["findings"]
    policy_path = work / "sla-policies.json"
    policy_path.write_bytes(Path("config/sla-policies.json").read_bytes())
    bundle = process_archived_run(
        raw, Settings(), {"findings": previous}, policy_path, work / "prepared",
        snapshot=SNAPSHOT, run_id=RUN_ID,
    )
    rows = list(iter_json_rows(bundle / "curated/findings.json.gz"))
    assert len(rows) == 1
    assert rows[0]["FindingStatus"] == "Fixed"
    assert rows[0]["FixedUtc"] == rows[0]["FixedConfirmedUtc"] == iso_utc(SNAPSHOT)
    assert rows[0]["ConfirmationRunsRequired"] == rows[0]["ConfirmationRunsCompleted"] == 1
    events = list(iter_json_rows(bundle / "curated/finding-events.json.gz"))
    assert [row["EventType"] for row in events if row["CollectionRunId"] == RUN_ID] == ["Fixed"]
    assert verify_run_bundle(bundle, raw) == []


def test_finalized_bundle_matches_legacy_pipeline_with_frozen_baseline(work):
    raw = work / "raw" / RUN_ID
    raw.mkdir(parents=True)
    for endpoint in ENDPOINTS:
        archive_raw_rows(endpoint.name, payloads(15).get(endpoint.name, []), RUN_ID, raw.parent)
    policy_path = work / "sla-policies.json"
    policy_path.write_bytes(Path("config/sla-policies.json").read_bytes())
    _, previous = lifecycle_fixture()
    prior_time = SNAPSHOT - timedelta(days=40)
    prior_events = build_finding_events(previous, [], [], prior_time, "prior")
    prior_recs = [{"RecommendationId": "va-_-old", "SnapshotTimeUtc": iso_utc(prior_time), "DataOrigin": "Live"}]
    prior_rec_events = build_recommendation_events(prior_recs, [], [], prior_time, "prior")
    baseline = {"findings": previous, "findingEvents": prior_events, "recommendations": prior_recs, "recommendationEvents": prior_rec_events}
    paths = {}
    for key, rows in baseline.items():
        paths[key] = work / f"{key}.json.gz"
        write_json_rows(paths[key], rows)
    expected, statuses = replay_raw_snapshot(raw)
    expected["findings"] = reconcile_live_findings(expected["findings"], previous, SNAPSHOT, RUN_ID, expected["devices"])
    expected["findingEvents"] = build_finding_events(expected["findings"], previous, prior_events, SNAPSHOT, RUN_ID)
    expected["dailySummary"] = build_daily_summary(expected["findings"], events=expected["findingEvents"])
    expected["reconciliation"] = build_reconciliation(expected["findings"])
    expected["collectionRuns"] = _collection_run_rows(expected, statuses, SNAPSHOT, RUN_ID, clock=SNAPSHOT)
    expected["recommendationEvents"] = build_recommendation_events(expected["recommendations"], prior_recs, prior_rec_events, SNAPSHOT, RUN_ID)
    expected["runHistory"] = build_run_history(expected["findings"], previous, expected["findingEvents"], expected["recommendations"], prior_recs, expected["recommendationEvents"], [], expected["collectionRuns"], SNAPSHOT, RUN_ID)
    bundle = process_archived_run(raw, Settings(), paths, policy_path, work / "prepared", snapshot=SNAPSHOT, run_id=RUN_ID)
    for key, basename in DATASET_FILES.items():
        assert list(iter_json_rows(bundle / "curated" / f"{basename}.json.gz")) == expected.get(key, [])
    first_manifest = json.loads((bundle / "manifest.json").read_text())
    bundle = process_archived_run(raw, Settings(), paths, policy_path, work / "prepared", snapshot=SNAPSHOT, run_id=RUN_ID)
    assert json.loads((bundle / "manifest.json").read_text()) == first_manifest


def test_frozen_manifest_baseline_requires_matching_content(work):
    manifest = {"complete": True, "sourceTenantId": TENANT, "files": [{
        "kind": "curated", "dataset": "findings", "path": "curated/old/findings.json.gz",
        "sha256": "not-the-file-hash", "sizeBytes": 1,
    }]}
    with pytest.raises(ValueError, match="integrity mismatch"):
        finalize_raw_snapshot(
            work / RUN_ID, Settings(), snapshot=SNAPSHOT, run_id=RUN_ID,
            previous_manifest=manifest, sla_policy=[], work_directory=work / "processing",
            previous_bundle_folder=work / "baseline",
            endpoint_statuses=[{"SourceTenantId": TENANT}],
        )


@pytest.mark.performance
def test_streaming_publication_memory_is_independent_of_total_rows(work):
    def measure(count):
        gc.collect()
        tracemalloc.start()
        path = work / f"rows-{count}.json.gz"
        written = write_json_rows(path, ({"FindingKey": f"key-{i}", "Description": "x" * 2000} for i in range(count)))
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert written == count
        assert sum(1 for _ in iter_json_rows(path)) == count
        return peak

    small, large = measure(2000), measure(100000)
    print(f"publication Python peak: 2,000={small:,} bytes; 100,000={large:,} bytes")
    assert large < small + 1_000_000
    assert large < 4_000_000


@pytest.mark.performance
def test_large_normalization_and_reconciliation_keep_python_working_set_bounded(work):
    def measure(count):
        source = payloads(0)
        source["machine_vulnerabilities"] = (
            {"id": f"finding-{i}", "machineId": "device-0", "cveId": "CVE-2026-0000", "severity": "High"}
            for i in range(count)
        )
        store = Workspace(work / f"normalization-{count}.sqlite")
        source["machine_vulnerabilities"] = store.rows(source["machine_vulnerabilities"])
        gc.collect()
        tracemalloc.start()
        try:
            data = normalize_live(source, SNAPSHOT, RUN_ID, workspace=store)
            reconciled = reconcile_live_findings(data["findings"], (), SNAPSHOT, RUN_ID, data["devices"], workspace=store)
            assert len(reconciled) == count
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
            store.close()
        return peak

    small, large = measure(1000), measure(100000)
    print(f"normalization/reconciliation Python peak: 1,000={small:,}; 100,000={large:,} bytes")
    assert large < small + 1_000_000
    assert large < 4_000_000


@pytest.mark.performance
def test_full_finalization_native_rss_is_bounded_with_large_raw_and_event_history(work):
    code = r"""
import json, resource, sys
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, str(Path("src").resolve()))
from vulnerability_view.config import Settings
from vulnerability_view.dataprep_cli import process_archived_run
from vulnerability_view.defender_client import ENDPOINTS
from vulnerability_view.storage_writer import archive_raw_rows
from vulnerability_view.bounded_processing import write_json_rows
count, root = int(sys.argv[1]), Path(sys.argv[2])
snapshot = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
run_id = "live-20261020T120000Z"
raw = root / "raw" / run_id
sources = {
    "machines": [{"id":"device","healthStatus":"Active","lastSeen":"2026-10-20T12:00:00Z"}],
    "vulnerabilities": [{"id":"CVE-2026-0001","severity":"High"}],
}
for endpoint in ENDPOINTS:
    rows = ({"id":f"finding-{i}","machineId":"device","cveId":"CVE-2026-0001","severity":"High"} for i in range(count)) if endpoint.name == "machine_vulnerabilities" else sources.get(endpoint.name, [])
    archive_raw_rows(endpoint.name, rows, run_id, raw.parent)
history_path = root / "history.json.gz"
write_json_rows(history_path, ({
    "EventId": f"old-{i}", "FindingKey": f"finding-{i}", "EffectiveTimeUtc":"2026-10-19T12:00:00Z",
    "EventTimeUtc":"2026-10-19T12:00:00Z","EventType":"New","CollectionRunId":"prior",
    "AssetClass":"TraditionalIT","SubscriptionId":"","OwnerTeam":"Server Operations",
    "Severity":"High","DataOrigin":"Live"
} for i in range(count)))
bundle = process_archived_run(raw, Settings(), {"findingEvents":history_path}, Path("config/sla-policies.json"), root / "work", snapshot=snapshot, run_id=run_id)
manifest = json.loads((bundle / "manifest.json").read_text())
counts = {row["dataset"]:row["rowCount"] for row in manifest["files"] if row["kind"] == "curated"}
rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(json.dumps({"rss":rss if sys.platform == "darwin" else rss*1024,"counts":counts}))
"""

    def measure(count):
        result = subprocess.run(
            [sys.executable, "-c", code, str(count), str(work / str(count))],
            check=True, capture_output=True, text=True, timeout=180,
        )
        report = json.loads(result.stdout)
        assert report["counts"]["findings"] == count
        assert report["counts"]["findingEvents"] == count * 2
        return report["rss"]

    small, large = measure(1000), measure(100000)
    print(f"full finalization native peak RSS: 1,000={small:,}; 100,000={large:,} bytes")
    assert large < small + 24 * 1024 * 1024
