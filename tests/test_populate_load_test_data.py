import json
import sqlite3
import threading
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, create_autospec

import pytest
from azure.core.exceptions import ResourceExistsError, ResourceModifiedError

from tools import populate_load_test_data as tool
from vulnerability_view.bounded_processing import iter_json_rows as raw_rows
from vulnerability_view.dashboard_preparation import initial_filters
from vulnerability_view.dashboard_queries import DashboardQueryEngine, PREPARED_VIEWS
from vulnerability_view.dataset_io import iter_json_rows
from vulnerability_view.storage_writer import create_run_bundle, verify_run_bundle


SOURCE_TIME = tool.utc("2026-11-01T00:00:00Z")
TARGET_TIME = tool.utc("2026-10-24T00:59:46Z")
SOURCE_RUN = "live-20261101T000000Z"
OLDER_RUN = "live-20261022T000000Z"


def iso(value):
    return value.isoformat().replace("+00:00", "Z")


@pytest.fixture
def seed(tmp_path):
    rows = []
    events = []
    for index, status in enumerate(("Open", "Fixed", "Reopened", "PendingVerification")):
        row = {
            "FindingKey": f"finding-{index}", "DeviceId": f"device-{index // 2}",
            "DeviceName": f"host-{index // 2}", "RecommendationId": f"rec-{index % 2}",
            "RecommendationName": "Update example software", "SoftwareName": "Example", "SoftwareVersion": "1.0",
            "CveId": f"CVE-2026-{index:04d}", "Severity": "High", "CvssScore": 8.8,
            "AssetClass": "TraditionalIT", "OwnerTeam": "Endpoints", "DataOrigin": "Live",
            "ScenarioId": "", "SnapshotTimeUtc": iso(SOURCE_TIME), "CollectionRunId": SOURCE_RUN,
            "FirstObservedUtc": iso(SOURCE_TIME - timedelta(days=10)),
            "FirstSeenUtc": iso(SOURCE_TIME - timedelta(days=10)),
            "LastSeenUtc": iso(SOURCE_TIME), "LastObservedUtc": iso(SOURCE_TIME),
            "FindingStatus": status,
            "FixedUtc": iso(SOURCE_TIME - timedelta(days=3)) if status in {"Fixed", "Reopened"} else "",
            "ReopenedUtc": iso(SOURCE_TIME - timedelta(days=1)) if status == "Reopened" else "",
            "SlaDueUtc": iso(SOURCE_TIME + timedelta(days=20)),
            "SlaStatus": "FixedWithinSla" if status == "Fixed" else "OpenWithinSla",
            "AssignmentStatus": "Unassigned", "PublicExploitAvailable": False,
            "VerifiedExploitAvailable": False, "ExploitKitAvailable": False, "PriorityScore": 80,
            "AzureResourceId": f"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-{index // 2}",
        }
        rows.append(row)
        events.append({
            **row, "EventId": f"new-{index}", "EventType": "New",
            "FindingStatus": "Open", "FixedUtc": "", "ReopenedUtc": "",
            "EffectiveTimeUtc": row["FirstSeenUtc"], "EventTimeUtc": row["FirstSeenUtc"],
            "SnapshotTimeUtc": row["FirstSeenUtc"], "CollectionRunId": OLDER_RUN,
        })
        if status == "Reopened":
            events.append({
                **row, "EventId": f"prior-fix-{index}", "EventType": "Fixed",
                "FindingStatus": "Fixed", "ReopenedUtc": "", "SlaStatus": "FixedWithinSla",
                "EffectiveTimeUtc": row["FixedUtc"], "EventTimeUtc": row["FixedUtc"],
                "SnapshotTimeUtc": row["FixedUtc"], "CollectionRunId": "live-20261029T000000Z",
            })
        if status != "Open":
            events.append({
                **row, "EventId": f"transition-{index}", "EventType": status,
                "EffectiveTimeUtc": row["ReopenedUtc"] if status == "Reopened" else row["FixedUtc"] or iso(SOURCE_TIME),
                "EventTimeUtc": iso(SOURCE_TIME),
            })
    datasets = {
        "findings": rows, "findingEvents": events,
        "devices": [{
            "DeviceId": f"device-{index}", "DeviceName": f"host-{index}",
            "OnboardingStatus": "Onboarded", "HealthStatus": "Active", "LastSeenUtc": iso(SOURCE_TIME),
            "SnapshotTimeUtc": iso(SOURCE_TIME),
        } for index in range(2)],
        "recommendations": [{
            "RecommendationId": f"rec-{index}", "RecommendationName": "Update example software",
            "ProductName": "Example", "RemediationType": "Update", "Status": "Active",
        } for index in range(2)],
        "vulnerabilities": [{"CveId": row["CveId"]} for row in rows],
        "collectionRuns": [{
            "CollectionRunId": run, "SnapshotTimeUtc": stamp, "Status": "Success",
            "Endpoint": "machine_vulnerabilities", "DataOrigin": "Live",
        } for run, stamp in ((OLDER_RUN, rows[0]["FirstSeenUtc"]), (SOURCE_RUN, iso(SOURCE_TIME)))],
    }
    raw = tmp_path / "source-raw" / SOURCE_RUN
    raw.mkdir(parents=True)
    bundle = create_run_bundle(
        raw, datasets, [], tool.ROOT / "config/sla-policies.json", tmp_path / "source-history",
        snapshot=SOURCE_TIME, run_id=SOURCE_RUN,
    )
    manifest = json.loads((bundle / "manifest.json").read_text())
    return bundle, manifest


class Service:
    def __init__(self):
        self.data = {}
        self.metadata = {}
        self.etags = {}
        self.uploads = []
        self.downloads = []
        self.before_pointer = None
        self.wrong_size = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def get_container_client(self, name):
        return Container(self, name)


class Container:
    def __init__(self, service, name):
        self.service, self.name = service, name

    def get_container_properties(self):
        return {}

    def get_blob_client(self, name):
        return Blob(self.service, self.name, name)


class Blob:
    def __init__(self, service, container, name):
        self.service, self.container, self.name = service, container, name
        self.key = (container, name)

    def get_blob_properties(self):
        return SimpleNamespace(
            size=len(self.service.data[self.key]) + self.service.wrong_size,
            metadata=self.service.metadata.get(self.key, {}), etag=self.service.etags.get(self.key, "original"),
        )

    def download_blob(self, **kwargs):
        self.service.downloads.append(self.key)
        if kwargs.get("etag") and kwargs["etag"] != self.get_blob_properties().etag:
            raise ResourceModifiedError("Pointer changed")
        data = self.service.data[self.key]

        def readinto(handle):
            hook = kwargs.get("progress_hook")
            if hook:
                hook(len(data) // 2, len(data))
            written = handle.write(data)
            if hook:
                hook(written, len(data))
            return written

        return SimpleNamespace(readall=lambda: data, readinto=readinto, chunks=lambda: iter((data[:3], data[3:])))

    def upload_blob(self, data, **kwargs):
        if self.container == "test-current" and self.service.before_pointer:
            self.service.before_pointer()
        if not kwargs["overwrite"] and self.key in self.service.data:
            raise ResourceExistsError("Immutable collision")
        if kwargs.get("etag") and kwargs["etag"] != self.get_blob_properties().etag:
            raise ResourceModifiedError("Concurrent publisher")
        content = data.read() if hasattr(data, "read") else data
        hook = kwargs.get("progress_hook")
        if hook:
            hook(len(content) // 2, len(content))
        self.service.data[self.key] = content
        self.service.metadata[self.key] = kwargs.get("metadata", {})
        self.service.etags[self.key] = "new"
        self.service.uploads.append((self.container, self.name, kwargs))
        if hook:
            hook(len(content), len(content))


@pytest.fixture
def service(seed):
    bundle, manifest = seed
    result = Service()
    result.data["test-current", "current/manifest.json"] = json.dumps(manifest).encode()
    for item in manifest["files"]:
        folder = item["kind"]
        result.data["test-history", item["path"]] = (bundle / folder / Path(item["path"]).name).read_bytes()
    return result


@pytest.fixture
def generated(tmp_path, service, seed):
    _, manifest = seed
    source = tmp_path / "downloaded"
    tool.download_seed(service.get_container_client("test-history"), manifest, source)
    output = tmp_path / "generated"
    output.mkdir()
    bundle, raw, details = tool.build_bundle(source, manifest, output, 10, 20, TARGET_TIME, history_days=2)
    return bundle, raw, details


def test_extrapolation_exact_counts_relations_partial_cohort_and_history(generated):
    bundle, raw, details = generated
    assert verify_run_bundle(bundle, raw) == []
    findings = list(iter_json_rows(bundle / "curated/findings.json.gz"))
    events = list(iter_json_rows(bundle / "curated/finding-events.json.gz"))
    devices = list(iter_json_rows(bundle / "curated/devices.json.gz"))
    recommendations = list(iter_json_rows(bundle / "curated/recommendations.json.gz"))
    assert len(findings) == len({row["FindingKey"] for row in findings}) == 10
    assert len(devices) == len(recommendations) == 6
    assert len({row["CveId"] for row in findings}) == 4
    assert {row["FindingStatus"] for row in findings} == {"Open", "Fixed", "Reopened", "PendingVerification"}
    by_key = {row["FindingKey"]: row for row in findings}
    for event in events:
        assert event["FindingKey"] in by_key
        assert event["DeviceId"] == by_key[event["FindingKey"]]["DeviceId"]
        assert event["RecommendationId"] == by_key[event["FindingKey"]]["RecommendationId"]
    assert len(events) == len({event["EventId"] for event in events}) == 19
    assert len({event["SnapshotTimeUtc"] for event in events}) == 3
    assert {row["DeviceId"] for row in findings} <= {row["DeviceId"] for row in devices}
    assert {row["RecommendationId"] for row in findings} <= {row["RecommendationId"] for row in recommendations}
    collection = list(iter_json_rows(bundle / "curated/collection-runs.json.gz"))
    assert max(collection, key=lambda row: row["SnapshotTimeUtc"])["CollectionRunId"] == details["runId"]
    history = list(iter_json_rows(bundle / "curated/run-history.json.gz"))
    assert len(history) == 1
    assert history[0]["OpenFindings"] == 7
    assert history[0]["CollectionRunId"] == details["runId"]
    pages = list(raw.glob("*.json.gz"))
    assert len(pages) == 1
    combined = [row for page in sorted(pages) for row in raw_rows(page, field="value")]
    assert combined == findings
    assert details["publishedFilesIncludingPointer"] == len(list((bundle / "curated").glob("*"))) + len(pages) + 5 == 20
    assert details["sourceRunId"] == SOURCE_RUN and details["historicalRunAggregatesCopied"] is False
    assert details["runId"].startswith("synthetic-20261024T005946Z-loadtest-")


def test_generated_bundle_prepares_all_real_dashboard_views(generated, tmp_path):
    bundle, _, details = generated
    engine = DashboardQueryEngine(
        tmp_path / "query-index", details["runId"], iso(TARGET_TIME),
        lambda name: iter_json_rows(bundle / "curated" / f"{name}.json.gz"),
    )
    filters = initial_filters(tool.ROOT / "dashboard/config.js")
    for view in PREPARED_VIEWS:
        payload = {"view": view, "filters": filters, "mode": "findings", "limit": 100}
        engine.prepare(payload)
        assert engine.query(payload)["scope"]["findings"] == 7


@pytest.mark.parametrize("change", ["hash", "size", "rows"])
def test_seed_corruption_is_rejected_before_extrapolation(tmp_path, service, seed, change):
    _, manifest = seed
    manifest = deepcopy(manifest)
    item = next(row for row in manifest["files"] if row.get("dataset") == "findings")
    if change == "hash":
        item["sha256"] = "0" * 64
    elif change == "size":
        item["sizeBytes"] += 1
    else:
        item["rowCount"] += 1
    with pytest.raises(ValueError, match="integrity|row count"):
        tool.download_seed(service.get_container_client("test-history"), manifest, tmp_path / "bad-seed")
    assert service.uploads == []


@pytest.mark.parametrize("change", ["future", "incomplete", "missing", "duplicate", "unsafe"])
def test_invalid_manifest_is_rejected(seed, change):
    _, manifest = seed
    manifest = deepcopy(manifest)
    if change == "future":
        manifest["schemaVersion"] = 100
    elif change == "incomplete":
        manifest["complete"] = False
    elif change == "missing":
        manifest["files"] = manifest["files"][1:]
    elif change == "duplicate":
        manifest["files"].append(deepcopy(manifest["files"][0]))
    else:
        manifest["files"][0]["path"] = "../outside.json.gz"
    with pytest.raises(ValueError):
        tool.validate_manifest(manifest)


def test_publish_is_append_only_manifest_last_and_pointer_conditionally_last(generated, service):
    bundle, raw, details = generated
    original = deepcopy(service.data)
    assert tool.publish(service, "test-history", "test-current", bundle, raw, "original") == 20
    assert len(service.uploads) == 20
    assert all(not options["overwrite"] for _, _, options in service.uploads[:-1])
    assert service.uploads[-2][1].endswith(f"/{details['runId']}/manifest.json")
    container, path, options = service.uploads[-1]
    assert (container, path) == ("test-current", "current/manifest.json")
    assert options["overwrite"] is True
    assert options["etag"] == "original" and options["match_condition"] == tool.MatchConditions.IfNotModified
    assert all(service.data[key] == value for key, value in original.items() if key != (container, path))
    assert json.loads(service.data[container, path])["runId"] == details["runId"]


@pytest.mark.parametrize("failure", ["changed", "race", "collision", "remote-size", "local-corruption"])
def test_publication_failures_preserve_pointer_and_existing_history(generated, service, failure):
    bundle, raw, _ = generated
    current_key = ("test-current", "current/manifest.json")
    original_pointer = service.data[current_key]
    first = json.loads((bundle / "manifest.json").read_text())["files"][0]["path"]
    if failure == "changed":
        service.etags[current_key] = "changed"
    elif failure == "race":
        service.before_pointer = lambda: service.etags.update({current_key: "raced"})
    elif failure == "collision":
        service.data["test-history", first] = b"immutable original"
    elif failure == "remote-size":
        service.wrong_size = True
    else:
        (bundle / "curated" / Path(first).name).write_bytes(b"bad")
    with pytest.raises((ValueError, ResourceExistsError, ResourceModifiedError)):
        tool.publish(service, "test-history", "test-current", bundle, raw, "original")
    assert service.data[current_key] == original_pointer
    assert not any(container == "test-current" for container, _, _ in service.uploads)
    if failure == "collision":
        assert service.data["test-history", first] == b"immutable original"


@pytest.mark.parametrize("publish", [False, True])
def test_full_cli_uses_az_identity_and_explicit_target_without_modifying_apps(tmp_path, seed, service, monkeypatch, publish):
    account = {"tenantId": "11111111-1111-1111-1111-111111111111", "id": "test-sub", "name": "Test"}
    monkeypatch.setattr(tool, "choose_target", lambda _args: (account, "testaccount", "test-history", "test-current"))
    credential = create_autospec(tool.AzureCliCredential)
    monkeypatch.setattr(tool, "AzureCliCredential", credential)
    monkeypatch.setattr(tool, "BlobServiceClient", Mock(return_value=service))
    arguments = [
        "--findings", "10", "--published-files", "20", "--history-days", "2",
        "--output-dir", str(tmp_path / "output"),
    ]
    if publish:
        arguments += ["--publish", "--confirm-target", "testaccount/test-history/test-current"]
    assert tool.main(arguments) == 0
    reports = list((tmp_path / "output").glob("*/population.json"))
    assert len(reports) == 1
    report = json.loads(reports[0].read_text())
    assert report["status"] == ("published" if publish else "validated")
    assert report["published"] is publish
    credential.assert_called_once_with(tenant_id=account["tenantId"])
    assert len(service.uploads) == (20 if publish else 0)
    assert report["rowCounts"]["findings"] == 10
    assert not list(reports[0].parent.glob("seed-*"))
    assert not list(reports[0].parent.glob("index-*"))
    if publish:
        assert report["uploadedFiles"] == 20
    bundle, manifest = seed
    assert json.loads((bundle / "manifest.json").read_text()) == manifest


@pytest.mark.parametrize("checkpoint", [True, False])
def test_resume_failed_local_population_reuses_exact_curated_and_raw_data(generated, seed, tmp_path, monkeypatch, checkpoint):
    bundle, raw, details = generated
    source = bundle.parent.parent
    _, seed_manifest = seed
    tool.save_json(source / "source-manifest.json", seed_manifest)
    tool.save_json(source / "population.json", {
        "status": "failed", "published": False, "publicationMayHaveCompleted": False,
        "sourceRunId": seed_manifest["runId"],
    })
    (bundle / "manifest.json").unlink()
    if not checkpoint:
        (bundle / "manifest.pending.json").unlink()
    before = {path: path.read_bytes() for path in source.rglob("*") if path.is_file()}
    monkeypatch.setattr(tool, "build_bundle", Mock(side_effect=AssertionError("Must not regenerate findings")))
    monkeypatch.setattr(tool, "download_seed", Mock(side_effect=AssertionError("Must not download the seed")))
    if checkpoint:
        monkeypatch.setattr(tool, "iter_json_rows", Mock(side_effect=AssertionError("Checkpoint counts avoid another JSON scan")))
    destination = tmp_path / "recovered"
    destination.mkdir()
    restored, retained_raw, resumed = tool.resume_local_bundle(source, destination)
    assert retained_raw == raw
    assert resumed == details
    assert verify_run_bundle(restored, retained_raw) == []
    for path, content in before.items():
        assert path.read_bytes() == content
    for path in (restored / "curated").glob("*.json.gz"):
        assert path.read_bytes() == (source / "staged" / path.name).read_bytes()


def test_cli_resume_publishes_validated_bundle_without_rebuilding_or_redownloading(tmp_path, seed, service, monkeypatch):
    account = {"tenantId": "tenant", "id": "test-sub", "name": "Test"}
    monkeypatch.setattr(tool, "choose_target", lambda _args: (account, "testaccount", "test-history", "test-current"))
    monkeypatch.setattr(tool, "AzureCliCredential", create_autospec(tool.AzureCliCredential))
    monkeypatch.setattr(tool, "BlobServiceClient", Mock(return_value=service))
    output = tmp_path / "output"
    assert tool.main(["--findings", "10", "--published-files", "20", "--output-dir", str(output)]) == 0
    source = next(output.iterdir())
    source_report = (source / "population.json").read_bytes()
    monkeypatch.setattr(tool, "build_bundle", Mock(side_effect=AssertionError("Must not generate again")))
    monkeypatch.setattr(tool, "assemble_bundle", Mock(side_effect=AssertionError("Must not rebuild validated indexes")))
    monkeypatch.setattr(tool, "download_seed", Mock(side_effect=AssertionError("Must not download again")))
    assert tool.main([
        "--resume-local", str(source), "--output-dir", str(output), "--publish",
        "--confirm-target", "testaccount/test-history/test-current",
    ]) == 0
    assert (source / "population.json").read_bytes() == source_report
    reports = [json.loads(path.read_text()) for path in output.glob("*/population.json")]
    published = next(report for report in reports if report["published"])
    assert published["rowCounts"]["findings"] == 10 and published["uploadedFiles"] == 20
    assert published["resumedFrom"] == str(source)
    assert len(service.uploads) == 20


def test_wrong_publish_confirmation_makes_no_cloud_requests(tmp_path, monkeypatch):
    monkeypatch.setattr(tool, "choose_target", lambda _args: ({}, "testaccount", "test-history", "test-current"))
    credential = Mock()
    monkeypatch.setattr(tool, "AzureCliCredential", credential)
    assert tool.main(["--publish", "--confirm-target", "wrong", "--output-dir", str(tmp_path)]) == 1
    credential.assert_not_called()
    assert list(tmp_path.iterdir()) == []


def test_container_prompts_and_subscription_account_guard(monkeypatch):
    account = {"tenantId": "tenant", "id": "sub", "name": "Test"}
    az = Mock(side_effect=[account, [{"name": "testaccount", "blob": "https://testaccount.blob.core.windows.net/"}]])
    monkeypatch.setattr(tool, "az_json", az)
    monkeypatch.setattr("builtins.input", Mock(side_effect=["testaccount", "test-history", "test-current"]))
    args = SimpleNamespace(account=None, history_container=None, current_container=None, subscription="sub")
    assert tool.choose_target(args) == (account, "testaccount", "test-history", "test-current")
    assert az.call_args_list[0].args == ("account", "show", "--subscription", "sub")
    assert az.call_args_list[1].args[:5] == ("storage", "account", "list", "--subscription", "sub")


@pytest.mark.parametrize("failure", ["smaller-target", "too-many-files", "no-history"])
def test_invalid_expansion_stops_before_writing_generated_files(tmp_path, seed, failure):
    bundle, manifest = seed
    target, count = (3, 20) if failure == "smaller-target" else (10, 100 if failure == "too-many-files" else 20)
    if failure == "no-history":
        manifest = deepcopy(manifest)
        next(item for item in manifest["files"] if item.get("dataset") == "findingEvents")["rowCount"] = 0
    output = tmp_path / "invalid-output"
    output.mkdir()
    with pytest.raises(ValueError):
        tool.build_bundle(bundle / "curated", manifest, output, target, count, TARGET_TIME)
    assert list(output.iterdir()) == []


def test_interactive_publication_can_be_declined_after_reviewing_generated_counts(tmp_path, service, monkeypatch):
    account = {"tenantId": "11111111-1111-1111-1111-111111111111", "id": "test-sub"}
    monkeypatch.setattr(tool, "choose_target", lambda _args: (account, "testaccount", "test-history", "test-current"))
    monkeypatch.setattr(tool, "AzureCliCredential", create_autospec(tool.AzureCliCredential))
    monkeypatch.setattr(tool, "BlobServiceClient", Mock(return_value=service))
    prompts = Mock(return_value="do-not-publish")
    monkeypatch.setattr("builtins.input", prompts)
    assert tool.main([
        "--publish", "--findings", "10", "--published-files", "20",
        "--history-days", "2", "--output-dir", str(tmp_path / "cancelled"),
    ]) == 1
    assert "Review the generated counts" in prompts.call_args.args[0]
    assert service.uploads == []
    report_path = next((tmp_path / "cancelled").glob("*/population.json"))
    report = json.loads(report_path.read_text())
    assert report["rowCounts"]["findings"] == 10
    assert report["status"] == "failed" and report["published"] is False
    assert report["publicationMayHaveCompleted"] is False


def test_progress_reports_measured_rate_percent_eta_and_cpu(monkeypatch, capsys):
    progress = tool.Progress("example", total=1000, unit="rows")
    progress.started = progress.previous_time = progress.previous_cpu = 0
    progress.update(500)
    progress.update(100)
    monkeypatch.setattr(tool.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(tool.time, "process_time", lambda: 5.0)
    monkeypatch.setattr(tool.sys, "platform", "unsupported")
    progress.emit("heartbeat")
    output = capsys.readouterr().out
    for text in ("rows=500/1,000", "rate=50rows/s", "percent=50.0%", "eta~10.0s", "cpu=50%", "peakRssMiB=unavailable"):
        assert text in output


def test_progress_without_a_total_does_not_invent_percent_or_eta(capsys):
    with tool.Progress("unknown amount", unit="rows") as progress:
        progress.update(123)
    output = capsys.readouterr().out
    assert "rows=123" in output and "event=complete" in output
    assert "percent=" not in output and "eta~" not in output
    assert not progress.thread.is_alive()


def test_row_progress_preserves_records_and_counts_including_last_batch(capsys):
    rows = [{"position": value} for value in range(2049)]
    with tool.Progress("rows", total=len(rows), unit="rows") as progress:
        assert list(progress.track(rows)) == rows
    assert progress.current == len(rows)
    assert "rows=2,049/2,049" in capsys.readouterr().out
    assert not progress.thread.is_alive()


@pytest.mark.parametrize("error", [OSError("test failure"), KeyboardInterrupt()])
def test_failed_progress_stops_its_thread_without_reporting_success(error, capsys):
    progress = tool.Progress("fails")
    with pytest.raises(type(error)):
        with progress:
            raise error
    output = capsys.readouterr().out
    assert "event=failed" in output and "event=complete" not in output
    assert progress.stopped.is_set() and not progress.thread.is_alive()


def test_periodic_heartbeat_works_during_a_wait(monkeypatch, capsys):
    monkeypatch.setattr(tool, "PROGRESS_SECONDS", 0.01)
    heartbeat = threading.Event()
    progress = tool.Progress("waiting")
    emit = progress.emit

    def observe(event):
        emit(event)
        if event == "heartbeat":
            heartbeat.set()

    monkeypatch.setattr(progress, "emit", observe)
    with progress:
        assert heartbeat.wait(2)
    assert "event=heartbeat" in capsys.readouterr().out
    assert not progress.thread.is_alive()


@pytest.mark.parametrize("fail", [False, True])
def test_sql_work_is_observed_without_changing_results_or_leaking_handler(fail, capsys):
    db = sqlite3.connect(":memory:")
    query = "WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<100000) SELECT sum(x) FROM n"
    progress = tool.Progress("SQL", connection=db)
    try:
        if fail:
            with pytest.raises(ValueError, match="test failure"):
                with progress:
                    assert db.execute(query).fetchone()[0] == 5_000_050_000
                    raise ValueError("test failure")
        else:
            with progress:
                assert db.execute(query).fetchone()[0] == 5_000_050_000
        assert progress.current >= 1_000_000
        before = progress.current
        assert db.execute(query).fetchone()[0] == 5_000_050_000
        assert progress.current == before
        assert not progress.thread.is_alive()
        output = capsys.readouterr().out
        assert "sqliteOps=" in output and "percent=" not in output and "eta~" not in output
    finally:
        db.close()


def test_transfer_hooks_report_intermediate_download_and_aggregate_upload_bytes(tmp_path, service, seed, generated, monkeypatch, capsys):
    updates = []
    update = tool.Progress.update

    def observe(self, current, total=None, **kwargs):
        update(self, current, total, **kwargs)
        updates.append((self.phase, self.current))

    monkeypatch.setattr(tool.Progress, "update", observe)
    _, manifest = seed
    source = tmp_path / "progress-download"
    tool.download_seed(service.get_container_client("test-history"), manifest, source)
    item = next(item for item in manifest["files"] if item.get("dataset") == "findings")
    assert ("download:findings", item["sizeBytes"] // 2) in updates
    assert ("download:findings", item["sizeBytes"]) in updates
    bundle, raw, _ = generated
    assert tool.publish(service, "test-history", "test-current", bundle, raw, "original") == 20
    generated_manifest = json.loads((bundle / "manifest.json").read_text())
    expected_bytes = sum(item["sizeBytes"] for item in generated_manifest["files"]) + 2 * (bundle / "manifest.json").stat().st_size
    uploaded = [value for phase, value in updates if phase == "publish run"]
    assert uploaded == sorted(uploaded)
    assert uploaded[-1] == expected_bytes
    assert len(set(uploaded)) > len(generated_manifest["files"])
    output = capsys.readouterr().out
    assert "MiB=" in output and "MiB/s" in output
    assert "verifiedFiles=20/20" in output and "writing=current-pointer" not in output.splitlines()[-1]
