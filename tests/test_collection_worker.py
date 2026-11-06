import gzip
import hashlib
import json
import logging
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import urlsplit
import shutil

import pytest
import requests
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError

from vulnerability_view import collection_worker
from vulnerability_view.collection_transport import CompletedPhases, CheckpointYield, current_checkpoints
from vulnerability_view.collection_timing import OperationTotals
from vulnerability_view.config import Settings
from vulnerability_view.defender_client import DefenderClient, ENDPOINTS
from vulnerability_view.storage_writer import archive_raw_page
from vulnerability_view.collection_workflow import publish_run, verify_batch, verify_file
from dataclasses import asdict
from test_collection_identity import TENANT, OTHER, credential as tenant_credential


@pytest.fixture(autouse=True)
def collection_credential(monkeypatch):
    monkeypatch.setattr(collection_worker, "create_credential", lambda *args: tenant_credential(TENANT))


class WorkerStore:
    def __init__(self):
        self.files = {}
        self.timings = OperationTotals()
        self.uploads = []
        self.downloads = 0

    def json(self, name):
        return json.loads(self.read(name))

    def read(self, name):
        if name not in self.files:
            raise ResourceNotFoundError("missing")
        return self.files[name]

    def list_names(self, prefix):
        return [name for name in self.files if name.startswith(prefix)]

    def append(self, name, content):
        if name in self.files:
            raise ResourceExistsError("exists")
        self.files[name] = content

    def append_json(self, name, value):
        self.append(name, json.dumps(value).encode())

    def download_file(self, name, target, expected):
        self.downloads += 1
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.read(name))

    def upload_file(self, name, source):
        self.uploads.append(name)
        content = source.read_bytes()
        if name in self.files:
            if self.files[name] != content:
                raise ValueError("conflicting immutable data")
        else:
            self.append(name, content)
        return {"path": name, "sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "sizeBytes": source.stat().st_size}


def test_journal_listing_is_one_remote_scan_per_activity_and_tracks_new_pages(tmp_path):
    store = WorkerStore()
    prefix = "raw/run/continuations/"
    for machine in range(2252):
        store.append(f"{prefix}findings/{machine}/00000001.json", b"{}")
    store.list_names = Mock(wraps=store.list_names)
    cache = collection_worker.LocalRequestCache(store, tmp_path, prefix)
    for machine in range(2252):
        assert cache.list_names(f"{prefix}findings/{machine}/") == [f"{prefix}findings/{machine}/00000001.json"]
    cache.append(f"{prefix}findings/0/00000002.json", b"{}")
    assert len(cache.list_names(f"{prefix}findings/0/")) == 2
    store.list_names.assert_called_once_with(prefix)
    assert len(collection_worker.LocalRequestCache(store, tmp_path, prefix).list_names(f"{prefix}findings/0/")) == 2
    assert store.list_names.call_count == 2


def test_completed_phases_restore_cold_and_reject_identity_or_byte_changes(tmp_path):
    store = WorkerStore()
    folder = tmp_path / "original"
    archive_raw_page("machines", 1, b'{"value":[{"id":"one"}]}', "run", root=folder)
    phases = CompletedPhases(store, "raw/run", folder / "run", {"tenant": TENANT})
    phases.save("machines", {"RowCount": 1}, [{"id": "one"}])
    frozen = dict(store.files)
    cold = CompletedPhases(store, "raw/run", tmp_path / "cold", {"tenant": TENANT})
    assert cold.load("machines")["payload"] == [{"id": "one"}]
    assert store.files == frozen
    wrong = CompletedPhases(store, "raw/run", tmp_path / "other", {"tenant": OTHER})
    with pytest.raises(ValueError, match="frozen"):
        wrong.load("machines")
    (tmp_path / "cold/machines-page-0001.json.gz").write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="integrity"):
        cold.load("machines")
    store.files["raw/run/machines-page-0001.json.gz"] = b"corrupt"
    with pytest.raises(ValueError, match="integrity"):
        CompletedPhases(store, "raw/run", tmp_path / "another", {"tenant": TENANT}).load("machines")


def plan():
    return {
        "runId": "live-20261023T160000Z", "snapshotUtc": "2026-10-23T16:00:00+00:00",
        "settings": asdict(Settings()), "baseline": None,
        "collection": "full", "enrichment": "targeted", "pageSize": 2500,
        "sourceTenantId": TENANT, "reuseBaseline": False,
    }


@pytest.mark.parametrize("stage", ["prepare", "verify", "verify-batch", "publish"])
def test_worker_dispatches_supervised_storage_stages_without_loading_a_collection_plan(monkeypatch, tmp_path, stage):
    store = SimpleNamespace(close=Mock(), json=Mock(side_effect=AssertionError("No collection plan for this stage")))
    monkeypatch.setattr(collection_worker.Settings, "load", lambda: Settings())
    monkeypatch.setattr(collection_worker, "RunStore", lambda settings: store)
    action = {
        "stage": stage, "runId": datetime.now(UTC).strftime("live-%Y%m%dT%H%M%SZ"),
        "deadlineUtc": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
    }
    if stage == "prepare":
        action.update(request={"runId": action["runId"]}, policy={"policyVersion": "original"})
    callback = Mock(return_value={"stage": stage, "done": True})
    monkeypatch.setattr(collection_worker, {
        "prepare": "prepare_run", "verify": "verify_file", "verify-batch": "verify_batch", "publish": "publish_run",
    }[stage], callback)
    input_path, output_path = tmp_path / "input.json", tmp_path / "result.json"
    input_path.write_text(json.dumps(action))
    monkeypatch.setattr(collection_worker.sys, "argv", ["worker", str(input_path), str(output_path)])
    collection_worker.main()
    assert json.loads(output_path.read_text()) == {"stage": stage, "done": True}
    if stage == "prepare":
        callback.assert_called_once_with(action["request"], store, action["policy"])
    else:
        callback.assert_called_once_with(action, store)
    store.close.assert_called_once()


@pytest.mark.parametrize("interrupted", [False, True])
def test_processing_heartbeat_reports_shared_run_deadline_and_stops(monkeypatch, caplog, interrupted):
    monkeypatch.setattr(collection_worker, "PROCESSING_HEARTBEAT_SECONDS", 0.01)
    observed = threading.Event()
    log = collection_worker.logging.info

    def capture(message, *args, **kwargs):
        log(message, *args, **kwargs)
        if "heartbeat" in message:
            observed.set()

    monkeypatch.setattr(collection_worker.logging, "info", capture)
    monitors = []

    def run():
        with collection_worker._processing_progress(plan()["runId"]) as progress:
            progress("stage=normalize step=replay rows=123 https://example.invalid?secret=value")
            monitors.extend(thread for thread in threading.enumerate() if thread.name == "dvm-processing-heartbeat")
            assert observed.wait(3), "A blocked processing step must still emit heartbeats"
            if interrupted:
                raise RuntimeError("Processing interrupted")

    with caplog.at_level(logging.INFO):
        if interrupted:
            with pytest.raises(RuntimeError, match="Processing interrupted"):
                run()
        else:
            run()
    assert "executionDeadline=original-run-six-hours" in caplog.text
    assert "heartbeat runId=live-20261023T160000Z" in caplog.text
    assert "cpuSeconds=" in caplog.text
    assert "lastProgressAgeSeconds=" in caplog.text
    assert "stage=normalize step=replay rows=123" in caplog.text
    assert "secret" not in caplog.text
    assert "https://" not in caplog.text
    assert monitors and all(not thread.is_alive() for thread in monitors)


def test_worker_collect_uses_frozen_snapshot_and_yields_small_progress(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    received = {}

    def collect(*args, **kwargs):
        received.update(kwargs)
        transport = current_checkpoints()
        transport.saved_requests = 3
        transport.new_requests = 4
        raise CheckpointYield(7200, "HTTP 429")

    monkeypatch.setattr(collection_worker, "collect_live", collect)
    result = collection_worker.collect_batch(plan(), WorkerStore(), tmp_path / "cache")
    assert result == {
        "done": False, "newRequests": 3, "cachedRequests": 0,
        "retryAfter": 7200, "retry": True, "reason": "HTTP 429",
        "collectionMode": "full", "sinceTime": None, "downloadedRows": 0, "downloadedBytes": 0,
    }
    assert received["snapshot"] == datetime(2026, 10, 23, 16, tzinfo=UTC)
    assert received["raw_only"] is True
    assert received["cve_batch_size"] == 100
    assert received["page_size"] == 2500


def test_machine_progress_survives_generic_completion_and_next_start(monkeypatch, tmp_path, caplog):
    monkeypatch.chdir(tmp_path)

    def collect(*args, **kwargs):
        report = kwargs["progress_callback"]
        report("[machine_vulnerabilities] starting device-scoped collection for 2,252 machines")
        report("[machine_vulnerabilities] complete: 800 rows (100%)")
        report("[machine_vulnerabilities] machines complete: 100/2,252; 80,000 total rows; 1s elapsed")
        report("[machine_vulnerabilities] starting download")
        raise CheckpointYield()

    monkeypatch.setattr(collection_worker, "collect_live", collect)
    with caplog.at_level(logging.INFO):
        result = collection_worker.collect_batch(plan(), WorkerStore(), tmp_path / "cache")
    assert result["machinesCompleted"] == 100
    assert result["machinesTotal"] == 2252
    assert result["findingRowsCheckpointed"] == 80000
    assert "machines complete: 100/2,252" in result["lastProgress"]
    assert "machines complete: 100/2,252" in caplog.text


@pytest.mark.parametrize("message,cached,severity", [
    ("[recommendation_machines] 66/131 recommendations; 106,496 relationships; 0 unavailable", False, logging.INFO),
    ("[vulnerabilities] CVE metadata batches processed: 1/1; 0 CVEs unavailable", False, logging.INFO),
    ("[vulnerabilities] CVE metadata batches processed: 1/1; 3 CVEs unavailable", False, logging.INFO),
    ("[optional] optional endpoint unavailable: HTTP 404", False, logging.WARNING),
    ("[optional] optional endpoint unavailable: HTTP 404", True, logging.WARNING),
    ("[recommendation_machines] recommendation-one unavailable: HTTP 403", False, logging.WARNING),
    ("[machines] failed: HTTP 403", True, logging.ERROR),
    ("[machines] failed: while requesting page 2", False, logging.ERROR),
    ("[machine_vulnerabilities] failed machine 1/2: collection is incomplete", False, logging.ERROR),
])
def test_progress_severity_distinguishes_counts_optional_issues_and_failures(
    monkeypatch, tmp_path, caplog, message, cached, severity,
):
    monkeypatch.chdir(tmp_path)

    def collect(*args, **kwargs):
        current_checkpoints().last_was_cached = cached
        kwargs["progress_callback"](message)
        raise CheckpointYield()

    monkeypatch.setattr(collection_worker, "collect_live", collect)
    with caplog.at_level(logging.INFO):
        result = collection_worker.collect_batch(plan(), WorkerStore(), tmp_path / "cache")
    assert result["done"] is False and result["retry"] is False
    matching = [record for record in caplog.records if record.getMessage() == message]
    assert len(matching) == 1
    assert matching[0].levelno == severity


def test_delta_worker_restarts_directly_and_commits_the_same_immutable_raw_pages(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    credential = tenant_credential(TENANT)
    monkeypatch.setattr(collection_worker, "create_credential", lambda *args: credential)
    monkeypatch.setattr(collection_worker, "baseline_rows", lambda *args, **kwargs: {})
    monkeypatch.setattr(collection_worker, "_resolve_collection_mode",
                        lambda *args: ("delta", datetime(2026, 10, 22, tzinfo=UTC)))
    monkeypatch.setattr("vulnerability_view.collection_transport.time.sleep", lambda delay: None)
    run = plan()
    run["collection"] = "delta"
    run.update(reuseBaseline=True, baseline={"sourceTenantId": TENANT})
    store = WorkerStore()
    calls = []

    def collect(*args, **kwargs):
        transport = current_checkpoints()
        transport.request_limit = 1
        client = DefenderClient(
            "https://example.test", credential,
            lambda name, page, content: archive_raw_page(name, page, content, run["runId"]),
        )
        transport.allowed_hosts.add("example.test")

        def send(url, **request_kwargs):
            calls.append(url)
            body = {"value": [{"id": str(len(calls))}]}
            if len(calls) == 1:
                body["@odata.nextLink"] = "https://example.test/next"
            response = requests.Response()
            response.status_code = 200
            response._content = json.dumps(body).encode()
            return response

        monkeypatch.setattr(client.session, "get", send)
        endpoint = next(item for item in ENDPOINTS if item.name == "vulnerability_changes")
        _, status = client.collect(endpoint, {"sinceTime": kwargs["previous_snapshot"].isoformat()}, retain_rows=False)
        status["SourceTenantId"] = TENANT
        return {}, [status]

    monkeypatch.setattr(collection_worker, "collect_live", collect)
    first = collection_worker.collect_batch(run, store, tmp_path / "cache")
    assert first["done"] is False
    assert first["downloadedRows"] == 1
    frozen = {name: content for name, content in store.files.items() if "/continuations/" in name}
    complete = collection_worker.collect_batch(run, store, tmp_path / "cache")
    assert complete == {"done": True, "rawFiles": 2, "collectionMode": "delta"}
    assert len(calls) == 2
    assert all(store.files[name] == content for name, content in frozen.items())
    collected = store.json(f"runs/2026/10/23/{run['runId']}/collected.json")
    assert collected["endpointStatuses"][0]["RowCount"] == 2
    for item in collected["rawFiles"]:
        assert item["sha256"] == hashlib.sha256(store.read(item["path"])).hexdigest()


def test_scoped_worker_selects_snapshot_without_loading_previous_findings(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(collection_worker, "baseline_rows",
                        lambda *args, **kwargs: pytest.fail("Scoped collection does not need baseline rows"))
    run = plan()
    run["settings"]["exclude_scale_sets"] = True
    run["collection"] = "auto"
    received = {}

    def collect(*args, **kwargs):
        received.update(kwargs)
        raise CheckpointYield()

    monkeypatch.setattr(collection_worker, "collect_live", collect)
    result = collection_worker.collect_batch(run, WorkerStore(), tmp_path / "cache")
    assert result["collectionMode"] == received["vulnerability_collection_mode"] == "full"
    assert received["exclude_scale_sets"] is True
    assert result["sinceTime"] is None


def test_old_frozen_delta_is_not_silently_reinterpreted_as_a_scoped_snapshot(monkeypatch, tmp_path):
    run = plan()
    run["settings"]["exclude_scale_sets"] = True
    store = WorkerStore()
    path = f"runs/2026/10/23/{run['runId']}/collection-inputs.json"
    store.append_json(path, {"mode": "delta", "previousSnapshot": "2026-10-22T00:00:00+00:00"})
    frozen = dict(store.files)
    monkeypatch.setattr(collection_worker, "collect_live", lambda *args, **kwargs: pytest.fail("Must fail before HTTP"))
    with pytest.raises(ValueError, match="Stop the old run"):
        collection_worker.collect_batch(run, store, tmp_path / "cache")
    assert store.files == frozen


def test_collection_logs_only_throttled_endpoint_counts_and_errors(monkeypatch, tmp_path, caplog):
    monkeypatch.chdir(tmp_path)
    clock = [0.0]
    monkeypatch.setattr(collection_worker.time, "monotonic", lambda: clock[0])

    def collect(*args, **kwargs):
        progress = kwargs["progress_callback"]
        transport = current_checkpoints()
        transport.last_was_cached = False
        progress("[machines] starting download")
        for index in range(100):
            progress(f"[machines] requesting page {index}")
            progress(f"[machines] page {index} received: 1 rows")
            progress(f"[machines] {index} rows downloaded; more data available")
        clock[0] = 59
        progress("[machines] 100 rows downloaded; more data available")
        clock[0] = 60
        progress("[machines] 200 rows downloaded; more data available")
        progress("[machines] complete: 200 rows")
        progress("[machine_vulnerabilities] starting device-scoped collection for 200 machines")
        progress("[machine_vulnerabilities] machine 1/200: device; 0 total rows")
        progress("[machine_vulnerabilities] 100 findings downloaded")
        clock[0] = 120
        progress("[machine_vulnerabilities] machines complete: 50/200; 100 findings")
        transport.last_was_cached = True
        progress("[old_endpoint] complete: cached rows")
        transport.last_was_cached = False
        progress("[machine_vulnerabilities] failed: permission denied")
        raise CheckpointYield(30, "HTTP 503")

    monkeypatch.setattr(collection_worker, "collect_live", collect)
    with caplog.at_level(logging.INFO):
        result = collection_worker.collect_batch(plan(), WorkerStore(), tmp_path / "cache")
    messages = [record.getMessage() for record in caplog.records if not record.getMessage().startswith("[timing]")]
    assert messages == [
        "[collection] runId=live-20261023T160000Z mode=full sinceTime=None baselineRunId=None excludeScaleSets=False",
        "[machines] starting download",
        "[machines] 200 rows downloaded; more data available",
        "[machines] complete: 200 rows",
        "[machine_vulnerabilities] starting device-scoped collection for 200 machines",
        "[machine_vulnerabilities] machines complete: 50/200; 100 findings",
        "[machine_vulnerabilities] failed: permission denied",
        "[collection] paused: HTTP 503; retry in 30s; newRequests=0 downloadedRows=0 downloadedBytes=0; [machine_vulnerabilities] failed: permission denied",
    ]
    assert [record.getMessage() for record in caplog.records if record.levelno == logging.ERROR] == [
        "[machine_vulnerabilities] failed: permission denied",
    ]
    assert result["lastProgress"] == "[machine_vulnerabilities] failed: permission denied"


def test_completed_collection_does_not_call_defender_again(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    calls = []

    def collect(*args, **kwargs):
        calls.append(kwargs)
        raw = tmp_path / "output/raw" / plan()["runId"]
        raw.mkdir(parents=True)
        (raw / "machines-page-000001.json.gz").write_bytes(gzip.compress(b'{"value":[]}'))
        return {}, [{"Endpoint": "machines", "Status": "Success", "SourceTenantId": TENANT}]

    monkeypatch.setattr(collection_worker, "collect_live", collect)
    store = WorkerStore()
    first = collection_worker.collect_batch(plan(), store, tmp_path / "cache")
    second = collection_worker.collect_batch(plan(), store, tmp_path / "cache")
    assert first == second == {"done": True, "rawFiles": 1, "collectionMode": "full"}
    assert len(calls) == len(store.uploads) == 1
    assert store.uploads[0].startswith("raw/2026/10/23/live-20261023T160000Z/")


def test_local_request_cache_survives_activity_processes_but_is_not_authoritative(tmp_path):
    store = WorkerStore()
    cache = collection_worker.LocalRequestCache(store, tmp_path)
    cache.append("raw/run/requests/page.json.gz", b"checkpoint")
    restarted = collection_worker.LocalRequestCache(store, tmp_path)
    assert restarted.read("raw/run/requests/page.json.gz") == b"checkpoint"
    with pytest.raises(ResourceExistsError):
        restarted.append("raw/run/requests/page.json.gz", b"changed")
    assert store.read("raw/run/requests/page.json.gz") == b"checkpoint"


def test_baseline_is_streamed_and_local_cache_integrity_is_verified(tmp_path):
    store = WorkerStore()
    content = gzip.compress(json.dumps([{"id": index} for index in range(20)]).encode())
    store.files["curated/prior.json.gz"] = content
    frozen = plan()
    frozen["reuseBaseline"] = True
    frozen["baseline"] = {"sourceTenantId": TENANT, "files": [{
        "kind": "curated", "dataset": "findings", "path": "curated/prior.json.gz",
        "rowCount": 20, "sizeBytes": len(content), "sha256": hashlib.sha256(content).hexdigest(),
    }]}
    rows = collection_worker.baseline_rows(frozen, store, tmp_path)
    assert len(rows["findings"]) == 20
    assert list(rows["findings"]) == list(rows["findings"]) == [{"id": index} for index in range(20)]
    collection_worker.baseline_rows(frozen, store, tmp_path)
    assert store.downloads == 1
    (tmp_path / "findings.json.gz").write_bytes(b"corrupt cache")
    with pytest.raises(ValueError, match="integrity"):
        collection_worker.baseline_rows(frozen, store, tmp_path)


@pytest.mark.parametrize("source", [None, OTHER])
def test_rejected_baseline_never_reaches_processing_or_history_restore(monkeypatch, tmp_path, source):
    monkeypatch.chdir(tmp_path)
    frozen = plan()
    frozen["baseline"] = {"sourceTenantId": source, "files": [{
        "kind": "curated", "dataset": "findings", "path": "curated/other-tenant.json.gz",
    }]}
    store = WorkerStore()
    prefix = f"runs/2026/10/23/{frozen['runId']}"
    store.append_json(f"{prefix}/collected.json", {
        "sourceTenantId": TENANT, "rawFiles": [], "endpointStatuses": [{"SourceTenantId": TENANT}],
    })
    received = {}

    def advance(raw, settings, baseline, *args, **kwargs):
        received["baseline"] = baseline
        return {"done": False, "nextStage": "reconcile"}

    monkeypatch.setattr(collection_worker, "advance_archived_run", advance)
    result = collection_worker.process_batch(frozen, store, tmp_path / "cache")
    assert result["done"] is False
    assert received["baseline"] == {}
    assert store.downloads == 0


def test_worker_rejects_a_source_tenant_change_before_defender_or_checkpoint_writes(monkeypatch, tmp_path):
    monkeypatch.setattr(collection_worker, "create_credential", lambda *args: tenant_credential(OTHER))
    monkeypatch.setattr(collection_worker, "collect_live", lambda *args, **kwargs: pytest.fail("No source calls allowed"))
    store = WorkerStore()
    with pytest.raises(ValueError, match="source tenant changed"):
        collection_worker.collect_batch(plan(), store, tmp_path)
    assert store.files == {}


def test_interrupted_local_cache_download_can_resume_from_remote_evidence(tmp_path):
    content = b"verified remote content"
    item = {"path": "raw/run/file.json.gz", "sizeBytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
    store = WorkerStore()
    store.files[item["path"]] = content
    complete_download = store.download_file

    def interrupted(name, destination, expected):
        destination.write_bytes(b"interrupted")
        raise requests.ConnectionError("interrupted local cache fill")

    store.download_file = interrupted
    target = tmp_path / "file.json.gz"
    with pytest.raises(requests.ConnectionError):
        collection_worker.cached_file(store, item, target)
    assert not target.exists()
    store.download_file = complete_download
    collection_worker.cached_file(store, item, target)
    assert target.read_bytes() == content


def test_interrupted_local_cache_append_does_not_poison_saved_remote_page(monkeypatch, tmp_path):
    store = WorkerStore()
    cache = collection_worker.LocalRequestCache(store, tmp_path)
    write_bytes = Path.write_bytes

    def interrupted(path, content):
        write_bytes(path, content[:3])
        raise OSError("interrupted cache write")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "write_bytes", interrupted)
        with pytest.raises(OSError):
            cache.append("raw/run/page.json.gz", b"complete saved checkpoint")
    assert cache.read("raw/run/page.json.gz") == b"complete saved checkpoint"


@pytest.mark.parametrize("metadata", ["available", "missing", "recovered_missing", "http_error"])
@pytest.mark.parametrize("workflow_version", [1, 2, 3])
def test_complete_worker_flow_preserves_tables_and_persists_retryable_bundle(monkeypatch, tmp_path, caplog, metadata, workflow_version):
    monkeypatch.chdir(tmp_path)
    credential = tenant_credential(TENANT)
    monkeypatch.setattr(collection_worker, "create_credential", lambda *args: credential)
    monkeypatch.setattr(collection_worker, "_resolve_enrichment_mode", lambda *args: "targeted")
    monkeypatch.setattr(
        "vulnerability_view.live_collector.collect_secure_scores",
        lambda *args, **kwargs: ([], {"Endpoint": "secure_scores", "Status": "Success", "DurationSeconds": 0}),
    )
    monkeypatch.setattr(
        "vulnerability_view.live_collector.collect_azure_subscriptions",
        lambda *args, **kwargs: ([], {"Endpoint": "azure_subscriptions", "Status": "Success", "DurationSeconds": 0}),
    )
    payloads = {
        "/api/machines": [{"id": "device-1", "computerDnsName": "device", "machineTags": [], "lastSeen": "2026-10-23T15:00:00Z"}],
        "/api/vulnerabilities/machinesVulnerabilities": [{
            "id": "finding-1", "machineId": "device-1", "cveId": "CVE-2026-0001",
            "severity": "High", "productName": "Product",
        }],
        "/api/vulnerabilities": [{"id": "CVE-2026-0001", "severity": "High"}] if metadata == "available" else [],
    }
    requests_sent = []

    def get(session, url, **kwargs):
        requests_sent.append(url)
        response = requests.Response()
        response.url = url
        response.status_code = 404 if metadata == "http_error" and urlsplit(url).path == "/api/vulnerabilities" else 200
        response._content = json.dumps({"value": payloads.get(urlsplit(url).path, [])}).encode()
        return response

    monkeypatch.setattr(requests.Session, "get", get)
    config = tmp_path / "config"
    config.mkdir()
    shutil.copyfile(Path(__file__).resolve().parents[1] / "config/sla-policies.json", config / "sla-policies.json")
    store = WorkerStore()
    frozen = plan()
    frozen["workflowVersion"] = workflow_version
    cache = tmp_path / "cache"
    from vulnerability_view import live_collector

    scans = []
    iter_rows = live_collector._iter_archived_endpoint_rows

    def tracked_rows(folder, endpoint, **kwargs):
        scans.append(endpoint)
        return iter_rows(folder, endpoint, **kwargs)

    monkeypatch.setattr(live_collector, "_iter_archived_endpoint_rows", tracked_rows)
    if metadata == "recovered_missing":
        from vulnerability_view import live_collector

        original_collect = live_collector._collect_referenced_catalog

        def old_failure(*args, **kwargs):
            original_collect(*args, **kwargs)
            raise RuntimeError("Old collector failed after retaining the missing CVE responses")

        with monkeypatch.context() as patch:
            patch.setattr(live_collector, "_collect_referenced_catalog", old_failure)
            with pytest.raises(RuntimeError, match="Old collector"):
                collection_worker.collect_batch(frozen, store, cache)
        prior_catalog_calls = sum(urlsplit(url).path == "/api/vulnerabilities" for url in requests_sent)
        assert prior_catalog_calls == 4
    if workflow_version >= 2:
        checkpoints = collection_worker.RequestCheckpoints

        def bounded(*args, **kwargs):
            transport = checkpoints(*args, **kwargs)
            transport.request_limit = 1
            transport.findings_interval = 0
            return transport

        monkeypatch.setattr(collection_worker, "RequestCheckpoints", bounded)
    for attempt in range(30):
        result = collection_worker.collect_batch(frozen, store, cache)
        if result["done"]:
            break
    assert result["done"]
    if workflow_version >= 2:
        if metadata != "recovered_missing":
            assert attempt > 0
        assert scans.count("machine_vulnerabilities") == 2
        assert sum(urlsplit(url).path == "/api/machines" for url in requests_sent) == 1
    if metadata == "available":
        assert not any(record.levelno >= logging.ERROR for record in caplog.records)
    if metadata == "recovered_missing":
        assert sum(urlsplit(url).path == "/api/vulnerabilities" for url in requests_sent) == prior_catalog_calls
    original_requests = len(requests_sent)
    assert original_requests > 0
    assert collection_worker.collect_batch(frozen, store, cache)["done"]
    assert len(requests_sent) == original_requests
    processing_stages = []
    for index in range(12):
        activity_root = tmp_path / "activities" / str(index)
        (activity_root / "config").mkdir(parents=True)
        shutil.copyfile(config / "sla-policies.json", activity_root / "config/sla-policies.json")
        monkeypatch.chdir(activity_root)
        prepared = collection_worker.process_batch(frozen, store, cache)
        processing_stages.append(prepared)
        if prepared["done"]:
            break
    assert prepared["done"] is True
    assert len(processing_stages) >= 3
    manifest_name = f"runs/2026/10/23/{frozen['runId']}/manifest.json"
    manifest = store.json(manifest_name)
    assert manifest["schemaVersion"] == 2
    findings = next(item for item in manifest["files"] if item.get("dataset") == "findings")
    rows = json.loads(gzip.decompress(store.read(findings["path"])))
    assert findings["rowCount"] == len(rows) == 1
    assert rows[0]["CveId"] == "CVE-2026-0001"
    assert {"FindingKey", "SlaStatus", "LifecycleReason"} <= rows[0].keys()
    if metadata != "available":
        assert rows[0]["CveMetadataStatus"] == "Unavailable"
        assert rows[0]["CvssScore"] is None
        assert rows[0]["FindingStatus"] == "Open"
        metadata_status = next(row for row in manifest["endpointStatuses"] if row["Endpoint"] == "vulnerabilities")
        assert metadata_status["Status"] == "PartialSuccess"
        assert metadata_status["MissingCveIds"] == ["CVE-2026-0001"]
        catalog = next(item for item in manifest["files"] if item.get("dataset") == "vulnerabilities")
        details = json.loads(gzip.decompress(store.read(catalog["path"])))
        assert details[0]["CveMetadataStatus"] == "Unavailable"
    assert collection_worker.process_batch(frozen, store, cache) == prepared
    assert len(requests_sent) == original_requests
    assert all(not name.startswith("current/") for name in store.uploads)
    # Simulate interruption after immutable uploads but before the stage receipt.
    store.files.pop(f"runs/2026/10/23/{frozen['runId']}/prepared.json")
    monkeypatch.setattr(
        collection_worker, "advance_archived_run",
        lambda *args, **kwargs: pytest.fail("completed processing stages must not run again"),
    )
    retry_root = tmp_path / "retry"
    (retry_root / "config").mkdir(parents=True)
    shutil.copyfile(config / "sla-policies.json", retry_root / "config/sla-policies.json")
    monkeypatch.chdir(retry_root)
    assert collection_worker.process_batch(frozen, store, cache) == prepared
    reference = {
        "runId": frozen["runId"],
        "planPath": f"runs/2026/10/23/{frozen['runId']}/collection-plan.json",
    }
    store.append_json(reference["planPath"], {**frozen, "baselineEtag": None})
    store.history = SimpleNamespace(
        download_blob=lambda name, **kwargs: SimpleNamespace(chunks=lambda: iter([store.read(name)])),
    )
    pointer = Mock()
    pointer.download_blob.side_effect = ResourceNotFoundError("first publication")
    store.current = SimpleNamespace(get_blob_client=lambda name: pointer)
    if workflow_version >= 2:
        index = 0
        while index < prepared["fileCount"]:
            index = verify_batch({**reference, "fileIndex": index}, store)["nextIndex"]
    else:
        for index in range(prepared["fileCount"]):
            verify_file({**reference, "fileIndex": index}, store)
    assert publish_run(reference, store)["published"] is True
    assert json.loads(pointer.upload_blob.call_args.args[0]) == manifest
