import gzip
import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import urlsplit
import shutil

import pytest
import requests
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError

from vulnerability_view import collection_worker
from vulnerability_view.collection_transport import CheckpointYield, current_checkpoints
from vulnerability_view.config import Settings
from vulnerability_view.collection_workflow import publish_run, verify_file
from dataclasses import asdict


class WorkerStore:
    def __init__(self):
        self.files = {}
        self.uploads = []
        self.downloads = 0

    def json(self, name):
        return json.loads(self.read(name))

    def read(self, name):
        if name not in self.files:
            raise ResourceNotFoundError("missing")
        return self.files[name]

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


def plan():
    return {
        "runId": "live-20261023T160000Z", "snapshotUtc": "2026-10-23T16:00:00+00:00",
        "settings": asdict(Settings()), "baseline": None,
        "collection": "full", "enrichment": "targeted", "pageSize": 2500,
    }


def test_worker_collect_uses_frozen_snapshot_and_yields_small_progress(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(collection_worker, "create_credential", lambda *args: object())
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
    }
    assert received["snapshot"] == datetime(2026, 10, 23, 16, tzinfo=UTC)
    assert received["raw_only"] is True
    assert received["cve_batch_size"] == 100
    assert received["page_size"] == 2500


def test_collection_logs_only_throttled_endpoint_counts_and_errors(monkeypatch, tmp_path, caplog):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(collection_worker, "create_credential", lambda *args: object())
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
    messages = [record.getMessage() for record in caplog.records]
    assert messages == [
        "[machines] starting download",
        "[machines] 200 rows downloaded; more data available",
        "[machines] complete: 200 rows",
        "[machine_vulnerabilities] starting device-scoped collection for 200 machines",
        "[machine_vulnerabilities] machines complete: 50/200; 100 findings",
        "[machine_vulnerabilities] failed: permission denied",
        "[collection] paused: HTTP 503; retry in 30s; [machine_vulnerabilities] failed: permission denied",
    ]
    assert caplog.records[-2].levelno == logging.ERROR
    assert result["lastProgress"] == "[machine_vulnerabilities] failed: permission denied"


def test_completed_collection_does_not_call_defender_again(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(collection_worker, "create_credential", lambda *args: object())
    calls = []

    def collect(*args, **kwargs):
        calls.append(kwargs)
        raw = tmp_path / "output/raw" / plan()["runId"]
        raw.mkdir(parents=True)
        (raw / "machines-page-000001.json.gz").write_bytes(gzip.compress(b'{"value":[]}'))
        return {}, [{"Endpoint": "machines", "Status": "Success"}]

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
    frozen["baseline"] = {"files": [{
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


def test_complete_worker_flow_preserves_tables_and_persists_retryable_bundle(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    credential = SimpleNamespace(get_token=lambda *args: SimpleNamespace(token="test-only-token"))
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
        "/api/vulnerabilities": [{"id": "CVE-2026-0001", "severity": "High"}],
    }
    requests_sent = []

    def get(session, url, **kwargs):
        requests_sent.append(url)
        response = requests.Response()
        response.url = url
        response.status_code = 200
        response._content = json.dumps({"value": payloads.get(urlsplit(url).path, [])}).encode()
        return response

    monkeypatch.setattr(requests.Session, "get", get)
    config = tmp_path / "config"
    config.mkdir()
    shutil.copyfile(Path(__file__).resolve().parents[1] / "config/sla-policies.json", config / "sla-policies.json")
    store = WorkerStore()
    frozen = plan()
    cache = tmp_path / "cache"
    assert collection_worker.collect_batch(frozen, store, cache)["done"]
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
        download_blob=lambda name: SimpleNamespace(chunks=lambda: iter([store.read(name)])),
    )
    pointer = Mock()
    pointer.download_blob.side_effect = ResourceNotFoundError("first publication")
    store.current = SimpleNamespace(get_blob_client=lambda name: pointer)
    for index in range(prepared["fileCount"]):
        verify_file({**reference, "fileIndex": index}, store)
    assert publish_run(reference, store)["published"] is True
    assert json.loads(pointer.upload_blob.call_args.args[0]) == manifest
