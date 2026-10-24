import gzip
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest

from vulnerability_view import dashboard_snapshots, storage_writer
from vulnerability_view.config import Settings
from vulnerability_view.dashboard_snapshots import DashboardCacheFull, DashboardSnapshots, SnapshotExpired
from vulnerability_view.dataset_io import DatasetFormatError, iter_json_rows
from vulnerability_view.storage_writer import download_manifest_dataset_file


def manifest_for(run_id, **datasets):
    return {
        "runId": run_id,
        "snapshotTimeUtc": "2026-10-24T00:59:46Z",
        "complete": True,
        "schemaVersion": 2,
        "files": [
            {"kind": "curated", "dataset": name, "path": f"runs/{run_id}/{name}.json.gz",
             "sha256": hashlib.sha256(content).hexdigest(), "sizeBytes": len(content)}
            for name, content in datasets.items()
        ],
    }


def fake_blob_service(monkeypatch, content):
    calls = []

    class Download:
        def chunks(self):
            for index in range(0, len(content), 7):
                yield content[index:index + 7]

        def readall(self):
            pytest.fail("Large dashboard downloads must stream, not readall()")

    class Blob:
        def download_blob(self):
            return Download()

    class Container:
        def get_blob_client(self, path):
            calls.append(path)
            return Blob()

    class Service:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get_container_client(self, name):
            return Container()

    monkeypatch.setattr("azure.storage.blob.BlobServiceClient", Service)
    return calls


def test_dataset_download_streams_and_verifies_before_exposing_file(monkeypatch, tmp_path):
    content = gzip.compress(b'[{"FindingKey":"a"}]')
    manifest = manifest_for("run-a", findings=content)
    calls = fake_blob_service(monkeypatch, content)
    destination = tmp_path / "snapshot/findings.json.gz"

    assert download_manifest_dataset_file("account", "history", "findings", object(), manifest, destination) == destination
    assert destination.read_bytes() == content
    assert calls == ["runs/run-a/findings.json.gz"]
    assert not list(destination.parent.glob("*.part"))


@pytest.mark.parametrize("failure", ["hash", "short", "long"])
def test_invalid_download_does_not_replace_existing_verified_file(monkeypatch, tmp_path, failure):
    content = gzip.compress(b"[]")
    manifest = manifest_for("run-a", findings=content)
    actual = content
    if failure == "hash":
        manifest["files"][0]["sha256"] = "0" * 64
    elif failure == "short":
        actual = content[:-1]
    else:
        actual = content + b"extra"
    fake_blob_service(monkeypatch, actual)
    destination = tmp_path / "findings.json.gz"
    destination.write_bytes(b"verified-old-file")

    with pytest.raises(ValueError, match="mismatch"):
        download_manifest_dataset_file("account", "history", "findings", object(), manifest, destination)

    assert destination.read_bytes() == b"verified-old-file"
    assert not list(tmp_path.glob("*.part"))


class FakeEngine:
    def __init__(self, root, snapshot_id, snapshot_time, rows):
        self.root = root
        self.rows = rows


def azure_snapshots(monkeypatch, tmp_path, pointer, **kwargs):
    monkeypatch.setattr(dashboard_snapshots, "DashboardQueryEngine", FakeEngine)
    return DashboardSnapshots(
        Settings(dashboard_data_source="azure", storage_account_name="account"),
        tmp_path, lambda: pointer[0], object,
        lambda *args: {"policyVersion": args[-1]["runId"], "policies": []},
        **kwargs,
    )


def test_snapshot_creation_is_metadata_only_and_old_pointer_is_pinned(monkeypatch, tmp_path):
    content = gzip.compress(b'[{"FindingKey":"a"}]')
    pointer = [manifest_for("run-a", findings=content)]
    snapshots = azure_snapshots(monkeypatch, tmp_path, pointer)
    calls = []

    def download(account, container, name, credential, manifest, destination):
        calls.append(manifest["runId"])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)

    monkeypatch.setattr(dashboard_snapshots, "download_manifest_dataset_file", download)
    try:
        first = snapshots.current()
        assert calls == []
        pointer[0] = manifest_for("run-b", findings=content)
        second = snapshots.current()
        assert second.id != first.id
        with snapshots.acquire(first.id) as snapshot:
            assert list(snapshot.engine.rows("findings")) == [{"FindingKey": "a"}]
            assert snapshot.policy["policyVersion"] == "run-a"
        assert calls == ["run-a"]
    finally:
        snapshots.close()


def test_current_snapshot_can_be_hydrated_by_another_server_worker(monkeypatch, tmp_path):
    pointer = [manifest_for("run-a")]
    first = azure_snapshots(monkeypatch, tmp_path, pointer)
    second = azure_snapshots(monkeypatch, tmp_path, pointer)
    try:
        selected = first.current()
        with second.acquire(selected.id) as hydrated:
            assert hydrated.id == selected.id
            assert hydrated.manifest == selected.manifest
    finally:
        first.close()
        second.close()


def test_cache_evicts_only_idle_snapshot_and_expiry_is_explicit(monkeypatch, tmp_path):
    pointer = [manifest_for("run-a")]
    snapshots = azure_snapshots(monkeypatch, tmp_path, pointer)
    try:
        first = snapshots.current()
        with snapshots.acquire(first.id):
            pointer[0] = manifest_for("run-b")
            second = snapshots.current()
            pointer[0] = manifest_for("run-c")
            third = snapshots.current()
            assert first.root.exists()
            assert third.root.exists()
            assert not second.root.exists()
            with pytest.raises(SnapshotExpired):
                with snapshots.acquire(second.id):
                    pytest.fail("Expired snapshot was acquired")
        assert len(snapshots._entries) == 2
    finally:
        snapshots.close()


def test_cache_refuses_eviction_when_both_snapshots_are_busy(monkeypatch, tmp_path):
    pointer = [manifest_for("run-a")]
    snapshots = azure_snapshots(monkeypatch, tmp_path, pointer)
    try:
        first = snapshots.current()
        pointer[0] = manifest_for("run-b")
        second = snapshots.current()
        with snapshots.acquire(first.id), snapshots.acquire(second.id):
            pointer[0] = manifest_for("run-c")
            with pytest.raises(DashboardCacheFull, match="busy"):
                snapshots.current()
    finally:
        snapshots.close()


def test_independent_dataset_downloads_do_not_share_a_global_lock(monkeypatch, tmp_path):
    content = gzip.compress(b"[]")
    pointer = [manifest_for("run-a", findings=content, devices=content)]
    snapshots = azure_snapshots(monkeypatch, tmp_path, pointer)
    waiting = Event()
    release = Event()

    def download(account, container, name, credential, manifest, destination):
        if name == "findings":
            waiting.set()
            assert release.wait(5)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)

    monkeypatch.setattr(dashboard_snapshots, "download_manifest_dataset_file", download)
    try:
        snapshot = snapshots.current()
        with ThreadPoolExecutor(max_workers=2) as pool:
            findings = pool.submit(list, snapshot.engine.rows("findings"))
            assert waiting.wait(5)
            try:
                devices = pool.submit(list, snapshot.engine.rows("devices"))
                assert devices.result(timeout=3) == []
            finally:
                release.set()
            assert findings.result(timeout=3) == []
    finally:
        snapshots.close()


def test_local_file_change_requires_a_new_snapshot(monkeypatch, tmp_path):
    monkeypatch.setattr(dashboard_snapshots, "DashboardQueryEngine", FakeEngine)
    directory = tmp_path / "dashboard/data"
    directory.mkdir(parents=True)
    path = directory / "findings.json"
    path.write_text('[{"FindingKey":"a"}]')
    snapshots = DashboardSnapshots(Settings(dashboard_data_source="local"), tmp_path, lambda: {}, object, lambda: {})
    try:
        first = snapshots.current()
        with snapshots.acquire(first.id):
            assert list(first.engine.rows("findings")) == [{"FindingKey": "a"}]
        path.write_text('[{"FindingKey":"different"}]')
        with pytest.raises(SnapshotExpired, match="changed"):
            with snapshots.acquire(first.id):
                pytest.fail("Changed local data was accepted")
        assert snapshots.current().id != first.id
    finally:
        snapshots.close()


def test_local_disk_budget_is_enforced(monkeypatch, tmp_path):
    pointer = [manifest_for("run-a")]
    snapshots = azure_snapshots(monkeypatch, tmp_path, pointer, max_bytes=10)
    try:
        snapshot = snapshots.current()
        (snapshot.root / "index.sqlite").write_bytes(b"01234567890")
        with pytest.raises(DashboardCacheFull, match="budget"):
            with snapshots.acquire(snapshot.id):
                pytest.fail("Oversized cache was accepted")
    finally:
        snapshots.close()


def test_disk_pressure_evicts_idle_history_before_active_index_growth(monkeypatch, tmp_path):
    pointer = [manifest_for("run-a")]
    snapshots = azure_snapshots(monkeypatch, tmp_path, pointer, max_bytes=20)
    try:
        first = snapshots.current()
        (first.root / "index.sqlite").write_bytes(b"12345678")
        pointer[0] = manifest_for("run-b")
        second = snapshots.current()
        (second.root / "index.sqlite").write_bytes(b"12345678")
        with snapshots.acquire(second.id):
            snapshots._check_space(extra=5)
            assert not first.root.exists()
            assert second.root.exists()
    finally:
        snapshots.close()


@pytest.mark.parametrize("content", ['{"items":[]}', '[1]', '["not-a-row"]', ""])
def test_streaming_reader_rejects_invalid_dataset_shapes(tmp_path, content):
    path = tmp_path / "findings.json"
    path.write_text(content)
    with pytest.raises(DatasetFormatError):
        list(iter_json_rows(path))


def test_streaming_reader_accepts_whitespace_empty_and_gzip_arrays(tmp_path):
    plain = tmp_path / "plain.json"
    plain.write_text(" " * 5000 + "[]")
    compressed = tmp_path / "rows.json.gz"
    compressed.write_bytes(gzip.compress(b'[{"count":1.5}]'))
    assert list(iter_json_rows(plain)) == []
    assert list(iter_json_rows(compressed)) == [{"count": 1.5}]
