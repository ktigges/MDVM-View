import gzip
import hashlib
import json
import logging
import os
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError

from vulnerability_view import dashboard_cache
from vulnerability_view.dashboard_cache import CHUNK_BYTES, DashboardDerivedCache
from vulnerability_view.storage_writer import DatasetIntegrityError
from test_dashboard_queries import datasets, engine
from test_dashboard_read_model import canonical


class Service:
    def __init__(self):
        self.blobs = {}
        self.writes = []
        self.fail_upload = False

    def __call__(self, **kwargs):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def get_container_client(self, name):
        assert name == "viewer-cache"
        return self

    def get_blob_client(self, name):
        service = self

        class Blob:
            def download_blob(self, **kwargs):
                if name not in service.blobs:
                    raise ResourceNotFoundError("missing")
                content = service.blobs[name]
                return SimpleNamespace(chunks=lambda: (
                    content[offset:offset + 137] for offset in range(0, len(content), 137)
                ))

            def upload_blob(self, data, *, overwrite, **kwargs):
                assert overwrite is False
                if service.fail_upload:
                    raise OSError("upload interrupted")
                if name in service.blobs:
                    raise ResourceExistsError("already exists")
                service.blobs[name] = (
                    data if isinstance(data, bytes) else data.read() if hasattr(data, "read") else b"".join(data)
                )
                service.writes.append(name)

            def get_blob_properties(self):
                return SimpleNamespace(size=len(service.blobs[name]))

        return Blob()

    def list_blobs(self, *, name_starts_with, **kwargs):
        return (
            SimpleNamespace(name=name) for name in sorted(self.blobs)
            if name.startswith(name_starts_with)
        )


def cache(service):
    return DashboardDerivedCache("account", "viewer-cache", object, service_factory=service)


def test_restart_restores_exact_indexes_and_aggregates_without_source_rows(tmp_path):
    service = Service()
    original = engine(tmp_path / "old", datasets(120))
    original.read_model.prepare({})
    expected = original.query({"view": "recommendations", "filters": {"newPeriodFilter": True}})
    primary = hashlib.sha256(original.path.read_bytes()).hexdigest()
    reserve = []
    cache(service).publish(original, {}, reserve=reserve.append)
    assert reserve == [original.path.stat().st_size, 0]
    assert hashlib.sha256(original.path.read_bytes()).hexdigest() == primary
    before = len(service.writes)
    cache(service).publish(original, {})
    assert len(service.writes) == before

    def unavailable(name):
        pytest.fail(f"Restart must not reload source dataset {name}")

    restored = engine(tmp_path / "new", datasets(0))
    restored._rows = unavailable
    assert cache(service).restore(restored, {}, reserve=reserve.append)
    actual = restored.query({"view": "recommendations", "filters": {"newPeriodFilter": True}})
    assert actual["metadata"]["readModel"] == "aggregate"
    assert canonical(actual) == canonical(expected)
    assert not list(restored.root.glob("*.restoring"))
    assert not list(restored.root.glob("*.cached.gz"))


def test_missing_cache_is_explicit_and_never_touches_other_containers(tmp_path, caplog):
    e = engine(tmp_path)
    assert not cache(Service()).restore(e, {})
    for protected in ("history", "current", "workflow"):
        with pytest.raises(ValueError, match="separate"):
            DashboardDerivedCache("account", protected, object, protected_containers=(protected,))


def test_changed_policy_reuses_primary_without_reusing_wrong_aggregates(tmp_path):
    service = Service()
    original = engine(tmp_path / "old", datasets(20))
    original.read_model.prepare({})
    cache(service).publish(original, {})
    restored = engine(tmp_path / "new", datasets(0))
    changed = {"slaPolicy": {"policyVersion": "changed"}}
    assert cache(service).restore(restored, changed)
    assert restored.indexed_rows()["findings"] == 20
    assert not restored.read_model.path(changed).exists()


@pytest.mark.parametrize("failure", [
    "hash", "expanded-size", "expanded-overflow", "compressed-size", "compressed-overflow",
    "identity", "path", "counts",
])
def test_invalid_cache_fails_without_replacing_primary(tmp_path, failure):
    service = Service()
    original = engine(tmp_path / "old", datasets(20))
    original.read_model.prepare({})
    cache(service).publish(original, {})
    key = next(name for name in service.blobs if name.endswith("/primary/complete.json"))
    descriptor = json.loads(service.blobs[key])
    if failure == "hash":
        descriptor["sha256"] = "0" * 64
    elif failure == "expanded-size":
        descriptor["bytes"] += 1
    elif failure == "expanded-overflow":
        descriptor["bytes"] -= 1
    elif failure == "compressed-size":
        descriptor["compressedBytes"] += 1
    elif failure == "compressed-overflow":
        descriptor["compressedBytes"] -= 1
    elif failure == "identity":
        descriptor["prefix"] = "other"
    elif failure == "counts":
        descriptor["datasets"]["findings"] += 1
    else:
        descriptor["blob"] = "../../history/evidence"
    service.blobs[key] = json.dumps(descriptor).encode()
    restored = engine(tmp_path / "new", datasets(0))
    before = restored.path.read_bytes()
    with pytest.raises(DatasetIntegrityError):
        cache(service).restore(restored, {})
    assert restored.path.read_bytes() == before
    assert not list(restored.root.glob("*.restoring"))
    assert not list(restored.root.glob("*.cached.gz"))


@pytest.mark.parametrize("chunk_bytes", [1, 137, 4 * CHUNK_BYTES])
def test_restore_streams_exact_bytes_without_compressed_disk_copy(tmp_path, monkeypatch, caplog, chunk_bytes):
    service = Service()
    content = os.urandom(2 * CHUNK_BYTES + 257) if chunk_bytes > 1 else b"small stream" * 100
    # Concatenated gzip members and padding are accepted by the existing cache format.
    compressed = gzip.compress(content[:100]) + gzip.compress(content[100:]) + b"\0" * 20
    prefix = "cache/primary"
    item = {
        "prefix": prefix, "blob": f"{prefix}/{'a' * 32}.sqlite3.gz",
        "bytes": len(content), "compressedBytes": len(compressed),
        "sha256": hashlib.sha256(compressed).hexdigest(),
    }
    service.blobs[prefix + "/complete.json"] = json.dumps(item).encode()
    destination = tmp_path / "restored.sqlite3"
    get_blob_client = service.get_blob_client
    open_file = Path.open
    observations = []

    def checked_open(path, *args, **kwargs):
        assert not path.name.endswith(".cached.gz")
        return open_file(path, *args, **kwargs)

    def checked_blob(name):
        blob = get_blob_client(name)
        if name == item["blob"]:
            def chunks():
                for offset in range(0, len(compressed), chunk_bytes):
                    temporary = destination.with_suffix(".restoring")
                    observations.append(temporary.exists() and temporary.stat().st_size > 0)
                    assert not destination.exists()
                    yield compressed[offset:offset + chunk_bytes]

            def download_blob(**kwargs):
                assert kwargs == {"max_concurrency": 1}
                return SimpleNamespace(chunks=chunks)

            blob.download_blob = download_blob
        return blob

    monkeypatch.setattr(Path, "open", checked_open)
    monkeypatch.setattr(service, "get_blob_client", checked_blob)
    reserved = []
    validated = []

    def validate(path, descriptor):
        assert not destination.exists()
        assert path.read_bytes() == content
        assert descriptor == item
        validated.append(path)

    with caplog.at_level(logging.INFO, logger="vulnerability_view.dashboard_startup"):
        assert cache(service)._restore_file(
            service, prefix, destination, "primary", len(compressed) + len(content),
            validate, reserved.append,
        )
    assert destination.read_bytes() == content
    assert reserved == [len(content)]
    assert validated == [destination.with_suffix(".restoring")]
    assert not list(tmp_path.glob("*.restoring"))
    assert f"compressedBytes={len(compressed)} expandedBytes={len(content)}" in caplog.text
    assert "downloadSeconds=" in caplog.text
    assert "decodeWriteSeconds=" in caplog.text
    if chunk_bytes == 137:
        assert any(observations)


def test_restore_timings_separate_download_from_decode_and_write(tmp_path, monkeypatch, caplog):
    service = Service()
    content = b"restored content"
    compressed = gzip.compress(content)
    prefix = "cache/primary"
    item = {
        "prefix": prefix, "blob": f"{prefix}/{'a' * 32}.sqlite3.gz",
        "bytes": len(content), "compressedBytes": len(compressed),
        "sha256": hashlib.sha256(compressed).hexdigest(),
    }
    service.blobs[prefix + "/complete.json"] = json.dumps(item).encode()
    get_blob_client = service.get_blob_client
    open_file = Path.open
    clock = [0.0]
    monkeypatch.setattr(dashboard_cache, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    def timed_blob(name):
        blob = get_blob_client(name)
        if name == item["blob"]:
            def chunks():
                clock[0] += 3
                yield compressed
                clock[0] += 3

            def download_blob(**kwargs):
                clock[0] += 2
                return SimpleNamespace(chunks=chunks)

            blob.download_blob = download_blob
        return blob

    @contextmanager
    def timed_output(path, *args, **kwargs):
        with open_file(path, *args, **kwargs) as output:
            def write(chunk):
                assert len(chunk) <= CHUNK_BYTES
                clock[0] += 5
                return output.write(chunk)

            yield SimpleNamespace(write=write)

    def timed_open(path, *args, **kwargs):
        if path.suffix == ".restoring":
            return timed_output(path, *args, **kwargs)
        return open_file(path, *args, **kwargs)

    monkeypatch.setattr(service, "get_blob_client", timed_blob)
    monkeypatch.setattr(Path, "open", timed_open)
    destination = tmp_path / "restored.sqlite3"
    with caplog.at_level(logging.INFO, logger="vulnerability_view.dashboard_startup"):
        assert cache(service)._restore_file(
            service, prefix, destination, "primary", 1024, lambda path, descriptor: None, None,
        )
    assert destination.read_bytes() == content
    assert "downloadSeconds=8.000 decodeWriteSeconds=5.000" in caplog.text


@pytest.mark.parametrize("failure", ["interrupted", "truncated", "gzip-crc", "sqlite"])
def test_stream_failure_preserves_existing_index_and_cleans_temporary_files(tmp_path, monkeypatch, failure):
    service = Service()
    original = engine(tmp_path / "old", datasets(20))
    original.read_model.prepare({})
    cache(service).publish(original, {})
    key = next(name for name in service.blobs if name.endswith("/primary/complete.json"))
    item = json.loads(service.blobs[key])
    compressed = service.blobs[item["blob"]]
    if failure == "truncated":
        compressed = compressed[:-5]
    elif failure == "gzip-crc":
        compressed = compressed[:-8] + bytes([compressed[-8] ^ 1]) + compressed[-7:]
    elif failure == "sqlite":
        compressed = gzip.compress(b"x" * item["bytes"])
    if failure != "interrupted":
        item["compressedBytes"] = len(compressed)
        item["sha256"] = hashlib.sha256(compressed).hexdigest()
        service.blobs[item["blob"]] = compressed
        service.blobs[key] = json.dumps(item).encode()
    else:
        get_blob_client = service.get_blob_client

        def interrupted_blob(name):
            blob = get_blob_client(name)
            if name == item["blob"]:
                def chunks():
                    yield compressed[:len(compressed) // 2]
                    raise OSError("download interrupted")

                blob.download_blob = lambda **kwargs: SimpleNamespace(chunks=chunks)
            return blob

        monkeypatch.setattr(service, "get_blob_client", interrupted_blob)
    restored = engine(tmp_path / "new", datasets(0))
    before = restored.path.read_bytes()
    expected_error = {
        "interrupted": OSError, "truncated": EOFError,
        "gzip-crc": gzip.BadGzipFile, "sqlite": sqlite3.DatabaseError,
    }[failure]
    with pytest.raises(expected_error):
        cache(service).restore(restored, {})
    assert restored.path.read_bytes() == before
    assert not list(restored.root.glob("*.restoring"))
    assert not list(restored.root.glob("*.cached.gz"))


def test_interrupted_upload_does_not_publish_a_completion_marker(tmp_path):
    service = Service()
    e = engine(tmp_path)
    e.read_model.prepare({})
    service.fail_upload = True
    with pytest.raises(OSError, match="upload interrupted"):
        cache(service).publish(e, {})
    assert not any(name.endswith("/complete.json") for name in service.blobs)
    assert not list(e.root.glob("*.cache-copy"))
    assert not list(e.root.glob("*.publishing.gz"))


def test_publication_reserves_only_backup_space_outside_retained_snapshots(tmp_path, monkeypatch):
    service = Service()
    e = engine(tmp_path / "retained")
    e.read_model.prepare({})
    c = cache(service)
    original_upload = c._upload_file
    sources = []

    def upload(container, prefix, source, item, limit):
        assert not source.is_relative_to(e.root) or source == e.read_model.path({})
        assert not list(e.root.glob("*.cache-copy"))
        sources.append(source)
        original_upload(container, prefix, source, item, limit)

    monkeypatch.setattr(c, "_upload_file", upload)
    reserved = []
    c.publish(e, {}, reserve=reserved.append)
    assert reserved == [e.path.stat().st_size, 0]
    assert not sources[0].exists()

    source = e.root / "products.sqlite3"
    extra_database(source, "first")
    reserved.clear()
    c.publish_extra(
        e, "products-v1", source, limit=1024**2, validate=validate_extra, reserve=reserved.append,
    )
    assert reserved == [source.stat().st_size]
    assert not sources[-1].exists()


def test_upload_streams_bounded_gzip_chunks_without_local_compressed_file(tmp_path, monkeypatch):
    service = Service()
    source = tmp_path / "index.sqlite3"
    content = os.urandom(3 * CHUNK_BYTES)
    source.write_bytes(content)
    item = {"blob": "cache/artifact.sqlite3.gz", "bytes": len(content), "prefix": "cache"}
    get_blob_client = service.get_blob_client
    sizes = []

    def checked_blob(name):
        blob = get_blob_client(name)
        upload = blob.upload_blob
        if name == item["blob"]:
            def checked_upload(data, **kwargs):
                assert not hasattr(data, "read")

                def chunks():
                    for chunk in data:
                        assert not list(tmp_path.glob("*.publishing.gz"))
                        sizes.append(len(chunk))
                        yield chunk

                upload(chunks(), **kwargs)

            blob.upload_blob = checked_upload
        return blob

    monkeypatch.setattr(service, "get_blob_client", checked_blob)
    cache(service)._upload_file(service, "cache", source, item, len(content) + CHUNK_BYTES)
    uploaded = service.blobs[item["blob"]]
    assert gzip.decompress(uploaded) == content
    assert item["sha256"] == hashlib.sha256(uploaded).hexdigest()
    assert item["compressedBytes"] == len(uploaded)
    assert len(sizes) >= 3
    assert max(sizes) <= 2 * CHUNK_BYTES
    assert not list(tmp_path.glob("*.publishing.gz"))


def test_streamed_compressed_size_limit_does_not_publish_completion(tmp_path):
    service = Service()
    source = tmp_path / "index.sqlite3"
    source.write_bytes(os.urandom(CHUNK_BYTES))
    item = {"blob": "cache/artifact.sqlite3.gz", "bytes": CHUNK_BYTES, "prefix": "cache"}
    with pytest.raises(DatasetIntegrityError, match="compressed artifact exceeds"):
        cache(service)._upload_file(service, "cache", source, item, 1024)
    assert not service.writes


def extra_database(path, value):
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("CREATE TABLE IF NOT EXISTS payload(value)")
        db.execute("DELETE FROM payload")
        db.execute("INSERT INTO payload VALUES(?)", (value,))


def validate_extra(path):
    with closing(sqlite3.connect(path)) as db:
        assert db.execute("PRAGMA quick_check").fetchall() == [("ok",)]
        assert db.execute("SELECT value FROM payload").fetchone() is not None


def test_extra_artifacts_restore_latest_immutable_product_generation(tmp_path):
    service = Service()
    e = engine(tmp_path / "engine")
    source = tmp_path / "products.sqlite3"
    extra_database(source, "first")
    c = cache(service)
    c.publish_extra(e, "products-v1", source, limit=1024**2, validate=validate_extra)
    original = dict(service.blobs)
    extra_database(source, "second")
    c.publish_extra(e, "products-v1", source, limit=1024**2, validate=validate_extra)
    assert all(service.blobs[name] == data for name, data in original.items())
    target = tmp_path / "restored.sqlite3"
    assert c.restore_extra(e, "products-v1", target, limit=1024**2, validate=validate_extra)
    with closing(sqlite3.connect(target)) as db:
        assert db.execute("SELECT value FROM payload").fetchone()[0] == "second"
    assert len([name for name in service.blobs if name.endswith("/complete.json")]) == 2


@pytest.mark.parametrize("field,value", [
    ("snapshotId", "other"), ("queryIndexVersion", -1), ("kind", "history-v10"), ("identity", "other"),
])
def test_extra_artifact_identity_failure_never_installs_it(tmp_path, field, value):
    service = Service()
    e = engine(tmp_path / "engine")
    source = tmp_path / "search.sqlite3"
    extra_database(source, "evidence")
    c = cache(service)
    c.publish_extra(e, "search-v1", source, identity="a" * 64, limit=1024**2, validate=validate_extra)
    key = next(name for name in service.blobs if name.endswith("/complete.json"))
    item = json.loads(service.blobs[key])
    item[field] = value
    service.blobs[key] = json.dumps(item).encode()
    target = tmp_path / "restored.sqlite3"
    with pytest.raises(DatasetIntegrityError, match="identity"):
        c.restore_extra(e, "search-v1", target, identity="a" * 64, limit=1024**2, validate=validate_extra)
    assert not target.exists()
    assert not list(tmp_path.glob("*.restoring"))
    assert not list(tmp_path.glob("*.cached.gz"))


def test_completed_search_artifact_is_not_republished(tmp_path):
    service = Service()
    e = engine(tmp_path / "engine")
    source = tmp_path / "search.sqlite3"
    extra_database(source, "evidence")
    c = cache(service)
    for _ in range(2):
        c.publish_extra(e, "search-v1", source, identity="a" * 64, limit=1024**2, validate=validate_extra)
    assert len(service.writes) == 2
