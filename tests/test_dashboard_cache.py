import hashlib
import json
import sqlite3
from contextlib import closing
from types import SimpleNamespace

import pytest
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError

from vulnerability_view.dashboard_cache import DashboardDerivedCache
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
                service.blobs[name] = data if isinstance(data, bytes) else data.read()
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
    assert reserve and all(value > 0 for value in reserve)
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


@pytest.mark.parametrize("failure", ["hash", "expanded-size", "identity", "path", "counts"])
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
