import gzip
import json
import time
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import pytest

from vulnerability_view.dashboard_index import (
    MAX_INDEX_BYTES, compatible_index, restore_dashboard_index,
)
from vulnerability_view.dashboard_queries import (
    DashboardQueryEngine, PREPARED_VIEWS, QUERY_INDEX_BUILD_CACHE_KIB,
)
from vulnerability_view import dashboard_queries
from vulnerability_view.dashboard_snapshots import DashboardSnapshots
from vulnerability_view.config import Settings
from vulnerability_view.storage_writer import DATASET_FILES, DatasetIntegrityError, create_run_bundle
from test_dashboard_queries import SNAPSHOT, datasets


def test_index_build_reuses_timestamp_projections_and_reports_real_progress(tmp_path, monkeypatch):
    data = datasets(600)
    parsed = []
    original = dashboard_queries._timestamp

    def observe(value):
        parsed.append(value)
        return original(value)

    engine = DashboardQueryEngine(tmp_path, "progress-build", SNAPSHOT, lambda name: iter(data.get(name, [])))
    monkeypatch.setattr(dashboard_queries, "_timestamp", observe)
    progress = []
    engine.build_index({"findings": 600}, progress_callback=progress.append)
    assert len(parsed) < 20
    assert any("dataset=findings" in message and "rows=600" in message for message in progress)
    assert any("step=build-query-index" in message and "findings_recommendation_rank" in message for message in progress)
    assert list(engine.iter_dataset("findings")) == data["findings"]


def test_index_fact_projection_does_not_reparse_row_json_in_sqlite(tmp_path, monkeypatch):
    data = datasets(4)
    engine = DashboardQueryEngine(tmp_path, "direct-build", SNAPSHOT, lambda name: iter(data.get(name, [])))
    original = engine._connect
    inserts = []

    @contextmanager
    def observe(*args, **kwargs):
        with original(*args, **kwargs) as db:
            db.set_trace_callback(lambda sql: inserts.append(sql) if sql.startswith("INSERT") else None)
            yield db

    monkeypatch.setattr(engine, "_connect", observe)
    engine.build_index({"findings": 4})
    assert inserts
    assert not any("json_extract" in sql or "json_each" in sql for sql in inserts)
    assert list(engine.iter_dataset("findings")) == data["findings"]


def test_direct_fact_projection_preserves_json_extraction_types(tmp_path):
    values = [None, "", 0, "12.5", True, False, "MÜNCHEN", ["x", 1], {"nested": 2}, 1.0, 2**70, ("x",)]
    data = datasets(len(values))
    for row, value in zip(data["findings"], values, strict=True):
        row.update(DeviceId=value, DeviceName=value, PriorityScore=value, Status=value)
    engine = DashboardQueryEngine(tmp_path, "typed-build", SNAPSHOT, lambda name: iter(data.get(name, [])))
    engine.build_index({"findings": len(values)})
    with engine._connect() as db:
        actual = db.execute(
            "SELECT DeviceId,typeof(DeviceId),DeviceName,typeof(DeviceName),"
            "PriorityScore,typeof(PriorityScore),Status,typeof(Status) FROM findings ORDER BY _rowid"
        ).fetchall()
        for result, source in zip(actual, data["findings"], strict=True):
            expected = db.execute("""
                SELECT json_extract(data,'$.DeviceId'),typeof(json_extract(data,'$.DeviceId')),
                    json_extract(data,'$.DeviceName'),typeof(json_extract(data,'$.DeviceName')),
                    CAST(json_extract(data,'$.PriorityScore') AS REAL),
                    typeof(CAST(json_extract(data,'$.PriorityScore') AS REAL)),
                    json_extract(data,'$.Status'),typeof(json_extract(data,'$.Status'))
                FROM (SELECT ? data)
            """, (json.dumps(source, ensure_ascii=False, separators=(",", ":")),)).fetchone()
            assert tuple(result) == tuple(expected)


def test_index_construction_bounds_cache_without_reducing_query_cache(tmp_path, monkeypatch):
    data = datasets(4)
    engine = DashboardQueryEngine(tmp_path, "bounded-build", SNAPSHOT, lambda name: iter(data.get(name, [])))
    original = engine._connect
    operations = []

    @contextmanager
    def observe(*args, **kwargs):
        with original(*args, **kwargs) as db:
            cache = db.execute("PRAGMA cache_size").fetchone()[0]

            def trace(sql):
                nonlocal cache
                if sql.startswith("PRAGMA cache_size="):
                    cache = int(sql.partition("=")[2])
                elif sql.startswith(("CREATE INDEX", "ANALYZE")):
                    operations.append((sql, cache))

            db.set_trace_callback(trace)
            yield db

    monkeypatch.setattr(engine, "_connect", observe)
    engine.build_index({"findings": 4})
    assert operations
    assert all(cache == -QUERY_INDEX_BUILD_CACHE_KIB for _, cache in operations), operations
    assert any(sql == "ANALYZE shared_values" for sql, _ in operations)
    with engine._connect() as db:
        assert db.execute("PRAGMA cache_size").fetchone()[0] == -8192
    assert engine.indexed_rows() == {"findings": 4}


def bundle_for(root, count=237):
    root.mkdir(exist_ok=True)
    raw = root / "live-20261024T120000Z"
    raw.mkdir()
    policy = root / "sla-policies.json"
    policy.write_text('{"policies":[]}')
    data = datasets(count)
    bundle = create_run_bundle(
        raw, {key: data.get(name, []) for key, name in DATASET_FILES.items()},
        [], policy, root / "history",
    )
    return bundle, json.loads((bundle / "manifest.json").read_text()), data


def restored_engine(root, bundle, manifest):
    def unexpected(name):
        raise AssertionError(f"Restored queries must not read curated data: {name}")

    engine = DashboardQueryEngine(root, "restored-snapshot", SNAPSHOT, unexpected)
    item = compatible_index(manifest)
    assert item is not None
    restore_dashboard_index(bundle / "index" / Path(item["path"]).name, engine, manifest, item)

    def history():
        item = compatible_index(manifest, "history")
        assert item is not None
        return restore_dashboard_index(
            bundle / "index" / Path(item["path"]).name, engine, manifest, item,
            destination=engine.root / "history.sqlite3",
        )

    engine.history_index_loader = history
    return engine


def test_restored_index_preserves_all_views_filters_pages_details_and_exports(tmp_path):
    bundle, manifest, data = bundle_for(tmp_path / "source")
    restored = restored_engine(tmp_path / "restored", bundle, manifest)
    assert "finding-events" not in restored.indexed_rows()
    assert not (restored.root / "history.sqlite3").exists()
    baseline = DashboardQueryEngine(
        tmp_path / "baseline", "restored-snapshot", SNAPSHOT, lambda name: iter(data.get(name, [])),
    )
    requests = [{"view": view} for view in PREPARED_VIEWS]
    requests += [
        {"view": "overview", "page": 2, "limit": 100},
        {"view": "overview", "mode": "cves"},
        {"view": "overview", "filters": {"search": "finding-0001"}},
        {"view": "priority", "filters": {"severity": "High"}},
        {"view": "detail", "selection": {"type": "machine", "id": "device-1"}},
    ]
    for payload in requests:
        assert restored.query(payload) == baseline.query(payload)
    assert (restored.root / "history.sqlite3").is_file()
    assert restored.dataset_info("finding-events") == baseline.dataset_info("finding-events")
    for mode in ("findings", "cves"):
        payload = {"view": "overview", "mode": mode}
        assert list(restored.iter_export(payload)) == list(baseline.iter_export(payload))
    assert len(list((bundle / "index").iterdir())) == 2
    assert not list(bundle.glob("query-index-*"))
    assert not list((tmp_path / "restored").glob("*.restoring"))


@pytest.mark.parametrize("change", ["source", "counts", "identity", "oversize", "multiple"])
def test_invalid_index_metadata_is_not_silently_accepted(tmp_path, change):
    _, manifest, _ = bundle_for(tmp_path / "source", 4)
    item = next(entry for entry in manifest["files"] if entry["kind"] == "index")
    if change == "source":
        manifest["files"][0]["sha256"] = "0" * 64
    elif change == "counts":
        manifest["files"][0]["rowCount"] += 1
    elif change == "identity":
        item["sourceIdentity"] = "0" * 64
    elif change == "oversize":
        item["uncompressedBytes"] = MAX_INDEX_BYTES + 1
    else:
        manifest["files"].append(deepcopy(item))
    with pytest.raises(DatasetIntegrityError):
        compatible_index(manifest)


def test_old_and_incompatible_runs_rebuild_explicitly(tmp_path, caplog):
    _, manifest, _ = bundle_for(tmp_path / "source", 4)
    next(entry for entry in manifest["files"] if entry["kind"] == "index")["formatVersion"] = -1
    assert compatible_index(manifest) is None
    assert "rebuilding" in caplog.text
    manifest["files"] = [entry for entry in manifest["files"] if entry["kind"] != "index"]
    assert compatible_index(manifest) is None


def test_azure_restore_downloads_only_primary_then_shares_lazy_history(monkeypatch, tmp_path):
    bundle, manifest, _ = bundle_for(tmp_path / "source")
    contents = {
        item["path"]: (bundle / "index" / Path(item["path"]).name).read_bytes()
        for item in manifest["files"] if item["kind"] == "index"
    }
    calls = []

    class Blob:
        def __init__(self, path):
            self.path = path

        def download_blob(self, **kwargs):
            calls.append(self.path)
            assert self.path in contents, "Restored indexes must not download curated JSON"
            return self

        def chunks(self):
            yield contents[self.path]

    class Service:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get_container_client(self, name):
            return self

        def get_blob_client(self, path):
            return Blob(path)

    monkeypatch.setattr("azure.storage.blob.BlobServiceClient", Service)
    snapshots = DashboardSnapshots(
        Settings(dashboard_data_source="azure", storage_account_name="test"),
        tmp_path, lambda: manifest, lambda: object(), lambda *args: {},
    )
    try:
        snapshot = snapshots.current()
        with snapshots.acquire(snapshot.id):
            snapshots.prepare_index(snapshot)
            assert snapshot.engine is not None
            snapshot.engine.query({"view": "executive"})
            assert len(calls) == 1
            assert "primary" in calls[0]
            assert "finding-events" not in snapshot.engine.indexed_rows()
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: snapshot.engine.query({"view": "trend"}), range(2)))
            assert results[0] == results[1]
            assert len(calls) == 2
            assert "history" in calls[1]
            assert "finding-events" in snapshot.engine.indexed_rows()
            assert not list(snapshot.root.glob("*.gz"))
    finally:
        snapshots.close()


@pytest.mark.parametrize("failure", ["short", "long", "sqlite", "counts"])
def test_failed_restore_preserves_existing_database_and_cleans_partial(tmp_path, failure):
    bundle, manifest, _ = bundle_for(tmp_path / "source", 4)
    item = compatible_index(manifest)
    assert item is not None
    engine = DashboardQueryEngine(tmp_path / "restored", "restored", SNAPSHOT, lambda name: iter(()))
    original = engine.path.read_bytes()
    compressed = bundle / "index" / Path(item["path"]).name
    if failure == "short":
        item["uncompressedBytes"] += 1
    elif failure == "long":
        item["uncompressedBytes"] -= 1
    elif failure == "sqlite":
        with gzip.open(compressed, "wb") as output:
            output.write(b"not sqlite")
        item["uncompressedBytes"] = 10
    else:
        manifest["files"][0]["rowCount"] += 1
    with pytest.raises(DatasetIntegrityError):
        restore_dashboard_index(compressed, engine, manifest, item)
    assert engine.path.read_bytes() == original
    assert not list(engine.root.glob("*.restoring"))


def test_index_growth_is_bounded_and_restoration_avoids_reingestion(tmp_path):
    first, first_manifest, _ = bundle_for(tmp_path / "small", 1000)
    second, second_manifest, _ = bundle_for(tmp_path / "large", 2000)
    small = compatible_index(first_manifest)
    large = compatible_index(second_manifest)
    assert small is not None and large is not None
    assert large["uncompressedBytes"] < small["uncompressedBytes"] * 3
    assert large["sizeBytes"] < small["sizeBytes"] * 3
    assert large["sizeBytes"] < large["uncompressedBytes"]
    small_total = sum(entry["sizeBytes"] for entry in first_manifest["files"] if entry["kind"] == "index")
    large_total = sum(entry["sizeBytes"] for entry in second_manifest["files"] if entry["kind"] == "index")
    assert large_total < small_total * 3
    start = time.perf_counter()
    restored_engine(tmp_path / "restore", second, second_manifest)
    assert time.perf_counter() - start < 10
