import json
from copy import deepcopy
from pathlib import Path
from threading import Thread
from unittest.mock import Mock, create_autospec

import pytest
from azure.core import MatchConditions
from azure.core.exceptions import ResourceExistsError, ResourceModifiedError

from tools import rebuild_dashboard_indexes as tool
from vulnerability_view.config import Settings
from vulnerability_view.dashboard_index import compatible_index, restore_dashboard_index
from vulnerability_view.dashboard_preparation import DashboardPreparation
from vulnerability_view.dashboard_queries import DashboardQueryEngine, PREPARED_VIEWS
from vulnerability_view.dashboard_snapshots import DashboardSnapshots
from vulnerability_view.dashboard_startup import StartupDiagnostics, query_progress
from vulnerability_view.dataset_io import iter_json_rows
from vulnerability_view.storage_writer import DatasetIntegrityError
from test_populate_load_test_data import Blob, seed, service


TARGET = "testaccount/test-history/test-current"
POINTER = ("test-current", "current/manifest.json")


@pytest.fixture
def azure(service, monkeypatch):
    factory = Mock(return_value=service)
    monkeypatch.setattr("azure.storage.blob.BlobServiceClient", factory)
    monkeypatch.setattr(tool, "BlobServiceClient", factory)
    monkeypatch.setattr(tool, "AzureCliCredential", create_autospec(tool.AzureCliCredential))
    monkeypatch.setattr(
        tool, "choose_storage_target",
        lambda *_args: ({"id": "subscription", "tenantId": "tenant"}, "testaccount", "test-history", "test-current"),
    )
    return service


@pytest.fixture
def revision(azure, tmp_path):
    directory = tmp_path / "revision"
    manifest = tool.build_revision("testaccount", "test-history", None, azure.data[POINTER], directory)
    return directory, manifest


def cli(tmp_path, *arguments):
    return [
        "--account", "testaccount", "--history-container", "test-history",
        "--current-container", "test-current", "--output-dir", str(tmp_path / "output"),
        *arguments,
    ]


@pytest.mark.parametrize("legacy", [False, True])
def test_rebuild_preserves_exact_evidence_identity_and_all_view_results(azure, seed, tmp_path, legacy):
    bundle, source = seed
    source = deepcopy(source)
    source["customerMetadata"] = {"retained": "unchanged"}
    source["loadTest"] = {"originalSeed": "retained-generated-data-is-supported"}
    if legacy:
        source["files"] = [item for item in source["files"] if item["kind"] != "index"]
    source_data = json.dumps(source, indent=3).encode()
    before = dict(azure.data)
    directory = tmp_path / "rebuilt"
    manifest = tool.build_revision("testaccount", "test-history", None, source_data, directory)
    assert azure.data == before and not azure.uploads
    assert (directory / "source-manifest.json").read_bytes() == source_data
    assert tool.evidence_manifest(manifest) == tool.evidence_manifest(source)
    assert manifest["runId"] == source["runId"]
    assert manifest["snapshotTimeUtc"] == source["snapshotTimeUtc"]
    assert tool.verify_revision(directory) == manifest
    assert not list(directory.glob("query-index-*")) and not list(directory.glob("verify-*"))
    assert set(azure.downloads) == {
        ("test-history", item["path"]) for item in source["files"] if item["kind"] in {"curated", "policy"}
    }

    def unexpected(name):
        raise AssertionError(f"Restored queries must not re-ingest curated data: {name}")

    restored = DashboardQueryEngine(tmp_path / "restored", "same", source["snapshotTimeUtc"], unexpected)
    primary = compatible_index(manifest)
    restore_dashboard_index(directory / "index/dashboard-primary.sqlite3.gz", restored, manifest, primary)
    restored.history_index_loader = lambda: restore_dashboard_index(
        directory / "index/dashboard-history.sqlite3.gz", restored, manifest, compatible_index(manifest, "history"),
        destination=restored.root / "history.sqlite3",
    )
    baseline = DashboardQueryEngine(
        tmp_path / "baseline", "same", source["snapshotTimeUtc"],
        lambda name: iter_json_rows(bundle / "curated" / f"{name}.json.gz"),
    )
    for view in PREPARED_VIEWS:
        assert restored.query({"view": view}) == baseline.query({"view": view})
    for mode in ("findings", "cves"):
        assert list(restored.iter_export({"view": "overview", "mode": mode})) == list(
            baseline.iter_export({"view": "overview", "mode": mode}),
        )


def test_publication_appends_only_indexes_and_provenance_then_cas_pointer(azure, revision):
    directory, manifest = revision
    before = dict(azure.data)
    assert tool.publish_revision(azure, "test-history", "test-current", directory, "original") == 5
    assert json.loads(azure.data[POINTER]) == manifest
    for key, content in before.items():
        if key != POINTER:
            assert azure.data[key] == content
    assert len(azure.uploads) == 5
    for container, path, options in azure.uploads[:-1]:
        assert container == "test-history"
        assert f"/{manifest['runId']}/index-rebuilds/{manifest['queryIndexRevision']['id']}/" in path
        assert options["overwrite"] is False
        assert options["validate_content"] is True
    assert azure.data["test-history", manifest["queryIndexRevision"]["sourceManifestPath"]] == before[POINTER]
    container, path, options = azure.uploads[-1]
    assert (container, path) == POINTER
    assert options["etag"] == "original" and options["match_condition"] == MatchConditions.IfNotModified
    assert options["overwrite"] is True


def test_same_collection_revision_is_detected_and_restored_without_curated_reingestion(azure, revision, tmp_path):
    directory, manifest = revision
    snapshots = DashboardSnapshots(
        Settings(dashboard_data_source="azure", storage_account_name="testaccount", storage_container_name="test-history"),
        tmp_path, lambda: json.loads(azure.data[POINTER]), lambda: None, lambda *_args: {"policies": []},
    )
    results = []

    def prepare(snapshot):
        snapshots.prepare_index(snapshot)
        results.append(snapshot.engine.query({"view": "executive"}))
        snapshot.prepared = True

    preparation = DashboardPreparation(snapshots, prepare, 300)
    azure.downloads.clear()
    try:
        preparation.refresh()
        original = preparation.metadata()
        assert "queryIndexRevision" not in original
        tool.publish_revision(azure, "test-history", "test-current", directory, "original")
        preparation.refresh()
        updated = preparation.metadata()
        assert updated["snapshotId"] != original["snapshotId"]
        assert updated["runId"] == original["runId"]
        assert updated["snapshotTimeUtc"] == original["snapshotTimeUtc"]
        assert updated["queryIndexRevision"] == manifest["queryIndexRevision"]
        assert results[0]["snapshotId"] == original["snapshotId"]
        assert results[1]["snapshotId"] == updated["snapshotId"]
        assert {key: value for key, value in results[0].items() if key != "snapshotId"} == {
            key: value for key, value in results[1].items() if key != "snapshotId"
        }
        with snapshots.acquire(original["snapshotId"]) as pinned:
            assert pinned.prepared and pinned.metadata() == original
        assert all(
            key == POINTER or key[1].endswith("dashboard-primary.sqlite3.gz")
            for key in azure.downloads
        )
    finally:
        preparation.close()
        snapshots.close()


def test_upload_byte_progress_survives_sdk_worker_threads(azure, revision, monkeypatch):
    directory, _ = revision
    monitor = StartupDiagnostics()
    samples = []
    original_upload = Blob.upload_blob

    def threaded_upload(blob, data, **options):
        hook = options.get("progress_hook")
        if hook is not None:
            def threaded_hook(current, total):
                thread = Thread(target=hook, args=(current, total))
                thread.start()
                thread.join()
                samples.append((current, monitor.bytes))

            options["progress_hook"] = threaded_hook
        return original_upload(blob, data, **options)

    monkeypatch.setattr(Blob, "upload_blob", threaded_upload)
    with query_progress(monitor):
        tool.publish_revision(azure, "test-history", "test-current", directory, "original")
    assert samples and all(current == reported for current, reported in samples)


def test_repeated_rebuilds_keep_manifest_size_fixed_and_never_copy_evidence(azure, revision, tmp_path):
    directory, first = revision
    before = dict(azure.data)
    tool.publish_revision(azure, "test-history", "test-current", directory, "original")
    second_directory = tmp_path / "second"
    second = tool.build_revision("testaccount", "test-history", None, azure.data[POINTER], second_directory)
    tool.publish_revision(azure, "test-history", "test-current", second_directory, "new")
    assert len(second["files"]) == len(first["files"])
    assert second["queryIndexRevision"]["id"] != first["queryIndexRevision"]["id"]
    assert tool.evidence_manifest(second) == tool.evidence_manifest(first)
    assert compatible_index(second)["sourceIdentity"] == compatible_index(first)["sourceIdentity"]
    assert len(azure.data) == len(before) + 8
    assert len(azure.uploads) == 10
    assert all(
        container == "test-current" or "/index-rebuilds/" in path
        for container, path, _options in azure.uploads
    )
    for key, content in before.items():
        if key != POINTER:
            assert azure.data[key] == content


@pytest.mark.parametrize("failure", ["changed", "race", "collision", "remote-integrity", "older-source"])
def test_failed_publication_never_switches_pointer_or_modifies_retained_files(azure, revision, failure):
    directory, manifest = revision
    if failure == "changed":
        azure.etags[POINTER] = "concurrent"
    elif failure == "race":
        azure.before_pointer = lambda: azure.etags.update({POINTER: "concurrent"})
    elif failure == "collision":
        item = next(item for item in manifest["files"] if item["kind"] == "index")
        azure.data["test-history", item["path"]] = b"existing immutable object"
    elif failure == "remote-integrity":
        azure.wrong_size = True
    else:
        different = json.loads(azure.data[POINTER])
        different["runId"] = "newer-collection"
        azure.data[POINTER] = json.dumps(different).encode()
    before = dict(azure.data)
    with pytest.raises((ValueError, ResourceModifiedError, ResourceExistsError)):
        tool.publish_revision(azure, "test-history", "test-current", directory, "original")
    for key, content in before.items():
        assert azure.data[key] == content
    assert all(container == "test-history" for container, _path, _options in azure.uploads)
    if failure in {"changed", "older-source"}:
        assert not azure.uploads


@pytest.mark.parametrize("kind", ["curated", "policy", "index", "source", "manifest"])
def test_corrupt_local_revision_cannot_be_published(azure, revision, kind):
    directory, manifest = revision
    if kind == "source":
        (directory / "source-manifest.json").write_bytes(b"{}")
    elif kind == "manifest":
        manifest["snapshotTimeUtc"] = "2026-11-02T00:00:00Z"
        tool.write_json(directory / "manifest.json", manifest)
    else:
        item = next(item for item in manifest["files"] if item["kind"] == kind)
        (directory / kind / Path(item["path"]).name).write_bytes(b"bad")
    with pytest.raises(ValueError):
        tool.publish_revision(azure, "test-history", "test-current", directory, "original")
    assert not azure.uploads


@pytest.mark.parametrize("corruption", ["hash", "count", "policy"])
def test_source_integrity_failures_never_publish(azure, tmp_path, corruption):
    manifest = json.loads(azure.data[POINTER])
    item = next(item for item in manifest["files"] if item.get("dataset") == "findings")
    if corruption == "hash":
        item["sha256"] = "0" * 64
    elif corruption == "count":
        item["rowCount"] += 1
    else:
        item = next(item for item in manifest["files"] if item["kind"] == "policy")
        azure.data["test-history", item["path"]] = b"broken policy"
    with pytest.raises((ValueError, DatasetIntegrityError)):
        tool.build_revision("testaccount", "test-history", None, json.dumps(manifest).encode(), tmp_path / "broken")
    assert not azure.uploads


def test_preview_then_publish_existing_does_not_repeat_download_or_index_build(azure, tmp_path, monkeypatch):
    build = Mock(wraps=tool.build_dashboard_indexes)
    monkeypatch.setattr(tool, "build_dashboard_indexes", build)
    assert tool.main(cli(tmp_path)) == 0
    assert not azure.uploads and build.call_count == 1
    directory = next((tmp_path / "output").iterdir())
    report = json.loads((directory / "rebuild.json").read_bytes())
    assert report["status"] == "validated" and report["published"] is False
    azure.downloads.clear()
    assert tool.main(cli(
        tmp_path, "--publish", "--publish-existing", str(directory), "--confirm-target", TARGET,
    )) == 0
    assert build.call_count == 1
    assert azure.downloads == [POINTER]
    report = json.loads((directory / "rebuild.json").read_bytes())
    assert report["status"] == "published" and report["published"] is True and report["uploadedFiles"] == 5


def test_declined_confirmation_makes_no_writes(azure, tmp_path, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _prompt: "no")
    assert tool.main(cli(tmp_path, "--publish")) == 1
    assert not azure.uploads


def test_wrong_confirmation_does_not_open_storage_client(azure, tmp_path):
    assert tool.main(cli(tmp_path, "--publish", "--confirm-target", "wrong")) == 1
    tool.BlobServiceClient.assert_not_called()
    assert not azure.uploads


def test_saved_revision_rejects_a_new_current_publication(azure, tmp_path):
    assert tool.main(cli(tmp_path)) == 0
    directory = next((tmp_path / "output").iterdir())
    azure.etags[POINTER] = "newer-collection"
    assert tool.main(cli(
        tmp_path, "--publish", "--publish-existing", str(directory), "--confirm-target", TARGET,
    )) == 1
    assert not azure.uploads


def test_immutable_source_manifest_can_be_selected_without_cloning(azure, tmp_path):
    source = "runs/2026/11/01/original/manifest.json"
    azure.data["test-history", source] = azure.data[POINTER]
    assert tool.main(cli(tmp_path, "--source-manifest", source)) == 0
    assert ("test-history", source) in azure.downloads
    assert not azure.uploads


@pytest.mark.parametrize("change", ["incomplete", "schema", "path", "run", "duplicate", "missing", "rowCount"])
def test_invalid_retained_manifest_is_rejected_before_dataset_downloads(azure, tmp_path, change):
    manifest = json.loads(azure.data[POINTER])
    if change == "incomplete":
        manifest["complete"] = False
    elif change == "schema":
        manifest["schemaVersion"] = 100
    elif change == "path":
        manifest["files"][0]["path"] = "curated/../outside"
    elif change == "run":
        manifest["runId"] = "../outside"
    elif change == "duplicate":
        manifest["files"].append(deepcopy(manifest["files"][0]))
    elif change == "missing":
        manifest["files"] = [item for item in manifest["files"] if item.get("dataset") != "findings"]
    else:
        next(item for item in manifest["files"] if item.get("dataset") == "findings")["rowCount"] = -1
    with pytest.raises(ValueError):
        tool.build_revision("testaccount", "test-history", None, json.dumps(manifest).encode(), tmp_path / "invalid")
    assert not azure.downloads and not azure.uploads
