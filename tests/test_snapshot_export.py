import gzip
import hashlib
import json
from contextlib import nullcontext
from zipfile import ZipFile

import pytest
from azure.core.exceptions import ResourceNotFoundError

from vulnerability_view import operations_cli


@pytest.fixture
def snapshot_export(monkeypatch, tmp_path):
    run_id = "live-20261103T050000Z"
    date = f"2026/11/03/{run_id}"
    contents = {
        f"curated/{date}/findings.json.gz": gzip.compress(b'[{"FindingKey":"finding-1"}]'),
        f"curated/{date}/devices.json.gz": gzip.compress(b'[{"DeviceId":"device-1"}]'),
        f"raw/{date}/machines-page-0001.json.gz": gzip.compress(b'{"value":[{"id":"device-1"}]}'),
        f"runs/{date}/sla-policies.json": b'{"policyVersion":"test","policies":[]}',
    }
    files = []
    for path, content in contents.items():
        kind = {"curated": "curated", "raw": "raw", "runs": "policy"}[path.split("/")[0]]
        item = {"kind": kind, "path": path, "sizeBytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        if kind == "curated":
            item.update(dataset=path.rsplit("/", 1)[-1].split(".")[0], rowCount=1)
        files.append(item)
    state = {
        "manifest": {
            "schemaVersion": 2, "runId": run_id, "snapshotTimeUtc": "2026-11-03T05:00:00Z",
            "complete": True, "files": files,
        },
        "contents": contents, "downloads": [], "on_download": None,
    }

    class Blob:
        def __init__(self, container, path):
            self.container, self.path = container, path

        def download_blob(self):
            state["downloads"].append((self.container, self.path))
            return self

        def readall(self):
            assert (self.container, self.path) == ("pointer-test", "current/manifest.json")
            return json.dumps(state["manifest"]).encode()

        def chunks(self):
            assert self.container == "history-test"
            if state["on_download"]:
                state["on_download"]()
            if self.path not in state["contents"]:
                raise ResourceNotFoundError("Published file missing")
            content = state["contents"][self.path]
            for offset in range(0, len(content), 7):
                yield content[offset:offset + 7]

    class Container:
        def __init__(self, name):
            self.name = name

        def get_blob_client(self, path):
            return Blob(self.name, path)

    class Service:
        def __init__(self, account_url, credential):
            assert account_url == "https://snapshotstest.blob.core.windows.net"

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def get_container_client(self, name):
            return Container(name)

    monkeypatch.setattr(operations_cli, "ROOT", tmp_path)
    monkeypatch.setattr(operations_cli, "_values", lambda: {
        "history_storage_account_name": "snapshotstest", "history_container_name": "history-test",
        "current_container_name": "pointer-test", "tenant_id": "tenant-test",
    })
    monkeypatch.setattr(operations_cli, "AzureCliCredential", lambda *, tenant_id: nullcontext(object()))
    monkeypatch.setattr(operations_cli, "BlobServiceClient", Service)
    state["root"] = tmp_path
    return state


def test_snapshot_export_verifies_all_files_and_preserves_analysis_evidence(snapshot_export, capsys):
    state = snapshot_export
    archive = operations_cli.export_latest_snapshot()

    assert archive.is_relative_to(state["root"] / "output" / "snapshots")
    with ZipFile(archive) as bundle:
        assert set(bundle.namelist()) == {*state["contents"], "manifest.json", "export-summary.json"}
        assert json.loads(bundle.read("manifest.json")) == state["manifest"]
        for path, content in state["contents"].items():
            assert bundle.read(path) == content
        summary = json.loads(bundle.read("export-summary.json"))
        assert summary["verifiedFileCount"] == 4
        assert summary["verifiedBytes"] == sum(map(len, state["contents"].values()))
        assert summary["datasetRowCounts"] == {"devices": 1, "findings": 1}
        assert summary["containsUnredactedData"] is True
        assert "Web App performance diagnostics are not included" in summary["scope"]
    output = capsys.readouterr().out
    assert "Verified 4/4 files" in output
    assert "findings: 1 rows (manifest count)" in output
    assert "sensitive, unredacted" in output
    assert "Azure history and the current pointer were not changed" in output
    assert len(state["downloads"]) == 5
    assert not list(state["root"].rglob("*.part"))


def test_snapshot_export_keeps_original_snapshot_when_current_pointer_advances(snapshot_export):
    state = snapshot_export
    original = json.loads(json.dumps(state["manifest"]))
    state["on_download"] = lambda: state["manifest"].update(runId="live-new-publication", files=[])

    archive = operations_cli.export_latest_snapshot()

    with ZipFile(archive) as bundle:
        assert json.loads(bundle.read("manifest.json")) == original
        assert json.loads(bundle.read("export-summary.json"))["runId"] == original["runId"]
    assert state["downloads"].count(("pointer-test", "current/manifest.json")) == 1


def test_repeated_snapshot_exports_never_overwrite_an_existing_export(snapshot_export):
    first = operations_cli.export_latest_snapshot()
    original = first.read_bytes()
    second = operations_cli.export_latest_snapshot()

    assert first != second
    assert first.read_bytes() == original
    assert second.is_file()


@pytest.mark.parametrize("field,value", [
    ("path", "../../outside.json"),
    ("path", "/absolute.json"),
    ("path", "C:\\outside.json"),
    ("path", "curated/2026/11/03/another-run/findings.json.gz"),
    ("path", "curated/2026/11/03/live-20261103T050000Z/../outside.json"),
    ("path", "curated/2026/11/03/live-20261103T050000Z/file. "),
    ("kind", []),
    ("sizeBytes", -1),
    ("sizeBytes", True),
    ("sha256", "not-a-digest"),
    ("rowCount", -1),
    ("rowCount", True),
    ("dataset", []),
])
def test_invalid_snapshot_metadata_fails_before_download_or_zip_creation(snapshot_export, field, value):
    state = snapshot_export
    state["manifest"]["files"][0][field] = value
    with pytest.raises(ValueError):
        operations_cli.export_latest_snapshot()
    assert state["downloads"] == [("pointer-test", "current/manifest.json")]
    assert not list(state["root"].rglob("*.zip*"))


@pytest.mark.parametrize("field,value", [
    ("complete", False), ("schemaVersion", 999), ("schemaVersion", True),
    ("runId", "../../outside"), ("files", []), ("snapshotTimeUtc", "2026-11-03T05:00:00"),
])
def test_incomplete_or_unsupported_publications_are_not_exported(snapshot_export, field, value):
    state = snapshot_export
    state["manifest"][field] = value
    with pytest.raises(ValueError):
        operations_cli.export_latest_snapshot()
    assert not list(state["root"].rglob("*.zip*"))


def test_duplicate_manifest_paths_fail_before_any_history_read(snapshot_export):
    state = snapshot_export
    state["manifest"]["files"].append(dict(state["manifest"]["files"][0]))
    with pytest.raises(ValueError, match="duplicate"):
        operations_cli.export_latest_snapshot()
    assert len(state["downloads"]) == 1


@pytest.mark.parametrize("failure", ["size", "oversize", "hash", "missing"])
def test_integrity_or_storage_failures_do_not_leave_success_shaped_archives(snapshot_export, failure, capsys):
    state = snapshot_export
    item = state["manifest"]["files"][0]
    if failure == "size":
        item["sizeBytes"] += 1
    elif failure == "oversize":
        item["sizeBytes"] -= 1
    elif failure == "hash":
        item["sha256"] = "0" * 64
    else:
        del state["contents"][item["path"]]
    assert operations_cli.main(["export-latest-snapshot"]) == 1
    assert not list(state["root"].rglob("*.zip*"))
    output = capsys.readouterr()
    assert "Operation failed:" in output.err
    assert "Verified snapshot export:" not in output.out


def test_snapshot_export_cli_routes_to_read_only_export(monkeypatch):
    calls = []
    monkeypatch.setattr(operations_cli, "export_latest_snapshot", lambda: calls.append("export"))
    assert operations_cli.main(["export-latest-snapshot"]) == 0
    assert calls == ["export"]
