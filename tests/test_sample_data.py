import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).parents[1] / "tools" / "import_sample_data.py"
SPEC = importlib.util.spec_from_file_location("import_sample_data", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def write_sample(
    path: Path,
    run_id: str = "live-20260928T150000Z",
    content: bytes = b'{"value":[]}',
    expected_hash: str | None = None,
) -> Path:
    raw_path = f"output/raw/{run_id}/machines-page-0001.json.gz"
    manifest = {
        "formatVersion": 1,
        "runId": run_id,
        "rawFileCount": 1,
        "rawBytes": len(content),
        "files": [{
            "path": raw_path,
            "bytes": len(content),
            "sha256": expected_hash or hashlib.sha256(content).hexdigest(),
        }],
    }
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("SENSITIVE-DATA.txt", "Sensitive")
        archive.writestr("sample-manifest.json", json.dumps(manifest))
        archive.writestr(raw_path, content)
    return path


def test_sample_data_validates_and_imports_without_overwrite(tmp_path: Path):
    package = write_sample(tmp_path / "sample.zip")

    manifest = MODULE.validate_sample(package)
    destination = MODULE.import_sample(package, tmp_path / "repository")

    assert manifest["runId"] == "live-20260928T150000Z"
    assert (destination / "machines-page-0001.json.gz").read_bytes() == b'{"value":[]}'
    with pytest.raises(FileExistsError, match="will not be overwritten"):
        MODULE.import_sample(package, tmp_path / "repository")


def test_sample_data_rejects_checksum_mismatch(tmp_path: Path):
    package = write_sample(tmp_path / "sample.zip", expected_hash="0" * 64)

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        MODULE.validate_sample(package)


def test_sample_data_rejects_path_traversal(tmp_path: Path):
    package = write_sample(tmp_path / "sample.zip")
    with zipfile.ZipFile(package, "a") as archive:
        archive.writestr("../outside.txt", "unsafe")

    with pytest.raises(ValueError, match="Unsafe ZIP member path"):
        MODULE.validate_sample(package)
