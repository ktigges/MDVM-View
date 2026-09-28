"""Validate and import a full raw-data sampling package."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any


FORMAT_VERSION = 1
MANIFEST_PATH = "sample-manifest.json"
ALLOWED_METADATA = {MANIFEST_PATH, "SENSITIVE-DATA.txt"}


def _member_path(name: str) -> PurePosixPath:
    """Return a safe normalized ZIP member path."""
    if "\\" in name:
        raise ValueError(f"ZIP member uses a backslash path: {name}")
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ValueError(f"Unsafe ZIP member path: {name}")
    return path


def _sha256(archive: zipfile.ZipFile, member: zipfile.ZipInfo) -> str:
    """Hash one compressed-package member without extracting it."""
    digest = hashlib.sha256()
    with archive.open(member, "r") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_sample(package: Path) -> dict[str, Any]:
    """Validate package structure, manifest, sizes, and checksums."""
    with zipfile.ZipFile(package, "r") as archive:
        members = archive.infolist()
        names = [member.filename for member in members if not member.is_dir()]
        if len(names) != len(set(names)):
            raise ValueError("Sample ZIP contains duplicate file names")
        member_by_name: dict[str, zipfile.ZipInfo] = {}
        for member in members:
            normalized = _member_path(member.filename).as_posix()
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError(f"Sample ZIP contains a symbolic link: {normalized}")
            if not member.is_dir():
                if normalized in member_by_name:
                    raise ValueError(f"Sample ZIP contains a duplicate normalized path: {normalized}")
                member_by_name[normalized] = member
        if MANIFEST_PATH not in member_by_name:
            raise ValueError(f"Sample ZIP is missing {MANIFEST_PATH}")
        manifest = json.loads(archive.read(MANIFEST_PATH).decode("utf-8-sig"))
        if manifest.get("formatVersion") != FORMAT_VERSION:
            raise ValueError(f"Unsupported sample format version: {manifest.get('formatVersion')}")
        run_id = str(manifest.get("runId") or "")
        try:
            datetime.strptime(run_id, "live-%Y%m%dT%H%M%SZ")
        except ValueError:
            raise ValueError(f"Invalid sample run ID: {run_id}")
        raw_prefix = f"output/raw/{run_id}/"
        declared_files = manifest.get("files")
        if not isinstance(declared_files, list) or not declared_files:
            raise ValueError("Sample manifest contains no raw files")
        declared_paths: set[str] = set()
        total_bytes = 0
        for entry in declared_files:
            if not isinstance(entry, dict):
                raise ValueError("Sample manifest file entry is not an object")
            path = _member_path(str(entry.get("path") or "")).as_posix()
            if not path.startswith(raw_prefix):
                raise ValueError(f"Manifest entry is outside the raw run: {path}")
            if not path.endswith(".json.gz"):
                raise ValueError(f"Raw sample file must use the .json.gz extension: {path}")
            if path in declared_paths:
                raise ValueError(f"Manifest contains a duplicate file entry: {path}")
            declared_paths.add(path)
            member = member_by_name.get(path)
            if member is None:
                raise ValueError(f"Manifest file is missing from ZIP: {path}")
            expected_size = int(entry.get("bytes") or -1)
            if member.file_size != expected_size:
                raise ValueError(f"Size mismatch for {path}")
            expected_hash = str(entry.get("sha256") or "").lower()
            if len(expected_hash) != 64 or _sha256(archive, member) != expected_hash:
                raise ValueError(f"SHA-256 mismatch for {path}")
            total_bytes += member.file_size
        packaged_raw = {name for name in member_by_name if name.startswith(raw_prefix)}
        if packaged_raw != declared_paths:
            raise ValueError("Sample ZIP contains undeclared or missing raw files")
        unexpected = set(member_by_name) - declared_paths - ALLOWED_METADATA
        if unexpected:
            raise ValueError(f"Sample ZIP contains unexpected files: {', '.join(sorted(unexpected))}")
        if int(manifest.get("rawFileCount") or -1) != len(declared_paths):
            raise ValueError("Manifest raw file count does not match its file list")
        if int(manifest.get("rawBytes") or -1) != total_bytes:
            raise ValueError("Manifest raw byte count does not match its file list")
        return manifest


def import_sample(package: Path, repository: Path) -> Path:
    """Import a validated raw run without overwriting existing data."""
    manifest = validate_sample(package)
    run_id = str(manifest["runId"])
    raw_root = repository / "output" / "raw"
    raw_root.mkdir(parents=True, exist_ok=True)
    destination = raw_root / run_id
    if destination.exists():
        raise FileExistsError(f"Raw run already exists and will not be overwritten: {destination}")
    staging = Path(tempfile.mkdtemp(prefix=f".{run_id}-", dir=raw_root))
    raw_prefix = f"output/raw/{run_id}/"
    try:
        with zipfile.ZipFile(package, "r") as archive:
            for entry in manifest["files"]:
                member_name = str(entry["path"])
                relative = PurePosixPath(member_name.removeprefix(raw_prefix))
                target = staging.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member_name, "r") as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
        staging.rename(destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return destination


def main() -> int:
    """Run the package validation and import workflow."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path, help="Raw-data sample ZIP")
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root that will receive output/raw/<run-id>",
    )
    parser.add_argument("--validate-only", action="store_true", help="Validate without importing")
    args = parser.parse_args()
    package = args.package.resolve()
    repository = args.repository.resolve()
    if args.validate_only:
        manifest = validate_sample(package)
        print(
            f"Validated {manifest['runId']}: {manifest['rawFileCount']} raw files, "
            f"{manifest['rawBytes']} bytes."
        )
        return 0
    destination = import_sample(package, repository)
    print(f"Imported without overwrite: {destination}")
    print(
        "Replay locally with: APP_MODE=live STORAGE_ACCOUNT_NAME= vulnerability-view collect-live "
        f"--from-raw {destination} --local-only"
    )
    print("Then validate with: vulnerability-view validate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
