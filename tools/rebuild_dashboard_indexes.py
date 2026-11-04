"""Rebuild dashboard indexes from retained curated evidence, without recollection.

The default builds and validates locally, with no Azure writes. --publish appends
an immutable index revision, then conditionally replaces current/manifest.json.
No existing history object is overwritten or deleted. Collection identity and all
non-index manifest content are preserved. No Defender APIs are called.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import subprocess
import sys
import tempfile
from contextvars import copy_context
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

from azure.core import MatchConditions
from azure.core.exceptions import AzureError
from azure.identity import AzureCliCredential
from azure.storage.blob import BlobServiceClient

from vulnerability_view.azure_cli_target import choose_storage_target
from vulnerability_view.dashboard_index import (
    INDEX_GROUPS, MAX_INDEX_BYTES, build_dashboard_indexes, compatible_index, restore_dashboard_index,
)
from vulnerability_view.dashboard_queries import DashboardQueryEngine
from vulnerability_view.dashboard_startup import startup_bytes, startup_diagnostics, startup_stage, storage_retry
from vulnerability_view.storage_writer import (
    DATASET_FILES, RUN_SCHEMA_VERSION, DatasetIntegrityError, _sha256, download_manifest_file,
)


ROOT = Path(__file__).resolve().parents[1]


def safe_path(path: str, prefix: str) -> None:
    if (
        not path.startswith(prefix + "/") or any(part in {"", ".", ".."} for part in path.split("/"))
        or any(character in path for character in '\\:<>"|?*')
        or any(ord(character) < 32 for character in path)
        or any(part.endswith((" ", ".")) for part in path.split("/"))
    ):
        raise ValueError(f"Unsafe retained blob path: {path!r}")


def validate_manifest(manifest: dict[str, Any]) -> None:
    if not isinstance(manifest, dict):
        raise ValueError("Source manifest must be a JSON object")
    schema = manifest.get("schemaVersion")
    if manifest.get("complete") is not True or type(schema) is not int or not 1 <= schema <= RUN_SCHEMA_VERSION:
        raise ValueError("Source must be a complete, supported retained snapshot")
    if not isinstance(manifest.get("runId"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", manifest["runId"]):
        raise ValueError("Source has an unsafe collection run ID")
    if not isinstance(manifest.get("snapshotTimeUtc"), str):
        raise ValueError("Source has no snapshotTimeUtc")
    snapshot = datetime.fromisoformat(manifest["snapshotTimeUtc"].replace("Z", "+00:00"))
    if snapshot.tzinfo is None or snapshot.utcoffset() != timedelta(0):
        raise ValueError("Source snapshotTimeUtc must include a UTC timezone")
    statuses = manifest.get("endpointStatuses", [])
    if not isinstance(statuses, list) or any(not isinstance(item, dict) for item in statuses):
        raise ValueError("Source has invalid endpoint statuses")
    if any(item.get("Status") == "Failed" for item in statuses):
        raise ValueError("Source has a failed required endpoint")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("Source has no retained files")
    paths: set[str] = set()
    datasets: set[str] = set()
    local_names: set[tuple[str, str]] = set()
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not isinstance(item.get("kind"), str):
            raise ValueError("Source has an invalid retained file entry")
        kind, path = item["kind"], item["path"]
        prefix = {"curated": "curated", "raw": "raw", "policy": "runs", "index": "runs"}.get(kind)
        if prefix is None:
            raise ValueError(f"Unsupported retained file kind: {kind}")
        safe_path(path, prefix)
        name = (kind, PurePosixPath(path).name.casefold())
        if path.casefold() in paths or (kind in {"curated", "policy"} and name in local_names):
            raise ValueError("Source contains duplicate retained paths or local filenames")
        paths.add(path.casefold())
        local_names.add(name)
        if type(item.get("sizeBytes")) is not int or item["sizeBytes"] < 0:
            raise ValueError(f"Invalid retained sizeBytes: {path}")
        if not isinstance(item.get("sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"]):
            raise ValueError(f"Invalid retained SHA-256: {path}")
        if kind == "curated":
            dataset = item.get("dataset")
            if not isinstance(dataset, str) or dataset not in DATASET_FILES or dataset in datasets:
                raise ValueError(f"Unsupported or duplicate curated dataset: {dataset}")
            if type(item.get("rowCount")) is not int or item["rowCount"] < 0:
                raise ValueError(f"Invalid retained rowCount: {path}")
            datasets.add(dataset)
    if "findings" not in datasets:
        raise ValueError("Source has no retained findings dataset")


def evidence_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(manifest)
    result.pop("queryIndexRevision", None)
    result["files"] = [item for item in result["files"] if item["kind"] != "index"]
    return result


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def build_revision(
    account: str, history: str, credential: AzureCliCredential, source_data: bytes, directory: Path,
) -> dict[str, Any]:
    manifest = json.loads(source_data)
    validate_manifest(manifest)
    directory.mkdir(parents=True, exist_ok=False)
    (directory / "source-manifest.json").write_bytes(source_data)
    for item in manifest["files"]:
        if item["kind"] in {"curated", "policy"}:
            destination = directory / item["kind"] / PurePosixPath(item["path"]).name
            with startup_stage(f"download:{item.get('dataset', item['kind'])}:bytes={item['sizeBytes']}"):
                download_manifest_file(
                    account, history, credential, item, destination, progress=startup_bytes, retry_hook=storage_retry,
                )
    revision = uuid4().hex
    prefix = f"runs/{manifest['snapshotTimeUtc'][:10].replace('-', '/')}/{manifest['runId']}/index-rebuilds/{revision}"
    indexes = build_dashboard_indexes(directory, manifest)
    for item in indexes:
        item["path"] = f"{prefix}/{PurePosixPath(item['path']).name}"
    manifest["files"] = [item for item in manifest["files"] if item["kind"] != "index"] + indexes
    manifest["queryIndexRevision"] = {
        "id": revision, "createdAtUtc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "manifestPath": f"{prefix}/manifest.json", "sourceManifestPath": f"{prefix}/source-manifest.json",
        "sourceManifestSha256": hashlib.sha256(source_data).hexdigest(),
        "sourceManifestSizeBytes": len(source_data),
    }
    write_json(directory / "manifest.json", manifest)
    verify_revision(directory)
    return manifest


def verify_revision(directory: Path) -> dict[str, Any]:
    with startup_stage("verify-index-revision"):
        manifest = json.loads((directory / "manifest.json").read_bytes())
        source_data = (directory / "source-manifest.json").read_bytes()
        source = json.loads(source_data)
        validate_manifest(source)
        validate_manifest(manifest)
        revision = manifest["queryIndexRevision"]
        if not re.fullmatch(r"[a-f0-9]{32}", revision["id"]):
            raise ValueError("Invalid index revision ID")
        prefix = f"runs/{manifest['snapshotTimeUtc'][:10].replace('-', '/')}/{manifest['runId']}/index-rebuilds/{revision['id']}"
        if (
            revision["manifestPath"] != f"{prefix}/manifest.json"
            or revision["sourceManifestPath"] != f"{prefix}/source-manifest.json"
            or revision["sourceManifestSha256"] != hashlib.sha256(source_data).hexdigest()
            or revision["sourceManifestSizeBytes"] != len(source_data)
            or evidence_manifest(manifest) != evidence_manifest(source)
        ):
            raise DatasetIntegrityError("Index revision changes retained evidence or source provenance")
        indexes = [item for item in manifest["files"] if item["kind"] == "index"]
        if (
            len(indexes) != len(INDEX_GROUPS)
            or sum(item["uncompressedBytes"] for item in indexes) > MAX_INDEX_BYTES
        ):
            raise DatasetIntegrityError("Index revision must contain two indexes within the supported disk budget")
        for item in manifest["files"]:
            if item["kind"] not in {"curated", "policy", "index"}:
                continue
            path = directory / ("index" if item["kind"] == "index" else item["kind"]) / PurePosixPath(item["path"]).name
            if path.stat().st_size != item["sizeBytes"] or _sha256(path) != item["sha256"]:
                raise DatasetIntegrityError(f"Local revision integrity failure: {item['path']}")
        with tempfile.TemporaryDirectory(prefix="verify-", dir=directory) as temporary:
            for group in INDEX_GROUPS:
                item = compatible_index(manifest, group)
                if item is None or item["path"] != f"{prefix}/dashboard-{group}.sqlite3.gz":
                    raise DatasetIntegrityError("Index revision has incompatible or unsafe index references")
                engine = DashboardQueryEngine(Path(temporary), group, manifest["snapshotTimeUtc"], lambda _name: iter(()))
                restore_dashboard_index(directory / "index" / PurePosixPath(item["path"]).name, engine, manifest, item)
        return manifest


def publish_revision(
    service: BlobServiceClient, history_name: str, current_name: str, directory: Path, etag: str,
) -> int:
    manifest = verify_revision(directory)
    pointer = service.get_container_client(current_name).get_blob_client("current/manifest.json")
    properties = pointer.get_blob_properties()
    if properties.etag != etag:
        raise ValueError("Current pointer changed while rebuilding; refusing publication. Local revision retained.")
    current = json.loads(pointer.download_blob(etag=etag, match_condition=MatchConditions.IfNotModified).readall())
    if evidence_manifest(current) != evidence_manifest(manifest):
        raise ValueError("Index-only publication cannot replace the current snapshot with different or older evidence")
    revision = manifest["queryIndexRevision"]
    uploads = [
        (directory / "index" / PurePosixPath(item["path"]).name, item["path"], item["sizeBytes"], item["sha256"])
        for item in manifest["files"] if item["kind"] == "index"
    ]
    for local_name, remote_path in (
        ("source-manifest.json", revision["sourceManifestPath"]), ("manifest.json", revision["manifestPath"]),
    ):
        path = directory / local_name
        uploads.append((path, remote_path, path.stat().st_size, _sha256(path)))
    history = service.get_container_client(history_name)
    progress_context = copy_context()
    for path, remote_path, size, digest in uploads:
        with startup_stage(f"upload:{remote_path}:bytes={size}"):
            with path.open("rb") as handle:
                history.get_blob_client(remote_path).upload_blob(
                    handle, overwrite=False, metadata={"sha256": digest}, validate_content=True,
                    max_concurrency=2,
                    progress_hook=lambda current, _total: progress_context.copy().run(startup_bytes, current),
                )
            remote = history.get_blob_client(remote_path).get_blob_properties()
            if remote.size != size or remote.metadata.get("sha256") != digest:
                raise DatasetIntegrityError(f"Uploaded revision verification failed: {remote_path}")
    with startup_stage("publish-current-pointer"):
        pointer.upload_blob(
            (directory / "manifest.json").read_bytes(), overwrite=True,
            etag=etag, match_condition=MatchConditions.IfNotModified, validate_content=True,
        )
    return len(uploads) + 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--history-container", required=True)
    parser.add_argument("--current-container", required=True)
    parser.add_argument("--subscription")
    parser.add_argument("--source-manifest", help="Optional immutable runs/... manifest; publication must preserve current evidence")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "output/index-rebuilds")
    parser.add_argument("--publish", action="store_true", help="Permit Azure writes after exact-target confirmation")
    parser.add_argument("--publish-existing", type=Path, help="Reuse a validated local revision directory; requires --publish")
    parser.add_argument("--confirm-target", help="Explicit account/history-container/current-container confirmation")
    args = parser.parse_args(argv)
    if args.publish_existing and (not args.publish or args.source_manifest):
        parser.error("--publish-existing requires --publish and cannot be combined with --source-manifest")
    directory: Path | None = None
    report_path: Path | None = None
    report: dict[str, Any] = {"status": "starting", "published": False}
    try:
        with startup_diagnostics(), startup_stage("rebuild-retained-indexes"):
            with startup_stage("resolve-azure-target"):
                account, storage, history_name, current_name = choose_storage_target(
                    args.account, args.history_container, args.current_container, args.subscription,
                )
            target = f"{storage}/{history_name}/{current_name}"
            print(f"Target: {target}. Azure writes permitted: {args.publish}. No collection or application restart.", flush=True)
            print("Local output contains sensitive retained evidence. Several GiB of free disk may be required.", flush=True)
            if args.confirm_target is not None and args.confirm_target != target:
                raise ValueError("Exact-target confirmation did not match; no Azure writes performed")
            with AzureCliCredential(tenant_id=account["tenantId"]) as credential, BlobServiceClient(
                f"https://{storage}.blob.core.windows.net", credential=credential,
            ) as service:
                if args.publish_existing:
                    directory = args.publish_existing.resolve()
                    report = json.loads((directory / "rebuild.json").read_bytes())
                    if report["target"] != target or report["subscriptionId"] != account["id"] or report.get("published"):
                        raise ValueError("Local revision has a different target/subscription or was already published")
                    manifest = verify_revision(directory)
                    if report["revisionId"] != manifest["queryIndexRevision"]["id"]:
                        raise ValueError("Local revision does not match its saved publication baseline")
                    report_path = directory / "rebuild.json"
                else:
                    with startup_stage("read-pinned-source-manifest"):
                        history = service.get_container_client(history_name)
                        history.get_container_properties()
                        pointer = service.get_container_client(current_name).get_blob_client("current/manifest.json")
                        properties = pointer.get_blob_properties()
                        source_data = pointer.download_blob(
                            etag=properties.etag, match_condition=MatchConditions.IfNotModified,
                        ).readall()
                        if args.source_manifest:
                            safe_path(args.source_manifest, "runs")
                            source_data = history.get_blob_client(args.source_manifest).download_blob().readall()
                    directory = args.output_dir.resolve() / f"rebuild-{uuid4().hex}"
                    manifest = build_revision(storage, history_name, credential, source_data, directory)
                    report.update(
                        target=target, subscriptionId=account["id"], baselineEtag=properties.etag,
                        sourceRunId=manifest["runId"], snapshotTimeUtc=manifest["snapshotTimeUtc"],
                        revisionId=manifest["queryIndexRevision"]["id"],
                        manifestPath=manifest["queryIndexRevision"]["manifestPath"],
                    )
                    report_path = directory / "rebuild.json"
                report["status"] = "validated"
                write_json(directory / "rebuild.json", report)
                print(json.dumps(report, indent=2), flush=True)
                if args.publish:
                    print("WRITE intent: append two indexes and two manifests; replace ONLY current/manifest.json.", flush=True)
                    confirmation = args.confirm_target or input(f"Type {target} to PUBLISH: ").strip()
                    if confirmation != target:
                        raise ValueError("Exact-target confirmation did not match; no Azure writes performed")
                    report["status"] = "publishing"
                    write_json(directory / "rebuild.json", report)
                    count = publish_revision(service, history_name, current_name, directory, report["baselineEtag"])
                    report.update(status="published", published=True, uploadedFiles=count)
                else:
                    print("No Azure writes. Reuse this directory with --publish --publish-existing to avoid rebuilding.", flush=True)
                write_json(directory / "rebuild.json", report)
                print(json.dumps(report, indent=2), flush=True)
                print(f"Result: {directory / 'rebuild.json'}", flush=True)
        return 0
    except (AzureError, OSError, ValueError, KeyError, TypeError, RuntimeError, EOFError, sqlite3.Error, subprocess.TimeoutExpired) as error:
        report.update(status="failed", error=str(error))
        if report_path is not None:
            write_json(report_path, report)
        print(f"Index rebuild failed: {type(error).__name__}: {error}", file=sys.stderr, flush=True)
        print("No retained history was deleted or overwritten. If failure occurred during pointer upload, verify current/manifest.json before retrying.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
