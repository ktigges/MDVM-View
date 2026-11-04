"""Expand an existing TEST Azure snapshot without changing application code.

Run from the repository root with its Python environment and an explicit az login:

    az login --tenant YOUR_TEST_TENANT
    az account set --subscription YOUR_TEST_SUBSCRIPTION
    PYTHONPATH=src .venv/bin/python tools/populate_load_test_data.py

The default only reads Azure and builds a verified local bundle. Add --publish
to upload and, after an exact-target confirmation, replace the current pointer.
Missing account/container names are prompted for; no containers are created.
All historical blobs are append-only. No Azure deletion operations are used.
The test Web App's code, configuration and running state are never changed.
Use --publish up front to generate once, review the row counts, then confirm.
Management-plane Reader access is needed to verify the selected storage account;
Blob Data Reader suffices for preview, Blob Data Contributor for publication.
Keep other writers to the test current pointer idle while generating: a changed
ETag aborts publication rather than replacing somebody else's newer snapshot.
Allow several GiB of local scratch space and potentially several minutes for
generation/summaries. Seed/output files contain copied test data, not anonymized
data. For cold-start testing, restart the test Web App yourself after publication.
Progress prints phase start/end messages and a heartbeat every 10 seconds:
processed rows/bytes/files, average rate and approximate ETA when totals are
known, interval process CPU (100% = one core), and process-lifetime peak RSS
on Linux/macOS. SQL stages report approximate SQLite VM operations, not a
fabricated row percentage or ETA. Heartbeats are observations, not proof that
an operation cannot be blocked. Already-running scripts do not pick up edits.

This extrapolates the seed's entity cohorts and lifecycle events, NOT the
customer's unknown distribution. CVEs/subscriptions are shared; devices,
recommendations, findings, tasks and their event IDs are cloned together.
The final cohort's findings/events are trimmed to the exact finding target.
Detailed lifecycle history is retained; summary datasets and the current
run-history row are rebuilt. Prior run-history aggregates are not fabricated.
Tracking-event blobs in separate workflow containers are not copied.

Published-file count includes curated datasets, the compressed query indexes,
derived raw pages, retained policy, immutable manifest and current pointer. Derived raw pages contain the
generated normalized findings, not original Defender responses or replay input.
Their count matches storage cardinality, not customer request/download traffic.

Authentication uses AzureCliCredential (az login), never storage keys or .env.
SDK references:
https://learn.microsoft.com/en-us/azure/developer/python/sdk/authentication/local-development-dev-accounts
https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blob-upload-python
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path, PurePosixPath
from types import TracebackType
from typing import Any
from uuid import uuid4

from azure.core import MatchConditions
from azure.core.exceptions import AzureError
from azure.identity import AzureCliCredential
from azure.storage.blob import BlobServiceClient

from vulnerability_view import bounded_summary
from vulnerability_view.azure_cli_target import az_json as _az_json, choose_storage_target
from vulnerability_view.bounded_processing import Workspace, write_json_rows
from vulnerability_view.dataset_io import JsonRows, iter_json_rows
from vulnerability_view.dashboard_index import compatible_index
from vulnerability_view.dashboard_startup import startup_diagnostics
from vulnerability_view.storage_writer import DATASET_FILES, RUN_SCHEMA_VERSION, create_run_bundle, verify_run_bundle


ROOT = Path(__file__).resolve().parents[1]
IDENTIFIERS = {
    "FindingKey", "DeviceId", "DeviceName", "MachineId", "MachineName",
    "RecommendationId", "RemediationId", "RemediationTaskId", "EventId",
}
GLOBAL_DATASETS = {"vulnerabilities", "subscriptions", "secureScores", "collectionRuns"}
REBUILT_DATASETS = {"dailySummary", "reconciliation", "runHistory"}
PROGRESS_SECONDS = 10.0


class Progress:
    def __init__(
        self, phase: str, *, total: int | None = None, unit: str | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        self.phase, self.total = phase, total
        self.unit = "sqliteOps" if connection is not None else unit
        self.connection = connection
        self.current = 0
        self.detail = ""
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.watch, name="load-test-progress", daemon=True)
        self.started = self.previous_time = time.monotonic()
        self.previous_cpu = time.process_time()

    def update(self, current: int, _total: int | None = None, *, detail: str | None = None) -> None:
        with self.lock:
            self.current = max(self.current, current)
            if detail is not None:
                self.detail = detail

    def track(self, rows: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
        count = 0
        try:
            for row in rows:
                yield row
                count += 1
                if count % 1024 == 0:
                    self.update(count)
        finally:
            self.update(count)

    def sql_tick(self) -> int:
        with self.lock:
            self.current += 1_000_000
        return 0

    def emit(self, event: str) -> None:
        now, cpu = time.monotonic(), time.process_time()
        elapsed = max(now - self.started, 0.001)
        cpu_percent = 100 * (cpu - self.previous_cpu) / max(now - self.previous_time, 0.001)
        with self.lock:
            current, detail = self.current, self.detail
        stats = "progress=unavailable"
        if self.unit is not None:
            rate = current / elapsed
            if self.unit == "bytes":
                stats = f"MiB={current / 1024**2:.1f}"
                if self.total is not None:
                    stats += f"/{self.total / 1024**2:.1f}"
                stats += f" rate={rate / 1024**2:.2f}MiB/s"
            else:
                stats = f"{self.unit}={current:,}"
                if self.total is not None:
                    stats += f"/{self.total:,}"
                stats += f" rate={rate:,.0f}{self.unit}/s"
            if self.total is not None:
                percent = 100 * current / self.total if self.total else 100.0
                eta = f"{max(0, self.total - current) / rate:.1f}s" if rate else "unavailable"
                stats += f" percent={percent:.1f}% eta~{eta}"
        peak = "unavailable"
        if sys.platform in {"darwin", "linux"}:
            import resource

            rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            peak = f"{rss / (1024**2 if sys.platform == 'darwin' else 1024):.1f}"
        print(
            f"[progress] {self.phase} event={event} elapsed={elapsed:.1f}s {stats} "
            f"cpu={cpu_percent:.0f}% peakRssMiB={peak}" + (f" {detail}" if detail else ""),
            flush=True,
        )
        self.previous_time, self.previous_cpu = now, cpu

    def watch(self) -> None:
        while not self.stopped.wait(PROGRESS_SECONDS):
            self.emit("heartbeat")

    def __enter__(self) -> Progress:
        self.started = self.previous_time = time.monotonic()
        self.previous_cpu = time.process_time()
        self.emit("start")
        if self.connection is not None:
            self.connection.set_progress_handler(self.sql_tick, 1_000_000)
        self.thread.start()
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, _exc: BaseException | None, _traceback: TracebackType | None,
    ) -> None:
        if self.connection is not None:
            self.connection.set_progress_handler(None, 0)
        self.stopped.set()
        self.thread.join()
        self.emit("failed" if exc_type is not None else "complete")


def save_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError(f"UTC timestamp needs a timezone: {value}")
    return result.astimezone(timezone.utc)


def az_json(*arguments: str) -> Any:
    with Progress("Azure CLI lookup"):
        return _az_json(*arguments)


def choose_target(args: argparse.Namespace) -> tuple[dict[str, Any], str, str, str]:
    return choose_storage_target(
        args.account, args.history_container, args.current_container, args.subscription,
        lookup=az_json, account_prompt="Existing TEST storage account: ",
    )


def validate_manifest(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if (
        manifest.get("complete") is not True
        or manifest.get("schemaVersion") not in range(1, RUN_SCHEMA_VERSION + 1)
        or not manifest.get("runId")
    ):
        raise ValueError("Seed must be a complete, supported published run")
    utc(manifest["snapshotTimeUtc"])
    entries: dict[str, dict[str, Any]] = {}
    paths = set()
    for item in manifest["files"]:
        path = PurePosixPath(item["path"])
        if path.is_absolute() or ".." in path.parts or "\\" in item["path"] or item["path"] in paths:
            raise ValueError("Seed manifest contains an unsafe or duplicate blob path")
        paths.add(item["path"])
        if item["kind"] not in {"curated", "policy"}:
            continue
        key = item["dataset"] if item["kind"] == "curated" else "policy"
        if key in entries:
            raise ValueError(f"Duplicate seed dataset: {key}")
        if item["kind"] == "curated" and key not in DATASET_FILES:
            raise ValueError(f"Unsupported seed dataset: {key}")
        if not isinstance(item["sizeBytes"], int) or item["sizeBytes"] < 0:
            raise ValueError("Invalid seed file size")
        if key != "policy" and (type(item["rowCount"]) is not int or item["rowCount"] < 0):
            raise ValueError("Invalid seed row count")
        if not re.fullmatch(r"[a-f0-9]{64}", item["sha256"]):
            raise ValueError("Invalid seed file hash")
        entries[key] = item
    if set(entries) != set(DATASET_FILES) | {"policy"}:
        raise ValueError("Seed needs all normal curated datasets and one retained SLA policy")
    return entries


def download_seed(history, manifest: dict[str, Any], root: Path) -> None:
    entries = validate_manifest(manifest)
    root.mkdir()
    for key, item in entries.items():
        path = root / ("sla-policies.json" if key == "policy" else f"{DATASET_FILES[key]}.json.gz")
        with Progress(f"download:{key}", total=item["sizeBytes"], unit="bytes") as progress:
            with path.open("xb") as handle:
                history.get_blob_client(item["path"]).download_blob(progress_hook=progress.update).readinto(handle)
            progress.update(path.stat().st_size)
        with Progress(f"verify-seed:{key}", total=item.get("rowCount"), unit="rows" if key != "policy" else None) as progress:
            if path.stat().st_size != item["sizeBytes"] or sha256(path) != item["sha256"]:
                raise ValueError(f"Seed integrity check failed for {key}")
            if key != "policy":
                actual = sum(1 for _ in progress.track(iter_json_rows(path)))
                if actual != item["rowCount"]:
                    raise ValueError(f"Seed row count mismatch for {key}: {actual} != {item['rowCount']}")


def transform(
    row: dict[str, Any], cohort: int, source_run: str, run_id: str,
    source_time: datetime, snapshot: datetime, *, clone_entities: bool = True,
) -> dict[str, Any]:
    delta = snapshot - source_time
    prefix = f"{run_id}|cohort-{cohort}|"
    result = {}
    for key, value in row.items():
        if clone_entities and key in IDENTIFIERS and value:
            value = prefix + str(value)
        elif clone_entities and key == "AzureResourceId" and value:
            parts = str(value).split("/")
            if "providers" in parts:
                for position in range(parts.index("providers") + 3, len(parts), 2):
                    parts[position] += f"-load-{cohort}"
                value = "/".join(parts)
        elif key == "CollectionRunId" and value:
            value = run_id if value == source_run else run_id + "-history-" + hashlib.sha256(str(value).encode()).hexdigest()[:16]
        elif key.endswith("Utc") and value:
            value = (utc(value) + delta).isoformat().replace("+00:00", "Z")
        result[key] = value
    result["ScenarioId"] = f"LOAD-TEST:{run_id}"
    result.setdefault("SnapshotTimeUtc", snapshot.isoformat().replace("+00:00", "Z"))
    return result


def build_bundle(
    seed: Path, manifest: dict[str, Any], directory: Path, target: int, published_files: int,
    snapshot: datetime, *, history_days: int = 90,
) -> tuple[Path, Path, dict[str, Any]]:
    source_count = next(item["rowCount"] for item in manifest["files"] if item.get("dataset") == "findings")
    if source_count < 1:
        raise ValueError("Cannot expand an empty findings dataset")
    event_count = next(item["rowCount"] for item in manifest["files"] if item.get("dataset") == "findingEvents")
    if event_count < 1:
        raise ValueError("Seed contains no finding lifecycle events; choose a seed with lifecycle history")
    if target < source_count:
        raise ValueError("This extrapolator requires target findings >= seed findings; choose a smaller seed")
    raw_count = published_files - len(DATASET_FILES) - 5
    if not 1 <= raw_count <= target:
        raise ValueError(f"Published files must be between {len(DATASET_FILES) + 6} and {target + len(DATASET_FILES) + 5}")
    source_time = utc(manifest["snapshotTimeUtc"])
    run_id = f"synthetic-{snapshot:%Y%m%dT%H%M%SZ}-loadtest-{uuid4().hex}"
    staged = directory / "staged"
    staged.mkdir()
    raw_root = directory / "raw"
    raw = raw_root / run_id
    raw.mkdir(parents=True)
    cohorts = (target + source_count - 1) // source_count
    counts: dict[str, int] = {}
    prepared = {}
    with tempfile.TemporaryDirectory(prefix="index-", dir=directory) as work:
        workspace = Workspace(Path(work) / "expansion.sqlite")
        try:
            db = workspace.connection
            db.execute("CREATE TABLE seed_findings (finding TEXT PRIMARY KEY, position INTEGER NOT NULL)")
            with Progress("index seed findings", total=source_count, unit="rows") as progress:
                for position, row in enumerate(progress.track(iter_json_rows(seed / "findings.json.gz"))):
                    if not row.get("FindingKey") or not row.get("DeviceId"):
                        raise ValueError("Seed findings require nonempty FindingKey and DeviceId")
                    db.execute("INSERT INTO seed_findings VALUES (?,?)", (row["FindingKey"], position))
                    workspace.changed()
                db.commit()

            def expanded(key: str) -> Iterator[dict[str, Any]]:
                for cohort in range(1 if key in GLOBAL_DATASETS else cohorts):
                    limit = min(source_count, target - cohort * source_count)
                    for position, row in enumerate(iter_json_rows(seed / f"{DATASET_FILES[key]}.json.gz")):
                        if key == "findings" and position >= limit:
                            break
                        if key == "findingEvents" and limit < source_count:
                            found = db.execute(
                                "SELECT position FROM seed_findings WHERE finding=?", (row.get("FindingKey"),),
                            ).fetchone()
                            if found and found[0] >= limit:
                                continue
                        yield transform(
                            row, cohort, manifest["runId"], run_id, source_time, snapshot,
                            clone_entities=key not in GLOBAL_DATASETS,
                        )

            seed_counts = {item["dataset"]: item["rowCount"] for item in manifest["files"] if item["kind"] == "curated"}
            for key, basename in DATASET_FILES.items():
                if key in REBUILT_DATASETS:
                    continue
                path = staged / f"{basename}.json.gz"
                total = seed_counts[key] * (1 if key in GLOBAL_DATASETS else cohorts)
                if key == "findings":
                    total = target
                elif key == "findingEvents" and target % source_count:
                    total = None
                with Progress(f"generate:{key}", total=total, unit="rows") as progress:
                    counts[key] = write_json_rows(path, progress.track(expanded(key)))
                prepared[key] = (path, counts[key])
            with Progress("index expanded findings", total=counts["findings"], unit="rows") as progress:
                findings = workspace.rows(progress.track(JsonRows(prepared["findings"][0], counts["findings"])))
            events = JsonRows(prepared["findingEvents"][0], counts["findingEvents"])
            recommendations = JsonRows(prepared["recommendations"][0], counts["recommendations"])
            recommendation_events = JsonRows(prepared["recommendationEvents"][0], counts["recommendationEvents"])
            runs = JsonRows(prepared["collectionRuns"][0], counts["collectionRuns"])
            with Progress("rebuild summaries/reconciliation", connection=db):
                daily, reconciliation = bounded_summary.summaries(findings, events, workspace, history_days=history_days)
            with Progress("rebuild current run history", connection=db):
                history_rows = bounded_summary.run_history(
                    findings, [], events, recommendations, [], recommendation_events, [], runs, snapshot, run_id, workspace,
                )
            for key, rows in (("dailySummary", daily), ("reconciliation", reconciliation), ("runHistory", history_rows)):
                path = staged / f"{DATASET_FILES[key]}.json.gz"
                with Progress(f"write:{key}", total=len(rows), unit="rows") as progress:
                    counts[key] = write_json_rows(path, progress.track(rows))
                prepared[key] = (path, counts[key])
        finally:
            workspace.close()
    if counts["findings"] != target:
        raise ValueError("Generated finding count does not equal the target")
    if counts["findingEvents"] == 0:
        raise ValueError("Seed contains no finding lifecycle events; choose a seed with lifecycle history")
    rows = iter(iter_json_rows(prepared["findings"][0]))
    page_size, extra = divmod(target, raw_count)
    with Progress("write derived raw pages", total=raw_count, unit="files") as progress:
        for number in range(raw_count):
            path = raw / f"load-test-derived-findings-page-{number + 1:04d}.json.gz"
            with gzip.open(path, "wt", encoding="utf-8") as handle:
                handle.write('{"value":[')
                for index, row in enumerate(islice(rows, page_size + (number < extra))):
                    if index:
                        handle.write(",")
                    handle.write(json.dumps(row, separators=(",", ":")))
                handle.write("]}")
            progress.update(number + 1)
    return assemble_bundle(manifest, prepared, directory, raw, seed / "sla-policies.json", snapshot)


def assemble_bundle(
    manifest: dict[str, Any], prepared: dict[str, tuple[Path, int]], directory: Path,
    raw: Path, policy: Path, snapshot: datetime,
) -> tuple[Path, Path, dict[str, Any]]:
    run_id = raw.name
    counts = {key: count for key, (_path, count) in prepared.items()}
    target = counts["findings"]
    source_count = next(item["rowCount"] for item in manifest["files"] if item.get("dataset") == "findings")
    source_time = utc(manifest["snapshotTimeUtc"])
    raw_count = len(list(raw.glob("*.json.gz")))
    published_files = raw_count + len(DATASET_FILES) + 5
    cohorts = (target + source_count - 1) // source_count
    statuses = [{"Endpoint": "load-test-extrapolation", "Status": "Success"}]
    with Progress("assemble/hash immutable bundle"), startup_diagnostics():
        bundle = create_run_bundle(
            raw, {}, statuses, policy, directory / "history",
            snapshot=snapshot, run_id=run_id, prepared_datasets=prepared,
        )
    generated = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    generated["loadTest"] = {
        "sourceRunId": manifest["runId"], "sourceSnapshotTimeUtc": manifest["snapshotTimeUtc"],
        "sourceManifestPath": f"runs/{source_time:%Y/%m/%d}/{manifest['runId']}/manifest.json",
        "sourceFindings": source_count, "targetFindings": target, "cohorts": cohorts,
        "publishedFilesIncludingPointer": published_files,
        "derivedRawPages": raw_count, "customerFileCompositionKnown": False,
        "historicalRunAggregatesCopied": False, "trackingHistoryCopied": False,
    }
    save_json(bundle / "manifest.json", generated)
    with Progress("verify generated bundle"):
        errors = verify_run_bundle(bundle, raw)
        if errors:
            raise ValueError("Generated bundle verification failed: " + "; ".join(errors))
    if len(generated["files"]) + 2 != published_files:
        raise ValueError("Generated published-file count does not match the target")
    return bundle, raw, {"runId": run_id, "rowCounts": counts, **generated["loadTest"]}


def resume_local_bundle(source: Path, directory: Path) -> tuple[Path, Path, dict[str, Any]]:
    """Reuse exact generated data; write any rebuilt bundle only in a new directory."""
    saved = json.loads((source / "population.json").read_text(encoding="utf-8"))
    if saved.get("published") or saved.get("publicationMayHaveCompleted"):
        raise ValueError("This population was published or publication may have completed; use index-only maintenance instead")
    manifest = json.loads((source / "source-manifest.json").read_text(encoding="utf-8"))
    validate_manifest(manifest)
    if saved.get("sourceRunId") != manifest["runId"]:
        raise ValueError("Saved source manifest does not match the failed population")
    if saved.get("raw"):
        raw = Path(saved["raw"]).resolve()
    else:
        runs = [path for path in (source / "raw").iterdir() if path.is_dir()]
        if len(runs) != 1:
            raise ValueError("Local population must contain exactly one generated raw run")
        raw = runs[0]
    match = re.fullmatch(r"synthetic-(\d{8}T\d{6}Z)-loadtest-[a-f0-9]{32}", raw.name)
    if match is None or not list(raw.glob("*.json.gz")):
        raise ValueError("Local population has no complete generated raw run")
    bundle = Path(saved["bundle"]).resolve() if saved.get("bundle") else source / "history" / raw.name
    completed = bundle / "manifest.json"
    if completed.is_file():
        generated = json.loads(completed.read_text(encoding="utf-8"))
        if generated["runId"] != raw.name:
            raise ValueError("Local bundle and raw run identities differ")
        if all(compatible_index(generated, group) is not None for group in ("primary", "history")):
            errors = verify_run_bundle(bundle, raw)
            if errors:
                raise ValueError("Local bundle integrity failed: " + "; ".join(errors))
            counts = {item["dataset"]: item["rowCount"] for item in generated["files"] if item["kind"] == "curated"}
            return bundle, raw, {"runId": raw.name, "rowCounts": counts, **generated["loadTest"]}
    pending_path = bundle / "manifest.pending.json"
    pending = json.loads(pending_path.read_text(encoding="utf-8")) if pending_path.is_file() else None
    if pending is not None and pending["runId"] != raw.name:
        raise ValueError("Local checkpoint and raw run identities differ")
    entries = {item["dataset"]: item for item in pending["files"] if item["kind"] == "curated"} if pending else {}
    prepared = {}
    for key, basename in DATASET_FILES.items():
        staged = source / "staged" / f"{basename}.json.gz"
        path = staged if staged.is_file() else bundle / "curated" / f"{basename}.json.gz"
        if key in entries:
            item = entries[key]
            if path.stat().st_size != item["sizeBytes"] or sha256(path) != item["sha256"]:
                raise ValueError(f"Local checkpoint integrity failed: {key}")
            count = item["rowCount"]
        else:
            with Progress(f"count retained local:{key}", unit="rows") as progress:
                count = sum(1 for _row in progress.track(iter_json_rows(path)))
        prepared[key] = (path, count)
    policy_entry = next(item for item in manifest["files"] if item["kind"] == "policy")
    policy = bundle / "policy" / PurePosixPath(policy_entry["path"]).name
    if policy.stat().st_size != policy_entry["sizeBytes"] or sha256(policy) != policy_entry["sha256"]:
        raise ValueError("Local retained policy does not match the original seed")
    snapshot = datetime.strptime(match[1], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    return assemble_bundle(manifest, prepared, directory, raw, policy, snapshot)


def publish(service, history_name: str, current_name: str, bundle: Path, raw: Path, etag: str) -> int:
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    with Progress("verify bundle before publication"):
        errors = verify_run_bundle(bundle, raw)
        if errors:
            raise ValueError("Refusing to publish an invalid bundle: " + "; ".join(errors))
    history = service.get_container_client(history_name)
    current = service.get_container_client(current_name).get_blob_client("current/manifest.json")
    data = manifest_path.read_bytes()
    files = len(manifest["files"]) + 2
    total_bytes = sum(item["sizeBytes"] for item in manifest["files"]) + 2 * len(data)
    completed_bytes = 0
    with Progress("publish run", total=total_bytes, unit="bytes") as progress:
        progress.update(0, detail=f"verifiedFiles=0/{files:,}")

        def transferred(current_bytes: int, _total: int | None) -> None:
            progress.update(completed_bytes + current_bytes)

        if current.get_blob_properties().etag != etag:
            raise ValueError("Current pointer changed while generating; refusing publication. Immutable local bundle retained.")
        for number, item in enumerate(manifest["files"], 1):
            folder = raw if item["kind"] == "raw" else bundle / item["kind"]
            path = folder / PurePosixPath(item["path"]).name
            blob = history.get_blob_client(item["path"])
            with path.open("rb") as handle:
                blob.upload_blob(
                    handle, overwrite=False, metadata={"sha256": item["sha256"]},
                    validate_content=True, max_concurrency=2, progress_hook=transferred,
                )
            properties = blob.get_blob_properties()
            if properties.size != item["sizeBytes"] or properties.metadata.get("sha256") != item["sha256"]:
                raise ValueError(f"Uploaded file verification failed: {item['path']}")
            completed_bytes += item["sizeBytes"]
            progress.update(completed_bytes, detail=f"verifiedFiles={number:,}/{files:,}")
        snapshot = utc(manifest["snapshotTimeUtc"])
        immutable_path = f"runs/{snapshot:%Y/%m/%d}/{manifest['runId']}/manifest.json"
        progress.update(completed_bytes, detail=f"verifiedFiles={files - 2:,}/{files:,} writing=immutable-manifest")
        history.get_blob_client(immutable_path).upload_blob(data, overwrite=False, validate_content=True, progress_hook=transferred)
        completed_bytes += len(data)
        progress.update(completed_bytes, detail=f"verifiedFiles={files - 1:,}/{files:,} writing=current-pointer")
        current.upload_blob(
            data, overwrite=True, etag=etag, match_condition=MatchConditions.IfNotModified,
            validate_content=True, progress_hook=transferred,
        )
        completed_bytes += len(data)
        progress.update(completed_bytes, detail=f"verifiedFiles={files:,}/{files:,}")
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--account")
    parser.add_argument("--history-container")
    parser.add_argument("--current-container")
    parser.add_argument("--subscription")
    parser.add_argument("--source-manifest", help="Optional immutable manifest blob path in the history container")
    parser.add_argument("--resume-local", type=Path, help="Reuse a failed/validated population directory without regenerating data")
    parser.add_argument("--findings", type=int, default=1_837_575)
    parser.add_argument("--published-files", type=int, default=2570, help="Includes the final current-pointer upload")
    parser.add_argument("--snapshot-utc", default="2026-10-24T00:59:46Z")
    parser.add_argument("--history-days", type=int, default=90)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "output/load-test-data")
    parser.add_argument("--publish", action="store_true", help="Permit uploads after exact-target confirmation")
    parser.add_argument("--confirm-target", help="Explicit account/history-container/current-container confirmation")
    args = parser.parse_args(argv)
    if args.resume_local and args.source_manifest:
        parser.error("--resume-local cannot be combined with --source-manifest")
    if args.findings < 1 or args.history_days < 1 or not len(DATASET_FILES) + 5 < args.published_files <= args.findings + len(DATASET_FILES) + 5:
        parser.error("Use positive findings/history-days and enough findings for nonempty raw pages")
    report: dict[str, Any] = {"status": "starting", "published": False}
    directory: Path | None = None
    try:
        snapshot = utc(args.snapshot_utc)
        account, storage, history_name, current_name = choose_target(args)
        target = f"{storage}/{history_name}/{current_name}"
        saved = None
        if args.resume_local:
            args.resume_local = args.resume_local.resolve()
            saved = json.loads((args.resume_local / "population.json").read_text(encoding="utf-8"))
            if saved.get("target") != target or saved.get("subscriptionId") != account["id"]:
                raise ValueError("Local population target/subscription does not match; no Azure writes performed")
        print(f"Intent: READ the seed from {target}. Local output only: {not args.publish}.")
        print("Source data is sensitive. No application code/settings, containers, or retained blobs will be deleted or modified.")
        if args.publish:
            print("WRITE intent: append a NEW synthetic run; replace ONLY the separate current/manifest.json after validation.")
            if args.confirm_target is not None and args.confirm_target != target:
                raise ValueError("Exact test-target confirmation did not match; no Azure writes performed")
        with AzureCliCredential(tenant_id=account["tenantId"]) as credential:
            with BlobServiceClient(f"https://{storage}.blob.core.windows.net", credential=credential) as service:
                history = service.get_container_client(history_name)
                pointer = service.get_container_client(current_name).get_blob_client("current/manifest.json")
                with Progress("read seed manifest"):
                    history.get_container_properties()
                    properties = pointer.get_blob_properties()
                    pointer_data = pointer.download_blob(etag=properties.etag, match_condition=MatchConditions.IfNotModified).readall()
                    manifest = json.loads(pointer_data)
                    if args.resume_local:
                        manifest = json.loads((args.resume_local / "source-manifest.json").read_text(encoding="utf-8"))
                    elif args.source_manifest:
                        manifest = json.loads(history.get_blob_client(args.source_manifest).download_blob().readall())
                    elif manifest.get("loadTest"):
                        raise ValueError("Current snapshot is already generated load-test data. Use --source-manifest for the original seed.")
                    validate_manifest(manifest)
                directory = args.output_dir.resolve() / ("population-" + uuid4().hex)
                directory.mkdir(parents=True)
                baseline = saved.get("baselineEtag", properties.etag) if saved else properties.etag
                if args.publish and baseline != properties.etag:
                    raise ValueError("Current pointer changed since the saved population; refusing publication")
                report.update(
                    target=target, subscriptionId=account["id"], sourceRunId=manifest["runId"], baselineEtag=baseline,
                )
                save_json(directory / "population.json", report)
                save_json(directory / "source-manifest.json", manifest)
                if args.resume_local:
                    bundle, raw, details = resume_local_bundle(args.resume_local, directory)
                    report["resumedFrom"] = str(args.resume_local)
                else:
                    with tempfile.TemporaryDirectory(prefix="seed-", dir=directory) as temporary:
                        seed = Path(temporary) / "datasets"
                        download_seed(history, manifest, seed)
                        bundle, raw, details = build_bundle(
                            seed, manifest, directory, args.findings, args.published_files, snapshot,
                            history_days=args.history_days,
                        )
                report.update(details, bundle=str(bundle), raw=str(raw), status="validated")
                save_json(directory / "population.json", report)
                print(json.dumps(report, indent=2), flush=True)
                if args.publish:
                    confirmation = args.confirm_target or input(f"Review the generated counts above. Type {target} to PUBLISH: ").strip()
                    if confirmation != target:
                        raise ValueError("Exact test-target confirmation did not match; no Azure writes performed")
                    report["status"] = "publishing"
                    save_json(directory / "population.json", report)
                    count = publish(service, history_name, current_name, bundle, raw, baseline)
                    report.update(status="published", published=True, uploadedFiles=count)
                print(f"Result: {directory / 'population.json'}")
                if not args.publish:
                    print(f"Local bundle validated; no Azure writes. Reuse it with --resume-local {directory} --publish.")
        return 0
    except (AzureError, OSError, ValueError, RuntimeError, KeyError, TypeError, sqlite3.Error, subprocess.TimeoutExpired) as error:
        report.update(
            publicationMayHaveCompleted=report["status"] == "publishing",
            status="failed", error=f"{type(error).__name__}: {error}",
        )
        print(report["error"], file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        report.update(
            publicationMayHaveCompleted=report["status"] == "publishing",
            status="interrupted", error="Interrupted. If publication had begun, inspect the current pointer before retrying; no rollback/deletion is attempted.",
        )
        print(report["error"], file=sys.stderr)
        return 130
    finally:
        if directory is not None:
            if report["status"] in {"starting", "publishing"}:
                report.update(
                    publicationMayHaveCompleted=report["status"] == "publishing",
                    status="failed", error="Unexpected failure; inspect the CLI traceback. No rollback/deletion is attempted.",
                )
            save_json(directory / "population.json", report)


if __name__ == "__main__":
    raise SystemExit(main())
