"""Measure actual local Uvicorn cold starts, without Azure or customer data."""

from __future__ import annotations

import argparse
import gzip
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from uuid import uuid4

import requests

from benchmark_dashboard_queries import generate_data
from vulnerability_view.dashboard_preparation import initial_filters
from vulnerability_view.dashboard_queries import PREPARED_VIEWS


ROOT = Path(__file__).resolve().parents[1]
LISTENING = re.compile(r"Uvicorn running on http://127\.0\.0\.1:(\d+)")


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def process_usage() -> dict[str, Any]:
    if sys.platform not in {"darwin", "linux"}:
        return {"peakRssMiB": None, "cpuSeconds": None, "resourceStatus": "unavailable on this platform"}
    import resource

    usage = resource.getrusage(resource.RUSAGE_SELF)
    rss_bytes = usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024)
    return {
        "peakRssMiB": round(rss_bytes / 1024**2, 3),
        "cpuSeconds": round(usage.ru_utime + usage.ru_stime, 3),
        "resourceStatus": "child-process usage through application shutdown, including HTTP verification",
    }


def serve(root: Path, metrics: Path) -> None:
    try:
        import uvicorn
        from vulnerability_view.config import Settings
        from vulnerability_view.dashboard_server import create_app

        application = create_app(
            Settings(
                auth_mode="managed_identity", dashboard_data_source="local",
                dashboard_static_dir=str(ROOT / "dashboard"),
                dashboard_auth_enabled=False, dashboard_recommendation_tracking_enabled=False,
                dashboard_branding_enabled=False,
            ),
            project_root=root,
        )
        lifespan = application.router.lifespan_context

        @asynccontextmanager
        async def measured_lifespan(app):
            try:
                async with lifespan(app) as state:
                    yield state
            finally:
                # Uvicorn replays SIGTERM after shutdown, bypassing the outer finally.
                write_json(metrics, process_usage())

        application.router.lifespan_context = measured_lifespan
        uvicorn.run(application, host="127.0.0.1", port=0, workers=1, log_level="info")
    finally:
        write_json(metrics, process_usage())


def child_environment(scratch: Path) -> dict[str, str]:
    prefixes = ("AZURE_", "WEBSITE_", "IDENTITY_", "MSI_", "DASHBOARD_", "STORAGE_")
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith(prefixes) and key not in {"AUTH_MODE", "ALLOW_LOCAL_CLIENT_SECRET"}
    }
    environment.update(
        PYTHONPATH=os.pathsep.join((str(ROOT / "src"), str(ROOT / "tests"))),
        PYTHONUNBUFFERED="1", AUTH_MODE="managed_identity", ALLOW_LOCAL_CLIENT_SECRET="false",
        DASHBOARD_DATA_SOURCE="local", DASHBOARD_AUTH_ENABLED="false",
        DASHBOARD_RECOMMENDATION_TRACKING_ENABLED="false", DASHBOARD_BRANDING_ENABLED="false",
        TMPDIR=str(scratch), TEMP=str(scratch), TMP=str(scratch),
    )
    return environment


def stop_process(process: subprocess.Popen) -> bool:
    if process.poll() is not None:
        return False
    process.terminate()
    try:
        process.wait(timeout=10)
        return False
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
        return True


def request_json(
    session: requests.Session, url: str, *, deadline: float | None = None, **kwargs: Any,
) -> dict[str, Any]:
    remaining = 30 if deadline is None else min(30, deadline - time.perf_counter())
    if remaining <= 0:
        raise TimeoutError("Readiness verification exceeded the startup deadline")
    response = session.request(url=url, timeout=remaining, **kwargs)
    response.raise_for_status()
    value = response.json()
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object from {url}")
    return value


def verify_ready(session: requests.Session, base: str, run_id: str, deadline: float) -> dict[str, Any]:
    health = request_json(session, base + "/api/health", method="GET", deadline=deadline)
    if health.get("dataSource") != "local" or health.get("dashboardReady") is not True:
        raise ValueError("Health did not confirm a ready local dashboard")
    snapshot = request_json(session, base + "/api/dashboard/snapshot", method="GET", deadline=deadline)
    diagnostics = request_json(session, base + "/api/diagnostics", method="GET", deadline=deadline)
    preparation = diagnostics["dashboardQueries"]["preparation"]
    if (
        snapshot.get("runId") != run_id or preparation["status"] != "ready"
        or preparation["readySnapshotId"] != snapshot["snapshotId"]
    ):
        raise ValueError("Prepared snapshot does not match the generated run")
    return {"snapshot": snapshot, "diagnostics": diagnostics, "health": health}


def startup_evidence(log: str, findings: int, events: int) -> dict[str, Any]:
    workspace = re.findall(
        r"stage=prepare-workspace-indexes event=complete elapsedSeconds=([\d.]+)", log,
    )
    prepared = {
        view: float(seconds) for view, seconds in re.findall(
            r"stage=view:([^:\s]+):\d+/\d+ event=complete elapsedSeconds=([\d.]+)", log,
        )
    }
    loaded = {
        name: int(count) for name, count in re.findall(
            r"stage=load-rows:([\w-]+) event=complete [^\n]*? rows=(\d+)", log,
        )
    }
    if not workspace or prepared:
        raise ValueError("Startup logs do not confirm shared-index readiness without report preparation")
    if loaded.get("findings") != findings:
        raise ValueError("Startup logs do not confirm the requested finding ingestion counts")
    return {"workspaceIndexSeconds": max(map(float, workspace)), "preparedViewSeconds": prepared, "loadedRows": loaded}


def verify_views(
    session: requests.Session, base: str, snapshot_id: str, expected_findings: int,
) -> dict[str, float]:
    filters = initial_filters(ROOT / "dashboard/config.js")
    timings = {}
    for view in PREPARED_VIEWS:
        started = time.perf_counter()
        result = request_json(
            session, base + "/api/dashboard/query", method="POST",
            json={"snapshotId": snapshot_id, "view": view, "filters": filters, "mode": "findings", "limit": 100},
        )
        if result.get("snapshotId") != snapshot_id or result["scope"]["findings"] != expected_findings:
            raise ValueError(f"{view} returned an incorrect snapshot or finding count")
        timings[view] = round(time.perf_counter() - started, 3)
    return timings


def run_cold_start(
    root: Path, directory: Path, attempt: int, run_id: str, findings: int, events: int,
    timeout_seconds: float, max_rss_mib: float,
) -> dict[str, Any]:
    log_path = directory / f"startup-{attempt}.log"
    metrics_path = directory / f"resources-{attempt}.json"
    result: dict[str, Any] = {"attempt": attempt, "status": "failed", "logFile": log_path.name}
    with tempfile.TemporaryDirectory(prefix=f"worker-{attempt}-", dir=directory) as scratch:
        with log_path.open("xb") as log, requests.Session() as session:
            session.trust_env = False
            started = time.perf_counter()
            process = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "--serve-root", str(root),
                 "--metrics-file", str(metrics_path)],
                cwd=root, env=child_environment(Path(scratch)), stdout=log, stderr=subprocess.STDOUT,
            )
            result["pid"] = process.pid
            deadline = started + timeout_seconds
            try:
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(f"Uvicorn exited before readiness (code {process.returncode})")
                    if time.perf_counter() - started >= timeout_seconds:
                        result["status"] = "timeout"
                        raise TimeoutError(f"Startup exceeded {timeout_seconds:g} seconds")
                    startup_log = log_path.read_text(encoding="utf-8")
                    match = LISTENING.search(startup_log)
                    if match:
                        base = f"http://127.0.0.1:{match[1]}"
                        health = request_json(session, base + "/api/health", method="GET", deadline=deadline)
                        if not health.get("dashboardReady"):
                            status = request_json(session, base + "/api/dashboard/status", method="GET", deadline=deadline)
                            if status.get("status") == "error":
                                raise RuntimeError("Dashboard data preparation failed; see startup log")
                            time.sleep(min(.1, timeout_seconds / 10))
                            continue
                        ready = verify_ready(session, base, run_id, deadline)
                        if time.perf_counter() >= deadline:
                            result["status"] = "timeout"
                            raise TimeoutError("Readiness verification exceeded the startup deadline")
                        result["startupSeconds"] = round(time.perf_counter() - started, 3)
                        result.update(ready)
                        result.update(startup_evidence(log_path.read_text(encoding="utf-8"), findings, events))
                        result["verifiedViews"] = verify_views(
                            session, base, ready["snapshot"]["snapshotId"], findings - (findings + 3) // 4,
                        )
                        after = request_json(session, base + "/api/diagnostics", method="GET")
                        retained = after["dashboardQueries"]["retainedSnapshots"]
                        indexed = next(item["indexedRows"] for item in retained if item["snapshotId"] == ready["snapshot"]["snapshotId"])
                        if indexed.get("findings") != findings or indexed.get("finding-events") != events:
                            raise ValueError("Post-readiness queries did not index the exact finding/event counts")
                        result["loadedRows"] = indexed
                        result["status"] = "ready"
                        break
                    time.sleep(min(0.1, timeout_seconds / 10))
            except (RuntimeError, TimeoutError, ValueError, KeyError, requests.RequestException) as error:
                if isinstance(error, (TimeoutError, requests.Timeout)):
                    result["status"] = "timeout"
                result["error"] = f"{type(error).__name__}: {error}"
            finally:
                result["forcedKill"] = stop_process(process)
                result["returncode"] = process.returncode
                result["totalChildSeconds"] = round(time.perf_counter() - started, 3)
    if metrics_path.exists():
        result.update(json.loads(metrics_path.read_text(encoding="utf-8")))
    else:
        result.update(peakRssMiB=None, cpuSeconds=None, resourceStatus="unavailable: child did not write final metrics")
    if result["status"] == "ready":
        clean_exit = result["returncode"] in (0, -signal.SIGTERM)
        shutdown_complete = "Application shutdown complete." in log_path.read_text(encoding="utf-8")
        if result["forcedKill"] or not clean_exit or not shutdown_complete:
            result.update(status="failed", error="Uvicorn did not shut down cleanly")
        elif result["peakRssMiB"] is None:
            result.update(status="failed", error="Cannot verify the requested peak-RSS threshold on this platform")
        elif result["peakRssMiB"] > max_rss_mib:
            result.update(status="failed", error=f"Peak RSS exceeded the {max_rss_mib:g} MiB acceptance threshold")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=1_800_000)
    parser.add_argument("--events", type=int, default=1_800_000)
    parser.add_argument("--devices", type=int, default=2075)
    parser.add_argument("--cves", type=int, default=13222)
    parser.add_argument("--recommendations", type=int, default=100)
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--timeout-seconds", type=float, default=1800)
    parser.add_argument("--max-rss-mib", type=float, default=512)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "output/dashboard-startup-benchmarks")
    parser.add_argument("--serve-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--metrics-file", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.serve_root:
        if not args.metrics_file:
            parser.error("--serve-root requires --metrics-file")
        serve(args.serve_root, args.metrics_file)
        return 0
    if (
        args.rows < 4 or args.events < 0 or args.runs < 1
        or min(args.devices, args.cves, args.recommendations) < 1
        or max(args.devices, args.cves, args.recommendations) > args.rows
        or not 0 < args.timeout_seconds < float("inf") or not 0 < args.max_rss_mib < float("inf")
    ):
        parser.error("Use rows >= 4, events >= 0, runs >= 1, dimensions in 1..rows, and positive finite thresholds")
    run_id = "startup-" + uuid4().hex
    directory = args.output_dir.resolve() / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + run_id)
    directory.mkdir(parents=True)
    report: dict[str, Any] = {
        "schemaVersion": 1, "status": "running", "runId": run_id,
        "scenario": {
            "findings": args.rows, "findingEvents": args.events, "devices": args.devices,
            "distinctFindingCves": args.cves, "recommendations": args.recommendations,
            "mixedLifecycle": True, "trackingEnabled": False, "coldStarts": args.runs,
        },
        "host": {"platform": platform.platform(), "python": platform.python_version(),
                 "cpuCount": os.cpu_count(), "resourceLimitsApplied": False},
        "thresholds": {"startupSeconds": args.timeout_seconds, "peakRssMiB": args.max_rss_mib},
        "runs": [],
    }
    report_path = directory / "results.json"
    write_json(report_path, report)
    print(f"Generating synthetic data; results: {report_path}", flush=True)
    try:
        with tempfile.TemporaryDirectory(prefix="data-", dir=directory) as temporary:
            root = Path(temporary)
            source = root / "dashboard/data"
            started = time.perf_counter()
            generate_data(
                source, args.rows, args.events, True, devices=args.devices, cves=args.cves,
                recommendations=args.recommendations, run_id=run_id,
            )
            for path in source.glob("*.json.gz"):
                with gzip.open(path, "rb") as compressed, path.with_suffix("").open("xb") as plain:
                    shutil.copyfileobj(compressed, plain)
                path.unlink()
            (root / "config").mkdir()
            shutil.copyfile(ROOT / "config/sla-policies.json", root / "config/sla-policies.json")
            report["generationSeconds"] = round(time.perf_counter() - started, 3)
            report["datasetBytes"] = sum(path.stat().st_size for path in source.iterdir())
            write_json(report_path, report)
            for attempt in range(1, args.runs + 1):
                print(f"Starting cold start {attempt}/{args.runs}; log: {directory / f'startup-{attempt}.log'}", flush=True)
                result = run_cold_start(
                    root, directory, attempt, run_id, args.rows, args.events, args.timeout_seconds, args.max_rss_mib,
                )
                report["runs"].append(result)
                write_json(report_path, report)
                print(json.dumps(result), flush=True)
                if result["status"] != "ready":
                    break
            report["status"] = "passed" if (
                len(report["runs"]) == args.runs and all(run["status"] == "ready" for run in report["runs"])
            ) else "failed"
    except (OSError, ValueError) as error:
        report.update(status="failed", error=f"{type(error).__name__}: {error}")
    except KeyboardInterrupt:
        report.update(status="interrupted", error="Benchmark interrupted by user")
        return 130
    finally:
        write_json(report_path, report)
    print(f"{report['status']}: {report_path}", flush=True)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
