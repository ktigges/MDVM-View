"""Opt-in synthetic raw replay/finalization benchmark; never accesses Azure."""

import argparse
import cProfile
import json
import pstats
import resource
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from itertools import islice
from pathlib import Path

from vulnerability_view.dataprep_cli import advance_archived_run
from vulnerability_view.config import Settings
from vulnerability_view.defender_client import ENDPOINTS
from vulnerability_view.resumable_processing import STAGES
from vulnerability_view.storage_writer import archive_raw_page, archive_raw_rows
from vulnerability_view.bounded_processing import write_json_rows


MACHINES = 2122
CVES = 13604
PRODUCTS = 128
SNAPSHOT = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
SEVERITIES = ("Critical", "High", "Medium", "Low")


class BudgetExpired(BaseException):
    pass


def finding_row(index):
    machine = index % MACHINES
    cve = (index // MACHINES + machine * 17) % CVES
    return {
        "id": f"finding-{index}", "machineId": f"device-{machine}",
        "cveId": f"CVE-2026-{cve:05d}", "severity": SEVERITIES[cve % 4],
        "productName": f"Product-{index // MACHINES % PRODUCTS}",
        "productVendor": f"Vendor-{index // MACHINES % 16}", "productVersion": f"{1 + index % 20}.0",
    }


def retained_events(count, findings):
    dates = [
        (SNAPSHOT - timedelta(days=day)).isoformat().replace("+00:00", "Z")
        for day in range(1, 91)
    ]
    for index in range(count):
        finding = finding_row(index % findings)
        machine = index % findings % MACHINES
        yield {
            "EventId": f"old-{index}", "FindingKey": finding["id"],
            "EventType": ("New", "Fixed", "Reopened")[index % 3],
            "EventTimeUtc": dates[index % 90], "EffectiveTimeUtc": dates[index % 90],
            "CollectionRunId": f"prior-{index % 90}",
            "DeviceId": finding["machineId"], "DeviceName": f"host-{machine}",
            "CveId": finding["cveId"], "Severity": finding["severity"],
            "AssetClass": "TraditionalIT",
            "OwnerTeam": "Endpoint Operations" if machine % 3 else "Server Operations",
            "SubscriptionId": "", "DataOrigin": "Live",
        }


def generate_inputs(root, findings, history_events):
    run_id = f"live-{SNAPSHOT:%Y%m%dT%H%M%SZ}"
    raw = root / "raw" / run_id
    dates = [
        (SNAPSHOT - timedelta(days=day)).isoformat().replace("+00:00", "Z")
        for day in range(1, 91)
    ]
    sources = {
        "machines": [{
            "id": f"device-{i}", "computerDnsName": f"host-{i}",
            "osPlatform": "Linux" if i % 3 == 0 else "Windows11",
            "healthStatus": "Active", "onboardingStatus": "Onboarded",
            "lastSeen": "2026-10-20T12:00:00Z",
        } for i in range(min(MACHINES, findings))],
        "vulnerabilities": [{
            "id": f"CVE-2026-{i:05d}", "severity": SEVERITIES[i % 4],
            "cvssV3": (9.5, 8.0, 5.0, 2.0)[i % 4],
            "firstDetected": dates[i % 90], "publicExploit": i % 5 == 0,
            "description": f"Synthetic vulnerability metadata for CVE-2026-{i:05d}",
        } for i in range(CVES)],
        "recommendations": [{
            "id": f"va-_-product-{i}", "productName": f"Product-{i}",
            "recommendationName": f"Update Product-{i}",
        } for i in range(PRODUCTS)],
    }
    for endpoint in ENDPOINTS:
        if endpoint.name != "machine_vulnerabilities":
            archive_raw_rows(endpoint.name, sources.get(endpoint.name, []), run_id, raw.parent)
            continue
        page = 0
        for machine in range(min(MACHINES, findings)):
            rows = (finding_row(i) for i in range(machine, findings, MACHINES))
            while batch := list(islice(rows, 2500)):
                page += 1
                archive_raw_page(
                    endpoint.name, page, json.dumps({"value": batch}, separators=(",", ":")).encode(),
                    run_id, raw.parent,
                )
    baseline = {}
    if history_events:
        history = root / "baseline-finding-events.json.gz"
        write_json_rows(history, retained_events(history_events, findings))
        baseline["findingEvents"] = history
    return raw, baseline


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", type=int, default=3_000_000)
    parser.add_argument("--history-events", type=int, default=3_300_000)
    parser.add_argument("--budget", type=int, default=1800)
    parser.add_argument("--stop-after", choices=STAGES[:-1], default="bundle")
    parser.add_argument("--profile", action="store_true", help="Save cProfile data (adds measurement overhead)")
    parser.add_argument("--enforce-targets", action="store_true")
    parser.add_argument("--root", type=Path, default=Path(".bounded-benchmark"))
    args = parser.parse_args(argv)
    if args.findings < 1 or args.history_events < 0 or args.budget < 1:
        parser.error("findings and budget must be positive; history-events must be nonnegative")
    root = args.root
    if root.exists() and any(root.iterdir()):
        parser.error("root must be a new or empty local directory; existing results will not be overwritten")
    root.mkdir(parents=True, exist_ok=True)
    generation_start = time.perf_counter()
    raw, baseline = generate_inputs(root, args.findings, args.history_events)
    generation_seconds = time.perf_counter() - generation_start
    state, stages = None, []
    started = time.perf_counter()
    cpu_started = time.process_time()
    phase = "normalize"
    latest_progress = None
    target_reached = timed_out = False
    profiler = cProfile.Profile() if args.profile else None
    progress_file = (root / "progress.jsonl").open("w", encoding="utf-8")

    def progress(message):
        nonlocal latest_progress
        latest_progress = {
            "seconds": round(time.perf_counter() - started, 3),
            "cpuSeconds": round(time.process_time() - cpu_started, 3),
            "message": message,
        }
        progress_file.write(json.dumps(latest_progress) + "\n")
        progress_file.flush()

    def expire(*_):
        raise BudgetExpired()

    previous_handler = signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, args.budget)
    if profiler:
        profiler.enable()
    try:
        while not state or not state["done"]:
            phase = state["nextStage"] if state else "normalize"
            phase_start, phase_cpu = time.perf_counter(), time.process_time()
            state = advance_archived_run(
                raw, Settings(), baseline, Path("config/sla-policies.json"), root / "work",
                snapshot=SNAPSHOT, run_id=raw.name, state=state, input_identity="benchmark-frozen-inputs",
                progress_callback=progress,
            )
            stages.append({
                "stage": phase, "seconds": round(time.perf_counter() - phase_start, 3),
                "cpuSeconds": round(time.process_time() - phase_cpu, 3),
            })
            print(json.dumps(stages[-1]), flush=True)
            if phase == args.stop_after:
                target_reached = True
                break
    except BudgetExpired:
        timed_out = True
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        elapsed, cpu_seconds = time.perf_counter() - started, time.process_time() - cpu_started
        progress_file.close()
        if profiler:
            profiler.disable()
            profiler.dump_stats(str(root / "profile.pstats"))
            with (root / "profile.txt").open("w", encoding="utf-8") as handle:
                stats = pstats.Stats(profiler, stream=handle)
                stats.sort_stats("cumulative").print_stats(40)
                stats.sort_stats("tottime").print_stats(40)
        counts = {}
        if state:
            metadata = json.loads(Path(state["checkpoint"]["reference"]).read_text())
            counts = {key: item["rowCount"] for key, item in metadata["datasets"].items()}
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        report = {
            "requestedFindings": args.findings, "retainedHistoryEvents": args.history_events,
            "complete": bool(state and state["done"]), "stopAfter": args.stop_after,
            "targetReached": target_reached, "timedOut": timed_out, "profiled": args.profile,
            "budgetSeconds": args.budget, "elapsedSeconds": round(elapsed, 3),
            "cpuSeconds": round(cpu_seconds, 3), "generationSeconds": round(generation_seconds, 3),
            "peakRssBytes": rss if sys.platform == "darwin" else rss * 1024,
            "completedStages": stages, "checkpointCounts": counts, "state": state,
            "interruptedStage": phase if not target_reached else None,
            "latestProgress": latest_progress,
        }
        (root / "report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report), flush=True)
    events_expected = STAGES.index(args.stop_after) >= STAGES.index("finding-events")
    if args.enforce_targets and (
        not target_reached or timed_out or elapsed > args.budget or counts.get("findings") != args.findings
        or (events_expected and counts.get("findingEvents") != args.findings + args.history_events)
    ):
        raise RuntimeError("Finalization missed its time budget or did not retain every finding/history event")
    return report


if __name__ == "__main__":
    main()
