"""Run a bounded-duration representative finalization benchmark without pytest."""

import argparse
import json
import resource
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from vulnerability_view.dataprep_cli import advance_archived_run
from vulnerability_view.config import Settings
from vulnerability_view.defender_client import ENDPOINTS
from vulnerability_view.storage_writer import archive_raw_rows
from vulnerability_view.bounded_processing import write_json_rows


class BudgetExpired(BaseException):
    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", type=int, default=2_000_000)
    parser.add_argument("--history-events", type=int, default=0)
    parser.add_argument("--budget", type=int, default=300)
    parser.add_argument("--enforce-targets", action="store_true")
    parser.add_argument("--root", type=Path, default=Path(".bounded-benchmark"))
    args = parser.parse_args()
    if args.findings < 1 or args.history_events < 0 or args.budget < 1:
        parser.error("findings and budget must be positive; history-events must be nonnegative")
    root = args.root
    root.mkdir(parents=True, exist_ok=True)
    run_id = "live-20261020T120000Z"
    snapshot = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
    raw = root / "raw" / run_id
    sources = {
        "machines": [
            {"id": f"device-{i}", "computerDnsName": f"host-{i}", "osPlatform": "Windows11",
             "healthStatus": "Active", "lastSeen": "2026-10-20T12:00:00Z"}
            for i in range(2000)
        ],
        "vulnerabilities": [
            {"id": f"CVE-2026-{i:05d}", "severity": "High", "cvssV3": 8.0, "publicExploit": i % 2 == 0}
            for i in range(100)
        ],
    }
    generation_start = time.perf_counter()
    for endpoint in ENDPOINTS:
        rows = (
            {"id": f"finding-{i}", "machineId": f"device-{i % 2000}", "cveId": f"CVE-2026-{i % 100:05d}",
             "severity": "High", "productName": "Browser", "productVersion": "1"}
            for i in range(args.findings)
        ) if endpoint.name == "machine_vulnerabilities" else sources.get(endpoint.name, [])
        archive_raw_rows(endpoint.name, rows, run_id, raw.parent)
    baseline = {}
    if args.history_events:
        history = root / "baseline-finding-events.json.gz"
        write_json_rows(history, ({
            "EventId": f"old-{i}", "FindingKey": f"finding-{i % args.findings}",
            "EventType": "New", "EventTimeUtc": "2026-10-19T12:00:00Z",
            "EffectiveTimeUtc": "2026-10-19T12:00:00Z", "CollectionRunId": "prior",
            "DeviceId": f"device-{i % 2000}", "DeviceName": f"host-{i % 2000}",
            "CveId": f"CVE-2026-{i % 100:05d}", "Severity": "High",
            "AssetClass": "TraditionalIT", "OwnerTeam": "Endpoints",
            "SubscriptionId": "", "DataOrigin": "Live",
        } for i in range(args.history_events)))
        baseline["findingEvents"] = history
    generation_seconds = time.perf_counter() - generation_start
    state, stages = None, []
    started = time.perf_counter()
    cpu_started = time.process_time()
    complete = False

    def expire(*_):
        raise BudgetExpired()

    signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, args.budget)
    try:
        while not state or not state["done"]:
            phase = state["nextStage"] if state else "normalize"
            phase_start = time.perf_counter()
            state = advance_archived_run(
                raw, Settings(), baseline, Path("config/sla-policies.json"), root / "work",
                snapshot=snapshot, run_id=run_id, state=state, input_identity="benchmark-frozen-inputs",
            )
            stages.append({"stage": phase, "seconds": round(time.perf_counter() - phase_start, 3)})
            print(json.dumps(stages[-1]), flush=True)
        complete = True
    except BudgetExpired:
        pass
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    counts = {}
    if state:
        metadata = json.loads(Path(state["checkpoint"]["reference"]).read_text())
        counts = {key: item["rowCount"] for key, item in metadata["datasets"].items()}
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    report = {
        "requestedFindings": args.findings, "retainedHistoryEvents": args.history_events,
        "complete": complete, "budgetSeconds": args.budget,
        "elapsedSeconds": round(time.perf_counter() - started, 3),
        "cpuSeconds": round(time.process_time() - cpu_started, 3),
        "generationSeconds": round(generation_seconds, 3),
        "peakRssBytes": rss if sys.platform == "darwin" else rss * 1024,
        "completedStages": stages, "checkpointCounts": counts, "state": state,
    }
    (root / "report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report), flush=True)
    if args.enforce_targets and (
        not complete or report["elapsedSeconds"] > args.budget or counts.get("findings") != args.findings
        or counts.get("findingEvents") != args.findings + args.history_events
    ):
        raise RuntimeError("Finalization missed its time budget or did not retain every finding/history event")


if __name__ == "__main__":
    main()
