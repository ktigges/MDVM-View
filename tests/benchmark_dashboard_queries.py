"""Exercise real disk-backed dashboard queries at million-finding scale."""

import argparse
import json
import sys
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

from vulnerability_view.bounded_processing import write_json_rows
from vulnerability_view.dashboard_queries import DashboardQueryEngine, PREPARED_VIEWS
from vulnerability_view.dashboard_preparation import initial_filters
from vulnerability_view.dashboard_snapshots import MAX_CACHE_BYTES
from vulnerability_view.dataset_io import JsonRows


SNAPSHOT_TIME = "2026-10-24T00:59:46Z"


def generate_data(
    source: Path, rows: int, events: int, mixed_lifecycle: bool = False, *,
    devices: int = 2000, cves: int = 13217, recommendations: int = 20,
    run_id: str = "benchmark",
) -> None:
    """Write shared, streamed synthetic fixtures for query and server benchmarks."""
    snapshot_time = SNAPSHOT_TIME
    source.mkdir(parents=True, exist_ok=True)
    datasets = {
        "devices": [
            {"DeviceId": f"device-{index}", "DeviceName": f"host-{index}",
             "AssetClass": "TraditionalIT", "DataOrigin": "Live", "OwnerTeam": "Endpoints",
             "OnboardingStatus": "Onboarded", "HealthStatus": "Active",
             "LastSeenUtc": snapshot_time, "SnapshotTimeUtc": snapshot_time}
            for index in range(devices)
        ],
        "recommendations": [
            {"RecommendationId": f"rec-{index}", "RecommendationName": f"Update software {index}",
             "ProductName": f"software-{index}", "RemediationType": "Update",
             "SeverityScore": 8.8, "DataOrigin": "Live", "Status": "Active"}
            for index in range(recommendations)
        ],
        "collection-runs": [{
            "CollectionRunId": run_id, "SnapshotTimeUtc": snapshot_time,
            "DataOrigin": "Live", "Endpoint": "machine_vulnerabilities", "Status": "Success",
        }],
    }
    names = [
        "findings", "devices", "recommendations", "collection-runs", "finding-events",
        "recommendation-events", "run-history", "recommendation-machines", "daily-summary",
        "secure-scores", "subscriptions", "remediation-activities", "vulnerabilities",
    ]
    snapshot = datetime.fromisoformat(snapshot_time.replace("Z", "+00:00"))

    def lifecycle(index):
        if not mixed_lifecycle:
            return {}
        first = snapshot - timedelta(days=5 + index % 90)
        status = ("Fixed", "PendingVerification", "Reopened", "Open")[index % 4]
        absence = snapshot
        due = first + timedelta(days=30)
        fixed = absence if status == "Fixed" else snapshot - timedelta(days=3) if status == "Reopened" else None
        iso = lambda value: value.isoformat().replace("+00:00", "Z") if value else None
        return {
            "FindingStatus": status, "FirstSeenUtc": iso(first), "FirstObservedUtc": iso(first),
            "FixedUtc": iso(fixed), "EffectiveRemediationUtc": iso(absence) if status in ("Fixed", "PendingVerification") else None,
            "ReopenedUtc": iso(snapshot - timedelta(days=2)) if status == "Reopened" else None,
            "SlaDueUtc": iso(due),
            "SlaStatus": ("FixedWithinSla" if absence <= due else "FixedOutsideSla") if status in ("Fixed", "PendingVerification")
                else ("OpenWithinSla" if snapshot <= due else "OpenOutsideSla"),
        }

    for name in names:
        records = (
            {
                "FindingKey": f"finding-{index:09d}", "DeviceId": f"device-{index % devices}",
                "DeviceName": f"host-{index % devices}", "CveId": f"CVE-2026-{index % cves:05d}",
                "RecommendationId": f"rec-{index % recommendations}", "RecommendationName": f"Update software {index % recommendations}",
                "SoftwareName": f"software-{index % recommendations}", "SoftwareVersion": "123.4",
                "OSPlatform": "Windows11", "AssetClass": "TraditionalIT", "DataOrigin": "Live",
                "OwnerTeam": "Endpoints", "SubscriptionId": "", "FindingStatus": "Open",
                "Severity": ["Critical", "High", "Medium", "Low"][index % 4],
                "PriorityScore": index % 100, "CvssScore": 8.8, "SlaStatus": "OpenWithinSla",
                "SlaDueUtc": "2026-11-24T00:59:46Z", "FirstSeenUtc": "2026-10-23T00:59:46Z",
                "FirstObservedUtc": "2026-10-23T00:59:46Z", "LastSeenUtc": snapshot_time,
                "LastObservedUtc": snapshot_time, "SnapshotTimeUtc": snapshot_time,
                "CollectionRunId": run_id, "KnownExploit": False,
                "PublicExploitAvailable": mixed_lifecycle and index % 41 == 0,
                **lifecycle(index),
            }
            for index in range(rows)
        ) if name == "findings" else datasets.get(name, [])
        if name == "finding-events":
            records = (
                {
                    "EventId": f"event-{index}", "FindingKey": f"finding-{index % rows:09d}",
                    "EventType": ("Fixed", "PendingVerification", "Reopened", "New")[index % 4] if mixed_lifecycle else "New",
                    "PreviousStatus": "", "FindingStatus": "Open",
                    "EventTimeUtc": snapshot_time, "EffectiveTimeUtc": "2026-10-23T00:59:46Z",
                    "DeviceId": f"device-{index % devices}", "DeviceName": f"host-{index % devices}",
                    "CveId": f"CVE-2026-{index % cves:05d}", "RecommendationId": f"rec-{index % recommendations}",
                    "Severity": ["Critical", "High", "Medium", "Low"][index % 4],
                    "AssetClass": "TraditionalIT", "SubscriptionId": "", "OwnerTeam": "Endpoints",
                    "DataOrigin": "Live", "SnapshotTimeUtc": snapshot_time, "CollectionRunId": run_id,
                    "SlaStatus": "OpenWithinSla", "SlaDueUtc": "2026-11-24T00:59:46Z",
                }
                for index in range(events)
            )
        write_json_rows(source / f"{name}.json.gz", records)


def main():
    import resource

    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=2_000_000)
    parser.add_argument("--events", type=int, default=0)
    parser.add_argument("--max-rss-mib", type=int, default=512)
    parser.add_argument("--prepare-defaults", action="store_true")
    parser.add_argument("--all-views", action="store_true")
    parser.add_argument("--enforce-targets", action="store_true")
    parser.add_argument("--broad-filters", action="store_true")
    parser.add_argument("--mixed-lifecycle", action="store_true")
    args = parser.parse_args()
    if args.rows < (4 if args.mixed_lifecycle else 1) or args.events < 0:
        parser.error("rows must be positive (at least four with mixed lifecycle), and events cannot be negative")
    snapshot_time = SNAPSHOT_TIME
    work_root = Path("output/dashboard-benchmarks")
    work_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="run-", dir=work_root) as directory:
        root = Path(directory)
        source = root / "source"
        generate_data(source, args.rows, args.events, args.mixed_lifecycle)
        engine = DashboardQueryEngine(
            root / "index", "benchmark", snapshot_time,
            lambda name: iter(JsonRows(source / f"{name}.json.gz", args.rows if name == "findings" else 0)),
        )
        payload = {
            "view": "overview", "mode": "findings", "page": 0, "limit": 100,
            "filters": {"origin": "Both", "severity": "All", "exposureStatus": "DetectedAndPending",
                        "assetClass": "All", "subscription": "All", "team": "All",
                        "domains": ["Devices", "Cloud"], "recommendationTypes": ["Vulnerability"]},
        }
        timings = {}
        if args.prepare_defaults:
            payload["filters"] = initial_filters(Path("dashboard/config.js"))
            start = time.perf_counter()
            for view in PREPARED_VIEWS:
                view_started = time.perf_counter()
                engine.prepare({**payload, "view": view})
                print(json.dumps({"preparedView": view, "seconds": round(time.perf_counter() - view_started, 3)}), flush=True)
            timings["startupPreparationSeconds"] = round(time.perf_counter() - start, 3)
            for view in PREPARED_VIEWS:
                request = {**payload, "view": view}
                start = time.perf_counter()
                result = engine.cached(request)
                elapsed = time.perf_counter() - start
                assert result is not None, f"{view} was not retained after preparation"
                assert elapsed < 1, f"Prepared {view} exceeded 1 second: {elapsed}"
                timings[f"prepared{view.title()}Seconds"] = round(elapsed, 4)

        def query(label, request):
            if label.startswith(("filtered-", "broad-")):
                engine._headers.clear()
            start = time.perf_counter()
            result = engine.query(request)
            timings[label] = round(time.perf_counter() - start, 3)
            size = len(json.dumps(result, separators=(",", ":")).encode())
            assert size < 512 * 1024, f"Unbounded response: {size} bytes"
            return result, size

        visible = args.rows - (args.rows + 3) // 4 if args.mixed_lifecycle else args.rows
        first, size = query("coldOverviewSeconds", payload)
        assert first["tables"]["findingsTable"]["total"] == visible
        assert len(first["tables"]["findingsTable"]["items"]) == min(100, visible)
        last, _ = query("lastPageSeconds", {**payload, "page": max(0, (visible - 1) // 100)})
        assert last["tables"]["findingsTable"]["total"] == visible
        last_index = args.rows - 1
        if args.mixed_lifecycle and last_index % 4 == 0:
            last_index -= 1
        found, _ = query("offPageSearchSeconds", {
            **payload, "filters": {**payload["filters"], "search": f"finding-{last_index:09d}"},
        })
        assert found["tables"]["findingsTable"]["total"] == 1
        grouped, _ = query("distinctCveSeconds", {**payload, "mode": "cves"})
        expected_cves = len({i % 13217 for i in range(min(args.rows, 13217 * 4)) if not args.mixed_lifecycle or i % 4})
        assert grouped["tables"]["findingsTable"]["total"] == expected_cves
        query("warmSummarySeconds", {**payload, "view": "executive"})
        if args.events:
            query("reportingSeconds", {**payload, "view": "trend"})
        slow = {}
        if args.all_views:
            for view in ("executive", "overview", "recommendations", "priority", "workstations", "sla", "trend", "executiveSnapshot"):
                label = f"first-{view}"
                query(label, {**payload, "view": view})
                query(f"cached-{view}", {**payload, "view": view})
                query(f"filtered-{view}", {
                    **payload, "view": view,
                    "filters": {**payload["filters"], "severity": "High"},
                })
                if args.broad_filters:
                    query(f"broad-{view}", {
                        **payload, "view": view, "filters": {**payload["filters"], "origin": "Live"},
                    })
                print(json.dumps({key: value for key, value in timings.items() if key.endswith("-" + view)}), flush=True)
            for kind, id in (
                ("machine", "device-1999"), ("cve", "CVE-2026-09997"), ("recommendation", "rec-19"),
            ):
                query(f"detail-{kind}", {**payload, "view": "detail", "selection": {"type": kind, "id": id}})
            if args.enforce_targets:
                slow = {
                    key: value for key, value in timings.items()
                    if key.startswith(("cached-", "filtered-", "broad-", "detail-"))
                    and value > (5 if key.startswith("cached-") else 10)
                }
                slow.update({
                    key: timings[key] for key in ("offPageSearchSeconds", "distinctCveSeconds")
                    if timings[key] > 10
                })
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        rss_bytes = rss if sys.platform == "darwin" else rss * 1024
        index_bytes = sum(path.stat().st_size for path in (root / "index").rglob("*") if path.is_file())
        source_bytes = sum(path.stat().st_size for path in source.iterdir())
        two_snapshot_bytes = 2 * (index_bytes + source_bytes)
        print(json.dumps({
            "rows": args.rows, "events": args.events,
            "mixedLifecycle": args.mixed_lifecycle,
            "peakRssBytes": rss_bytes, "overviewResponseBytes": size,
            "indexBytes": index_bytes, "sourceBytes": source_bytes,
            "twoSnapshotCacheBytes": two_snapshot_bytes, "maxLocalCacheBytes": MAX_CACHE_BYTES,
            "maxPageRows": 100, **timings,
        }), flush=True)
        assert rss_bytes <= args.max_rss_mib * 1024**2, f"Peak RSS {rss_bytes} exceeds budget"
        assert not slow, f"Interactive latency targets failed: {slow}"
        if args.enforce_targets:
            assert two_snapshot_bytes + 128 * 1024**2 <= MAX_CACHE_BYTES, "Two prepared snapshots exceed the local cache budget"


if __name__ == "__main__":
    main()
