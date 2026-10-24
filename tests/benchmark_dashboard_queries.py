"""Exercise real disk-backed dashboard queries at million-finding scale."""

import argparse
import json
import resource
import sys
import tempfile
import time
from pathlib import Path

from vulnerability_view.bounded_processing import write_json_rows
from vulnerability_view.dashboard_queries import DashboardQueryEngine
from vulnerability_view.dashboard_preparation import initial_filters
from vulnerability_view.dataset_io import JsonRows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=2_000_000)
    parser.add_argument("--events", type=int, default=0)
    parser.add_argument("--max-rss-mib", type=int, default=512)
    parser.add_argument("--prepare-defaults", action="store_true")
    args = parser.parse_args()
    snapshot_time = "2026-10-24T00:59:46Z"
    work_root = Path("output/dashboard-benchmarks")
    work_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="run-", dir=work_root) as directory:
        root = Path(directory)
        source = root / "source"
        source.mkdir()
        datasets = {
            "devices": [
                {"DeviceId": f"device-{index}", "DeviceName": f"host-{index}",
                 "AssetClass": "TraditionalIT", "DataOrigin": "Live", "OwnerTeam": "Endpoints",
                 "OnboardingStatus": "Onboarded", "HealthStatus": "Active",
                 "LastSeenUtc": snapshot_time, "SnapshotTimeUtc": snapshot_time}
                for index in range(2000)
            ],
            "recommendations": [
                {"RecommendationId": f"rec-{index}", "RecommendationName": f"Update software {index}",
                 "ProductName": f"software-{index}", "RemediationType": "Update",
                 "SeverityScore": 8.8, "DataOrigin": "Live", "Status": "Active"}
                for index in range(20)
            ],
            "collection-runs": [{
                "CollectionRunId": "benchmark", "SnapshotTimeUtc": snapshot_time,
                "DataOrigin": "Live", "Endpoint": "machine_vulnerabilities", "Status": "Success",
            }],
        }
        names = [
            "findings", "devices", "recommendations", "collection-runs", "finding-events",
            "recommendation-events", "run-history", "recommendation-machines", "daily-summary",
            "secure-scores", "subscriptions", "remediation-activities", "vulnerabilities",
        ]
        for name in names:
            rows = (
                {
                    "FindingKey": f"finding-{index:09d}", "DeviceId": f"device-{index % 2000}",
                    "DeviceName": f"host-{index % 2000}", "CveId": f"CVE-2026-{index % 13217:05d}",
                    "RecommendationId": f"rec-{index % 20}", "RecommendationName": f"Update software {index % 20}",
                    "SoftwareName": f"software-{index % 20}", "SoftwareVersion": "123.4",
                    "OSPlatform": "Windows11", "AssetClass": "TraditionalIT", "DataOrigin": "Live",
                    "OwnerTeam": "Endpoints", "SubscriptionId": "", "FindingStatus": "Open",
                    "Severity": ["Critical", "High", "Medium", "Low"][index % 4],
                    "PriorityScore": index % 100, "CvssScore": 8.8, "SlaStatus": "OpenWithinSla",
                    "SlaDueUtc": "2026-11-24T00:59:46Z", "FirstSeenUtc": "2026-10-23T00:59:46Z",
                    "FirstObservedUtc": "2026-10-23T00:59:46Z", "LastSeenUtc": snapshot_time,
                    "LastObservedUtc": snapshot_time, "SnapshotTimeUtc": snapshot_time,
                    "CollectionRunId": "benchmark", "KnownExploit": False, "PublicExploitAvailable": False,
                }
                for index in range(args.rows)
            ) if name == "findings" else datasets.get(name, [])
            if name == "finding-events":
                rows = (
                    {
                        "EventId": f"event-{index}", "FindingKey": f"finding-{index % args.rows:09d}",
                        "EventType": "New", "PreviousStatus": "", "FindingStatus": "Open",
                        "EventTimeUtc": snapshot_time, "EffectiveTimeUtc": "2026-10-23T00:59:46Z",
                        "DeviceId": f"device-{index % 2000}", "DeviceName": f"host-{index % 2000}",
                        "CveId": f"CVE-2026-{index % 13217:05d}", "RecommendationId": f"rec-{index % 20}",
                        "Severity": ["Critical", "High", "Medium", "Low"][index % 4],
                        "AssetClass": "TraditionalIT", "SubscriptionId": "", "OwnerTeam": "Endpoints",
                        "DataOrigin": "Live", "SnapshotTimeUtc": snapshot_time, "CollectionRunId": "benchmark",
                        "SlaStatus": "OpenWithinSla", "SlaDueUtc": "2026-11-24T00:59:46Z",
                    }
                    for index in range(args.events)
                )
            write_json_rows(source / f"{name}.json.gz", rows)
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
            for view in ("executive", "overview"):
                engine.prepare({**payload, "view": view})
            timings["startupPreparationSeconds"] = round(time.perf_counter() - start, 3)
            for view in ("executive", "overview"):
                request = {**payload, "view": view}
                start = time.perf_counter()
                result = engine.cached(request)
                elapsed = time.perf_counter() - start
                assert result is not None, f"{view} was not retained after preparation"
                assert elapsed < 1, f"Prepared {view} exceeded 1 second: {elapsed}"
                timings[f"prepared{view.title()}Seconds"] = round(elapsed, 4)

        def query(label, request):
            start = time.perf_counter()
            result = engine.query(request)
            timings[label] = round(time.perf_counter() - start, 3)
            size = len(json.dumps(result, separators=(",", ":")).encode())
            assert size < 512 * 1024, f"Unbounded response: {size} bytes"
            return result, size

        first, size = query("coldOverviewSeconds", payload)
        assert first["tables"]["findingsTable"]["total"] == args.rows
        assert len(first["tables"]["findingsTable"]["items"]) == min(100, args.rows)
        last, _ = query("lastPageSeconds", {**payload, "page": max(0, (args.rows - 1) // 100)})
        assert last["tables"]["findingsTable"]["total"] == args.rows
        found, _ = query("offPageSearchSeconds", {
            **payload, "filters": {**payload["filters"], "search": f"finding-{args.rows - 1:09d}"},
        })
        assert found["tables"]["findingsTable"]["total"] == 1
        grouped, _ = query("distinctCveSeconds", {**payload, "mode": "cves"})
        assert grouped["tables"]["findingsTable"]["total"] == min(args.rows, 13217)
        query("warmSummarySeconds", {**payload, "view": "executive"})
        if args.events:
            query("reportingSeconds", {**payload, "view": "trend"})
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        rss_bytes = rss if sys.platform == "darwin" else rss * 1024
        assert rss_bytes <= args.max_rss_mib * 1024**2, f"Peak RSS {rss_bytes} exceeds budget"
        print(json.dumps({
            "rows": args.rows, "events": args.events,
            "peakRssBytes": rss_bytes, "overviewResponseBytes": size,
            "indexBytes": sum(path.stat().st_size for path in (root / "index").rglob("*") if path.is_file()),
            "maxPageRows": 100, **timings,
        }), flush=True)


if __name__ == "__main__":
    main()
