import json
import pstats
import time

import pytest

import benchmark_bounded_finalization as benchmark
from vulnerability_view.bounded_processing import iter_json_rows


def small_fixture(monkeypatch):
    monkeypatch.setattr(benchmark, "MACHINES", 3)
    monkeypatch.setattr(benchmark, "CVES", 11)
    monkeypatch.setattr(benchmark, "PRODUCTS", 5)


def test_default_workload_is_three_million_findings_with_retained_history(tmp_path, monkeypatch):
    observed = []

    def observe(root, findings, history_events):
        observed.append((findings, history_events))
        raise RuntimeError("Skip large fixture generation in the fast regression")

    monkeypatch.setattr(benchmark, "generate_inputs", observe)
    with pytest.raises(RuntimeError, match="Skip large fixture generation"):
        benchmark.main(["--root", str(tmp_path)])
    assert observed == [(3_000_000, 3_300_000)]


def test_fixture_uses_bounded_machine_pages_and_diverse_retained_evidence(tmp_path, monkeypatch):
    small_fixture(monkeypatch)
    raw, baseline = benchmark.generate_inputs(tmp_path, 9001, 200)
    pages = sorted(raw.glob("machine_vulnerabilities-page-*.json.gz"))
    assert len(pages) == 6
    ids, cves, severities, products = set(), set(), set(), set()
    for page in pages:
        rows = list(iter_json_rows(page, field="value"))
        assert 0 < len(rows) <= 2500
        assert len({row["machineId"] for row in rows}) == 1
        for row in rows:
            assert row["id"] not in ids
            ids.add(row["id"])
            cves.add(row["cveId"])
            severities.add(row["severity"])
            products.add(row["productName"])
    assert len(ids) == 9001
    assert len(cves) == 11
    assert len(severities) == 4
    assert len(products) == 5
    events = list(iter_json_rows(baseline["findingEvents"]))
    assert len(events) == len({row["EventId"] for row in events}) == 200
    assert len({row["EffectiveTimeUtc"] for row in events}) == 90
    assert {row["EventType"] for row in events} == {"New", "Fixed", "Reopened"}
    assert all(row["FindingKey"] in ids for row in events)


@pytest.mark.parametrize("stage,profile", [("normalize", True), ("bundle", False)])
def test_benchmark_exercises_real_processing_and_reports_exact_counts(tmp_path, monkeypatch, stage, profile):
    small_fixture(monkeypatch)
    args = [
        "--findings", "80", "--history-events", "190", "--budget", "60",
        "--stop-after", stage, "--enforce-targets", "--root", str(tmp_path),
    ]
    if profile:
        args.append("--profile")
    report = benchmark.main(args)
    assert report == json.loads((tmp_path / "report.json").read_text())
    assert report["targetReached"] and not report["timedOut"]
    assert report["complete"] == (stage == "bundle")
    assert report["checkpointCounts"]["findings"] == 80
    assert report["completedStages"][-1]["stage"] == stage
    assert all(item["seconds"] > 0 and item["cpuSeconds"] > 0 for item in report["completedStages"])
    progress = [json.loads(line) for line in (tmp_path / "progress.jsonl").read_text().splitlines()]
    assert any("step=replay-raw [normalize]" in item["message"] for item in progress)
    assert report["latestProgress"] == progress[-1]
    if stage == "bundle":
        assert report["checkpointCounts"]["findingEvents"] == 270
        for group in ("primary", "history"):
            assert any(f"step=build-query-group group={group} complete=True" in item["message"] for item in progress)
        assert any("step=verify-bundle" in item["message"] for item in progress)
    if profile:
        stats = pstats.Stats(str(tmp_path / "profile.pstats"))
        assert any(key[2] == "normalize_live" for key in stats.stats)
        assert "normalize_live" in (tmp_path / "profile.txt").read_text()


@pytest.mark.parametrize("enforce", [False, True])
def test_budget_interrupts_processing_and_preserves_a_failure_report(tmp_path, monkeypatch, enforce):
    small_fixture(monkeypatch)

    def blocked(*args, progress_callback, **kwargs):
        progress_callback("stage=normalize step=test-blocked")
        time.sleep(5)
        pytest.fail("The one-second processing budget did not interrupt the stage")

    monkeypatch.setattr(benchmark, "advance_archived_run", blocked)
    args = [
        "--findings", "1", "--history-events", "0", "--budget", "1",
        "--root", str(tmp_path),
    ]
    if enforce:
        args.append("--enforce-targets")
        with pytest.raises(RuntimeError, match="time budget"):
            benchmark.main(args)
    else:
        benchmark.main(args)
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["timedOut"] and not report["targetReached"] and not report["complete"]
    assert report["interruptedStage"] == "normalize"
    assert report["latestProgress"]["message"] == "stage=normalize step=test-blocked"
    assert report["completedStages"] == []


def test_processing_errors_are_reported_and_not_swallowed(tmp_path, monkeypatch):
    small_fixture(monkeypatch)

    def fail(*args, **kwargs):
        raise ValueError("Invalid benchmark evidence")

    monkeypatch.setattr(benchmark, "advance_archived_run", fail)
    with pytest.raises(ValueError, match="Invalid benchmark evidence"):
        benchmark.main(["--findings", "1", "--history-events", "0", "--root", str(tmp_path)])
    report = json.loads((tmp_path / "report.json").read_text())
    assert not report["complete"] and not report["targetReached"] and not report["timedOut"]


@pytest.mark.parametrize("findings,events", [(79, 270), (80, 269)])
def test_enforced_targets_reject_missing_evidence(tmp_path, monkeypatch, findings, events):
    small_fixture(monkeypatch)

    def wrong_count(raw, settings, baseline, policy, workspace, **kwargs):
        checkpoint = workspace.parent / "wrong-count-checkpoint.json"
        checkpoint.write_text(json.dumps({"datasets": {
            "findings": {"rowCount": findings}, "findingEvents": {"rowCount": events},
        }}))
        return {"done": False, "nextStage": "finding-events", "checkpoint": {"reference": str(checkpoint)}}

    monkeypatch.setattr(benchmark, "advance_archived_run", wrong_count)
    with pytest.raises(RuntimeError, match="retain every finding"):
        benchmark.main([
            "--findings", "80", "--history-events", "190",
            "--stop-after", "normalize" if findings != 80 else "finding-events",
            "--enforce-targets", "--root", str(tmp_path),
        ])
    assert json.loads((tmp_path / "report.json").read_text())["targetReached"]


def test_existing_results_cannot_be_overwritten(tmp_path):
    existing = tmp_path / "report.json"
    existing.write_text("retained benchmark result")
    with pytest.raises(SystemExit) as error:
        benchmark.main(["--root", str(tmp_path)])
    assert error.value.code == 2
    assert existing.read_text() == "retained benchmark result"
