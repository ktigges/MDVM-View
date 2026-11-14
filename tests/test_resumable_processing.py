import json
import shutil
from copy import deepcopy
from pathlib import Path

import pytest

from test_bounded_processing import RUN_ID, SNAPSHOT, lifecycle_fixture, payloads, work
from vulnerability_view.config import Settings
from vulnerability_view.dataprep_cli import advance_archived_run, materialize_prepared_bundle, process_archived_run
from vulnerability_view.defender_client import ENDPOINTS
from vulnerability_view.resumable_processing import STAGES
from vulnerability_view.storage_writer import DATASET_FILES, _sha256, archive_raw_rows, verify_run_bundle


@pytest.mark.parametrize("combined", [False, True])
def test_processing_freezes_only_required_baselines_without_losing_combined_history(work, combined):
    from vulnerability_view.resumable_processing import Artifacts

    raw, policy = setup_run(work)
    needed = {"findings", "recommendations", "findingEvents", "recommendationEvents", "runHistory"}

    def unused():
        pytest.fail("Live-only processing must not scan unused baseline datasets")
        yield

    baseline = {
        key: [] if combined or key in needed else unused()
        for key in DATASET_FILES
    }
    if combined:
        baseline["subscriptions"] = [{"DataOrigin": "Synthetic", "SubscriptionId": "prior-subscription"}]
    worker = work / "worker"
    state = advance_archived_run(
        raw, Settings(app_mode="combined" if combined else "live"), baseline, policy, worker,
        snapshot=SNAPSHOT, run_id=RUN_ID,
    )
    artifacts = Artifacts(worker / "processing-artifacts")
    metadata = json.loads(artifacts.get(state["checkpoint"]).read_text())
    assert set(metadata["baseline"]) == (set(DATASET_FILES) if combined else needed)
    if combined:
        assert list(artifacts.rows(metadata["baseline"]["subscriptions"])) == baseline["subscriptions"]


@pytest.mark.parametrize("corrupt_cache", [False, True])
def test_cached_artifacts_hash_once_and_repair_corruption(work, monkeypatch, corrupt_cache):
    from vulnerability_view import resumable_processing

    durable = DurableArtifacts(work / "durable")
    artifacts = resumable_processing.Artifacts(work / "cache", durable.save, durable.load)
    source = work / "dataset.gz"
    source.write_bytes(b"retained-evidence")
    descriptor = artifacts.put(source, "dataset")
    cached = artifacts.get(descriptor)
    if corrupt_cache:
        cached.write_bytes(b"corrupt-evidence!")
    scanned = []

    def observe(path):
        scanned.append(path.stat().st_size)
        return _sha256(path)

    monkeypatch.setattr(resumable_processing, "_sha256", observe)
    assert artifacts.get(descriptor).read_bytes() == source.read_bytes()
    # An unchanged cached file is not re-hashed; a modified one is re-verified, then
    # re-downloaded and verified again.
    assert sum(scanned) == source.stat().st_size * (2 if corrupt_cache else 0)


class DurableArtifacts:
    def __init__(self, root):
        self.root = root
        self.saved = []

    def save(self, path, key):
        destination = self.root / key
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            assert _sha256(destination) == _sha256(path)
        else:
            shutil.copyfile(path, destination)
        self.saved.append(key)
        return {"key": key}

    def load(self, reference, destination):
        shutil.copyfile(self.root / reference["key"], destination)


def setup_run(work):
    raw = work / "raw" / RUN_ID
    for endpoint in ENDPOINTS:
        archive_raw_rows(endpoint.name, payloads().get(endpoint.name, []), RUN_ID, raw.parent)
    policy = work / "sla-policies.json"
    policy.write_bytes(Path("config/sla-policies.json").read_bytes())
    return raw, policy


@pytest.mark.parametrize("combined", [False, True])
def test_every_stage_survives_complete_worker_loss_and_matches_single_pass(work, combined):
    raw, policy = setup_run(work)
    settings = Settings(app_mode="combined" if combined else "live")
    baseline = {"runHistory": [{
        "DataOrigin": "Synthetic", "CollectionRunId": "synthetic-prior", "SnapshotTimeUtc": "2026-09-01T00:00:00Z",
    }]} if combined else {}
    _, baseline["findings"] = lifecycle_fixture()
    expected = process_archived_run(raw, settings, baseline, policy, work / "expected", snapshot=SNAPSHOT, run_id=RUN_ID)
    durable = DurableArtifacts(work / "durable")
    state = None
    progress = []
    for index, stage in enumerate(STAGES[:-1]):
        worker = work / f"worker-{index}"
        state = advance_archived_run(
            raw, settings, baseline if state is None else {"do-not-read": iter(())},
            policy, worker, snapshot=SNAPSHOT, run_id=RUN_ID, state=state,
            save_artifact=durable.save, load_artifact=durable.load, input_identity="frozen-inputs",
            progress_callback=progress.append,
        )
        assert state["nextStage"] == STAGES[index + 1]
        assert f"stage={stage} step=start-stage" in progress
        assert f"stage={stage} step=persist-checkpoint nextStage={state['nextStage']}" in progress
        assert len(json.dumps(state)) < 2000
        shutil.rmtree(worker)
    restored = materialize_prepared_bundle(state, work / "restored", load_artifact=durable.load)
    assert verify_run_bundle(restored, raw) == []
    assert json.loads((restored / "manifest.json").read_text()) == json.loads((expected / "manifest.json").read_text())
    for basename in DATASET_FILES.values():
        assert (restored / "curated" / f"{basename}.json.gz").read_bytes() == (expected / "curated" / f"{basename}.json.gz").read_bytes()
    assert any("step=replay-raw [replay] endpoint=machine_vulnerabilities rows=" in message for message in progress)
    assert any("step=write-dataset section=datasets dataset=findings rows=" in message for message in progress)
    assert any("stage=bundle step=load-query-rows dataset=findings rows=" in message for message in progress)
    assert any("stage=bundle step=build-query-group group=history complete=True" in message for message in progress)


def test_retries_reuse_content_addressed_artifacts_and_do_not_repeat_normalization(work, monkeypatch):
    from vulnerability_view import resumable_processing

    raw, policy = setup_run(work)
    durable = DurableArtifacts(work / "durable")
    initial = advance_archived_run(
        raw, Settings(), {}, policy, work / "first", snapshot=SNAPSHOT, run_id=RUN_ID,
        save_artifact=durable.save, load_artifact=durable.load,
    )
    monkeypatch.setattr(resumable_processing, "replay_raw_snapshot", lambda *a, **k: pytest.fail("Normalization must not replay"))
    outputs = []
    for index in range(2):
        outputs.append(advance_archived_run(
            raw, Settings(), {}, policy, work / str(index), snapshot=SNAPSHOT, run_id=RUN_ID,
            state=deepcopy(initial), save_artifact=durable.save, load_artifact=durable.load,
        ))
    assert outputs[0] == outputs[1]


@pytest.mark.parametrize("stage", ["normalize", "reconcile"])
def test_stage_failure_does_not_commit_a_continuation_and_can_retry(work, stage):
    raw, policy = setup_run(work)
    durable = DurableArtifacts(work / "durable")
    state = None if stage == "normalize" else advance_archived_run(
        raw, Settings(), {}, policy, work / "first", snapshot=SNAPSHOT, run_id=RUN_ID,
        save_artifact=durable.save, load_artifact=durable.load,
    )

    def interrupted_save(path, key):
        durable.save(path, key)
        raise RuntimeError("Activity lost after immutable artifact upload")

    with pytest.raises(RuntimeError, match="Activity lost"):
        advance_archived_run(
            raw, Settings(), {}, policy, work / "failed", snapshot=SNAPSHOT, run_id=RUN_ID,
            state=state, save_artifact=interrupted_save, load_artifact=durable.load,
        )
    resumed = advance_archived_run(
        raw, Settings(), {}, policy, work / "resumed", snapshot=SNAPSHOT, run_id=RUN_ID,
        state=state, save_artifact=durable.save, load_artifact=durable.load,
    )
    assert resumed["nextStage"] == ("reconcile" if stage == "normalize" else "finding-events")


def test_checkpoint_corruption_and_policy_drift_are_rejected(work):
    raw, policy = setup_run(work)
    durable = DurableArtifacts(work / "durable")
    state = advance_archived_run(
        raw, Settings(), {}, policy, work / "first", snapshot=SNAPSHOT, run_id=RUN_ID,
        save_artifact=durable.save, load_artifact=durable.load,
    )
    changed = json.loads(policy.read_text())
    changed["policyVersion"] = "changed"
    policy.write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="frozen inputs"):
        advance_archived_run(raw, Settings(), {}, policy, work / "bad-policy", snapshot=SNAPSHOT, run_id=RUN_ID, state=state)
    policy.write_bytes(Path("config/sla-policies.json").read_bytes())
    (durable.root / state["checkpoint"]["reference"]["key"]).write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="integrity mismatch"):
        advance_archived_run(
            raw, Settings(), {}, policy, work / "corrupt", snapshot=SNAPSHOT, run_id=RUN_ID,
            state=state, load_artifact=durable.load,
        )


def test_bundle_rejects_raw_inventory_changes_after_normalization(work):
    raw, policy = setup_run(work)
    state = None
    while state is None or state["nextStage"] != "bundle":
        state = advance_archived_run(
            raw, Settings(), {}, policy, work / "worker",
            snapshot=SNAPSHOT, run_id=RUN_ID, state=state,
        )
    archive_raw_rows("unexpected", [], RUN_ID, raw.parent)
    with pytest.raises(ValueError, match="raw file inventory changed"):
        advance_archived_run(
            raw, Settings(), {}, policy, work / "worker",
            snapshot=SNAPSHOT, run_id=RUN_ID, state=state,
        )


@pytest.mark.parametrize("legacy", [False, True])
def test_history_reuses_checkpointed_event_totals_without_rescanning_history(work, monkeypatch, legacy):
    from vulnerability_view.resumable_processing import Artifacts
    from vulnerability_view.bounded_processing import iter_json_rows

    raw, policy = setup_run(work)
    worker = work / "worker"
    state = None
    while state is None or state["nextStage"] != "history":
        state = advance_archived_run(
            raw, Settings(), {}, policy, worker, snapshot=SNAPSHOT, run_id=RUN_ID, state=state,
        )
    artifacts = Artifacts(worker / "processing-artifacts")
    metadata = json.loads(artifacts.get(state["checkpoint"]).read_text())
    assert set(metadata["eventSummaries"]) == {"findingEvents", "recommendationEvents"}
    expected_new = metadata["datasets"]["findingEvents"]["rowCount"]
    if legacy:
        metadata.pop("eventSummaries")
        checkpoint = work / "legacy-checkpoint.json"
        checkpoint.write_text(json.dumps(metadata))
        state["checkpoint"] = artifacts.put(checkpoint, "legacy-checkpoint")
    original = Artifacts.rows
    scanned = []

    def observe(self, descriptor, progress_callback=None):
        if descriptor and descriptor["fileName"] in {"finding-events.json.gz", "recommendation-events.json.gz"}:
            scanned.append(descriptor["fileName"])
            assert legacy, "New history checkpoints must not rescan event datasets"
        return original(self, descriptor, progress_callback)

    monkeypatch.setattr(Artifacts, "rows", observe)
    result = advance_archived_run(
        raw, Settings(), {}, policy, worker, snapshot=SNAPSHOT, run_id=RUN_ID, state=state,
    )
    metadata = json.loads(artifacts.get(result["checkpoint"]).read_text())
    rows = list(iter_json_rows(artifacts.get(metadata["datasets"]["runHistory"])))
    assert rows[-1]["NewFindings"] == expected_new
    assert bool(scanned) == legacy
