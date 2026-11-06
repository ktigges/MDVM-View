import logging
import asyncio
import json
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from test_collection_workflow import OrchestrationContext, recent_run_options
from test_collection_worker import WorkerStore
from vulnerability_view import collection_transport, collection_workflow
from vulnerability_view.collection_timing import OperationTotals, timed_operation
from vulnerability_view.collection_transport import CompletedPhases
from vulnerability_view.collection_workflow import INSTANCE_ID, orchestrate, start_collection


def test_run_phase_durations_include_checkpoint_waits(caplog):
    context = OrchestrationContext()
    context.options["workflowVersion"] = 3
    with caplog.at_level(logging.INFO):
        workflow = orchestrate(context)
        next(workflow)
        context.current_utc_datetime += timedelta(seconds=1)
        workflow.send({"runId": context.options["runId"], "planPath": "runs/plan.json"})
        context.current_utc_datetime += timedelta(seconds=120)
        workflow.send({"done": False, "newRequests": 10})
        context.current_utc_datetime += timedelta(seconds=3)
        workflow.send(None)
        context.current_utc_datetime += timedelta(seconds=5)
        workflow.send({"done": True})
        context.current_utc_datetime += timedelta(seconds=20)
        workflow.send({"done": True, "fileCount": 32})
        context.current_utc_datetime += timedelta(seconds=3)
        workflow.send({"verified": True, "nextIndex": 32})
        context.current_utc_datetime += timedelta(seconds=1)
        with pytest.raises(StopIteration):
            workflow.send({"published": True})
    completed = [
        record.getMessage() for record in caplog.records
        if "scope=run_phase" in record.getMessage() and "event=completed" in record.getMessage()
    ]
    assert len(completed) == 5
    assert any("stage=collect" in line and "elapsedSeconds=128.000" in line for line in completed)
    assert any("scope=run " in record.getMessage() and "elapsedSeconds=153.000" in record.getMessage()
               for record in caplog.records)


def test_phase_timing_survives_continue_as_new_without_restarting(caplog):
    context = OrchestrationContext()
    context.options["workflowVersion"] = 3
    workflow = orchestrate(context)
    next(workflow)
    reference = {"runId": context.options["runId"], "planPath": "runs/plan.json"}
    workflow.send(reference)
    for index in range(25):
        context.current_utc_datetime += timedelta(seconds=1)
        workflow.send({"done": False})
        if index < 24:
            workflow.send(None)
        else:
            with pytest.raises(StopIteration):
                workflow.send(None)
    assert context.continued["_timing"]["stage"] == "collect"
    resumed = OrchestrationContext()
    resumed.options = context.continued
    resumed.current_utc_datetime = context.current_utc_datetime + timedelta(seconds=30)
    with caplog.at_level(logging.INFO):
        continuation = orchestrate(resumed)
        next(continuation)
        continuation.send(reference)
        continuation.send({"done": True})
    lines = [record.getMessage() for record in caplog.records]
    assert any("stage=collect" in line and "elapsedSeconds=55.000" in line for line in lines)
    assert not any("stage=collect" in line and "event=started" in line for line in lines)


def test_endpoint_timing_survives_cold_resume_and_has_one_completion(monkeypatch, tmp_path, caplog):
    store = WorkerStore()
    now = [OrchestrationContext().current_utc_datetime]
    monkeypatch.setattr(collection_transport, "utc_now", lambda: now[0])
    folder = tmp_path / "live-20261023T000000Z"
    with caplog.at_level(logging.INFO):
        first = CompletedPhases(store, "raw/run", folder, {"tenant": "synthetic"}, timing_enabled=True)
        assert first.load("machine_vulnerabilities") is None
        starts = dict(store.files)
        now[0] += timedelta(seconds=120)
        resumed = CompletedPhases(store, "raw/run", folder, {"tenant": "synthetic"}, timing_enabled=True)
        assert resumed.load("machine_vulnerabilities") is None
        assert store.files == starts
        resumed.save("machine_vulnerabilities", {"RowCount": 200, "PageCount": 2, "MachineCount": 1}, [])
        frozen = dict(store.files)
        now[0] += timedelta(seconds=10)
        resumed.save("machine_vulnerabilities", {"RowCount": 200, "PageCount": 2, "MachineCount": 1}, [])
        assert store.files == frozen
    phase = json.loads(store.files["raw/run/phases/machine_vulnerabilities.json"])
    assert phase["timing"]["elapsedSeconds"] == 120
    completed = [record.getMessage() for record in caplog.records if "event=completed" in record.getMessage()]
    assert len(completed) == 1
    assert "rowsPerSecond=1.667" in completed[0]


def test_replay_does_not_duplicate_timing_markers(caplog):
    context = OrchestrationContext()
    context.is_replaying = True
    context.options["workflowVersion"] = 3
    with caplog.at_level(logging.INFO):
        workflow = orchestrate(context)
        next(workflow)
        workflow.send({"runId": context.options["runId"], "planPath": "runs/plan.json"})
        workflow.send({"done": True})
        workflow.send({"done": True, "fileCount": 0})
        with pytest.raises(StopIteration):
            workflow.send({"published": True})
    assert not any("[timing]" in record.getMessage() for record in caplog.records)


def test_failed_phase_and_run_still_emit_errors(caplog):
    context = OrchestrationContext()
    context.options["workflowVersion"] = 3
    with caplog.at_level(logging.INFO):
        workflow = orchestrate(context)
        next(workflow)
        workflow.send({"runId": context.options["runId"], "planPath": "runs/plan.json"})
        context.current_utc_datetime += timedelta(seconds=10)
        with pytest.raises(RuntimeError, match="required endpoint failed"):
            workflow.throw(RuntimeError("required endpoint failed"))
    errors = [record.getMessage() for record in caplog.records if record.levelno == logging.ERROR]
    assert any("scope=run_phase stage=collect event=failed" in line for line in errors)
    assert any("scope=run stage=total event=failed" in line for line in errors)
    assert not any("stage=collect event=completed" in record.getMessage() for record in caplog.records)


def test_activity_checkpoint_is_not_logged_as_failed(monkeypatch, caplog):
    monkeypatch.setattr(collection_workflow, "_execute_worker", lambda action: {"done": False, "retry": False})
    with caplog.at_level(logging.INFO):
        result = collection_workflow.execute_worker({"runId": "live-20261023T000000Z", "stage": "collect"})
    assert result["done"] is False
    assert any("event=checkpoint" in record.getMessage() for record in caplog.records)
    assert not any(record.levelno >= logging.WARNING for record in caplog.records)


def test_timed_operation_preserves_real_failure(caplog):
    with caplog.at_level(logging.INFO), pytest.raises(ValueError, match="corrupt"):
        with timed_operation("run", "processing_stage", "normalize", cpu=True):
            raise ValueError("corrupt")
    assert any("event=failed" in record.getMessage() and record.levelno == logging.ERROR for record in caplog.records)
    assert not any("event=completed" in record.getMessage() for record in caplog.records)


def test_io_measurements_include_failed_calls_and_leave_failure_visible(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("vulnerability_view.collection_timing.time.monotonic", lambda: clock[0])
    totals = OperationTotals()
    with totals.measure("storageRead"):
        clock[0] += 2
    with pytest.raises(ValueError):
        with totals.measure("storageWrite"):
            clock[0] += 3
            raise ValueError("write failed")
    assert totals.snapshot() == {
        "storageReadSeconds": 2, "storageReadCalls": 1,
        "storageWriteSeconds": 3, "storageWriteCalls": 1,
    }


def test_failed_run_recovery_carries_phase_start_without_new_deadline():
    original = {**recent_run_options(), "workflowVersion": 3}
    timing = {"stage": "collect", "startedUtc": original["snapshotUtc"]}
    client = SimpleNamespace(
        get_status=AsyncMock(return_value=SimpleNamespace(
            runtime_status=SimpleNamespace(value="Failed"), input_=original, custom_status={"timing": timing},
        )),
        start_new=AsyncMock(return_value=INSTANCE_ID),
    )
    asyncio.run(start_collection(client, {}))
    recovered = client.start_new.call_args.args[2]
    assert recovered["_timing"] == timing
    assert recovered["runId"] == original["runId"]
    assert recovered["snapshotUtc"] == original["snapshotUtc"]
