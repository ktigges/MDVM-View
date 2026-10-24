import asyncio
import json
import hashlib
import logging
import subprocess
import sys
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from azure.core.exceptions import ResourceExistsError, ResourceModifiedError, ResourceNotFoundError
from azure.durable_functions.models.DurableOrchestrationStatus import DurableOrchestrationStatus

from vulnerability_view.collection_workflow import (
    INSTANCE_ID, RunStore, orchestrate, prepare_run, publish_run, run_prefix, start_collection, verify_file,
)
from vulnerability_view.config import Settings
from vulnerability_view import collection_workflow


def test_worker_output_is_forwarded_as_function_logs_not_console_prints(monkeypatch, caplog, capfd):
    popen = subprocess.Popen

    def worker(command, **kwargs):
        script = (
            "import json, pathlib, sys; "
            "print('INFO Request [123] GET https://example.invalid/api', flush=True); "
            "print('x-ms-version:2024-11-04', flush=True); "
            "print('Content-Type: text/html', flush=True); "
            "print('<html><body>Bad Gateway</body></html>', flush=True); "
            "print('INFO [machine_vulnerabilities] machines complete: 50/200; 100 findings', flush=True); "
            "print('ERROR [collection] endpoint failed', flush=True); "
            "pathlib.Path(sys.argv[1]).write_text(json.dumps({'done': True}))"
        )
        return popen([sys.executable, "-c", script, command[-1]], **kwargs)

    monkeypatch.setattr(collection_workflow.subprocess, "Popen", worker)
    with caplog.at_level(logging.INFO):
        assert collection_workflow.execute_worker({"stage": "collect"}) == {"done": True}
    assert [(record.levelno, record.getMessage()) for record in caplog.records] == [
        (logging.INFO, "[machine_vulnerabilities] machines complete: 50/200; 100 findings"),
        (logging.ERROR, "[collection] endpoint failed"),
    ]
    assert capfd.readouterr().out == ""


def test_console_status_omits_urls_headers_and_response_bodies():
    text = (
        "[machine_vulnerabilities] failed: HTTP 502 from https://example.invalid/api?secret=value "
        "<html><body>gateway error</body></html>\nx-ms-request-id: request-123"
    )
    status = collection_workflow.console_status(text)
    assert "[machine_vulnerabilities] failed: HTTP 502" in status
    for omitted in ("https://", "secret", "<html", "gateway error", "x-ms-request-id", "request-123"):
        assert omitted not in status


def test_worker_failure_preserves_error_output_and_exit_code(monkeypatch, caplog):
    popen = subprocess.Popen

    def worker(command, **kwargs):
        return popen([sys.executable, "-c", "import sys; print('ValueError: invalid checkpoint', file=sys.stderr); sys.exit(7)"], **kwargs)

    monkeypatch.setattr(collection_workflow.subprocess, "Popen", worker)
    with pytest.raises(subprocess.CalledProcessError) as raised:
        collection_workflow.execute_worker({"stage": "collect"})
    assert raised.value.returncode == 7
    assert "ValueError: invalid checkpoint" in caplog.text


def test_worker_log_forwarding_preserves_timeout(monkeypatch):
    popen = subprocess.Popen
    monkeypatch.setattr(collection_workflow, "WORKER_TIMEOUT_SECONDS", 0.1)

    def worker(command, **kwargs):
        return popen([sys.executable, "-c", "import time; time.sleep(10)"], **kwargs)

    monkeypatch.setattr(collection_workflow.subprocess, "Popen", worker)
    with pytest.raises(subprocess.TimeoutExpired):
        collection_workflow.execute_worker({"stage": "collect"})


class PlanStore:
    def __init__(self):
        self.files = {}
        self.settings = Settings(storage_account_name="history")
        self.current = self

    def get_blob_client(self, name):
        return self

    def download_blob(self):
        raise ResourceNotFoundError("no published baseline")

    def json(self, path):
        if path not in self.files:
            raise ResourceNotFoundError("missing")
        return json.loads(self.files[path])

    def append_json(self, path, value):
        if path in self.files:
            raise ResourceExistsError("exists")
        self.files[path] = json.dumps(value)


def test_plan_freezes_settings_policy_and_baseline_across_restart():
    store = PlanStore()
    request = {"runId": "live-20261023T160000Z", "snapshotUtc": "2026-10-23T16:00:00+00:00"}
    first = prepare_run(request, store, {"policyVersion": "one"})
    store.settings.exclude_scale_sets = True
    second = prepare_run(request, store, {"policyVersion": "two"})
    plan = store.json(first["planPath"])
    assert first == second
    assert plan["settings"]["exclude_scale_sets"] is False
    assert plan["policy"]["policyVersion"] == "one"
    assert plan["baseline"] is None
    assert len(store.files) == 1


@pytest.mark.parametrize("state", ["Running", "Pending", "Suspended", "ContinuedAsNew"])
def test_start_does_not_replace_active_workflow(state):
    client = SimpleNamespace(
        get_status=AsyncMock(return_value=SimpleNamespace(runtime_status=SimpleNamespace(value=state))),
        start_new=AsyncMock(),
        rewind=AsyncMock(),
    )
    assert asyncio.run(start_collection(client, {})) == INSTANCE_ID
    client.start_new.assert_not_called()
    client.rewind.assert_not_called()


def test_failed_run_is_resumed_not_recollected():
    client = SimpleNamespace(
        get_status=AsyncMock(return_value=SimpleNamespace(runtime_status=SimpleNamespace(value="Failed"))),
        start_new=AsyncMock(), rewind=AsyncMock(),
    )
    assert asyncio.run(start_collection(client, {})) == INSTANCE_ID
    client.rewind.assert_awaited_once()
    client.start_new.assert_not_called()


def test_first_start_records_only_small_run_options():
    client = SimpleNamespace(get_status=AsyncMock(return_value=None), start_new=AsyncMock(return_value=INSTANCE_ID))
    asyncio.run(start_collection(client, {"pageSize": 2500, "collection": "auto"}))
    args = client.start_new.call_args.args
    assert args[1] == INSTANCE_ID
    assert args[2]["pageSize"] == 2500
    assert datetime.fromisoformat(args[2]["snapshotUtc"]).tzinfo == UTC
    assert "findings" not in args[2]


def test_first_run_accepts_sdk_empty_status_for_missing_instance():
    missing = DurableOrchestrationStatus.from_json("No instance with ID vulnerability-collection found")
    assert not missing
    client = SimpleNamespace(get_status=AsyncMock(return_value=missing), start_new=AsyncMock(return_value=INSTANCE_ID))
    assert asyncio.run(start_collection(client, {"pageSize": 2500})) == INSTANCE_ID
    client.start_new.assert_awaited_once()


@pytest.mark.parametrize("state", ["Running", "Pending", "Suspended", "ContinuedAsNew", "Failed", "Completed"])
def test_starter_handles_actual_sdk_existing_instance_status(state):
    status = DurableOrchestrationStatus(
        instanceId=INSTANCE_ID, runtimeStatus=state,
        createdTime="2026-10-23T16:00:00Z", lastUpdatedTime="2026-10-23T16:01:00Z",
    )
    client = SimpleNamespace(get_status=AsyncMock(return_value=status), start_new=AsyncMock(return_value=INSTANCE_ID), rewind=AsyncMock())
    assert asyncio.run(start_collection(client, {})) == INSTANCE_ID
    if state == "Completed":
        client.start_new.assert_awaited_once()
    elif state == "Failed":
        client.rewind.assert_awaited_once()
        client.start_new.assert_not_called()
    else:
        client.start_new.assert_not_called()
        client.rewind.assert_not_called()


def test_runstore_rejects_nonappendonly_paths_before_upload():
    store = object.__new__(RunStore)
    with pytest.raises(ValueError, match="immutable"):
        store.append("current/manifest.json", b"bad")


class PublicationStore(PlanStore):
    def __init__(self, baseline_etag=None):
        super().__init__()
        self.pointer = Mock()
        self.pointer.download_blob.side_effect = ResourceNotFoundError("no current manifest")
        self.current = SimpleNamespace(get_blob_client=lambda name: self.pointer)
        self.raw = b"immutable test payload"
        self.history = SimpleNamespace(
            download_blob=lambda name: SimpleNamespace(chunks=lambda: iter([self.raw])),
        )
        self.reference = {"runId": "live-20261023T160000Z", "planPath": "runs/plan.json"}
        self.prefix = run_prefix(self.reference["runId"])
        self.manifest = {
            "runId": self.reference["runId"], "complete": True,
            "snapshotTimeUtc": "2026-10-23T16:00:00Z",
            "endpointStatuses": [{"Status": "Success"}],
            "files": [{
                "path": "curated/2026/10/23/run/findings.json.gz",
                "sizeBytes": len(self.raw), "sha256": hashlib.sha256(self.raw).hexdigest(),
                "dataset": "findings", "rowCount": 10,
            }],
        }
        self.append_json(self.reference["planPath"], {"baselineEtag": baseline_etag})
        self.append_json(f"{self.prefix}/prepared.json", {"manifestPath": f"{self.prefix}/manifest.json"})
        self.save_manifest()

    def save_manifest(self):
        self.files[f"{self.prefix}/manifest.json"] = json.dumps(self.manifest)


def test_each_file_is_verified_before_pointer_can_advance():
    store = PublicationStore()
    with pytest.raises(ResourceNotFoundError):
        publish_run(store.reference, store)
    store.pointer.upload_blob.assert_not_called()
    assert verify_file({**store.reference, "fileIndex": 0}, store)["verified"] is True
    assert publish_run(store.reference, store)["published"] is True
    assert store.pointer.upload_blob.call_args.kwargs == {"overwrite": False}


def test_corrupt_persisted_file_cannot_gain_verification_proof_or_publish():
    store = PublicationStore()
    store.raw = b"corrupted"
    with pytest.raises(ValueError, match="verification"):
        verify_file({**store.reference, "fileIndex": 0}, store)
    assert not any("/verified/" in name for name in store.files)
    store.pointer.upload_blob.assert_not_called()


def test_replaced_publication_baseline_is_not_overwritten():
    store = PublicationStore('"frozen-etag"')
    verify_file({**store.reference, "fileIndex": 0}, store)
    store.pointer.upload_blob.side_effect = ResourceModifiedError("a newer run advanced current")
    with pytest.raises(ResourceModifiedError):
        publish_run(store.reference, store)
    assert store.pointer.upload_blob.call_args.kwargs["etag"] == '"frozen-etag"'


def test_retried_publication_is_idempotent():
    store = PublicationStore()
    verify_file({**store.reference, "fileIndex": 0}, store)
    store.pointer.download_blob.side_effect = None
    store.pointer.download_blob.return_value.readall.return_value = json.dumps(store.manifest).encode()
    assert publish_run(store.reference, store)["published"] is True
    store.pointer.upload_blob.assert_not_called()


def test_optional_endpoint_issue_is_reported_as_partial_success(caplog):
    store = PublicationStore()
    store.manifest["endpointStatuses"].append({"Status": "OptionalUnavailable"})
    store.save_manifest()
    verify_file({**store.reference, "fileIndex": 0}, store)
    with caplog.at_level("INFO"):
        publish_run(store.reference, store)
    assert "status=PartialSuccess" in caplog.text


class OrchestrationContext:
    def __init__(self):
        self.current_utc_datetime = datetime(2026, 10, 23, tzinfo=UTC)
        self.options = {"runId": "live-20261023T000000Z"}
        self.statuses = []
        self.continued = None

    def get_input(self):
        return self.options

    def call_activity_with_retry(self, name, retry, value):
        return name, value

    def create_timer(self, deadline):
        return "timer", deadline

    def set_custom_status(self, value):
        self.statuses.append(value)

    def continue_as_new(self, value):
        self.continued = value


def test_orchestrator_uses_durable_cooldown_and_separate_file_verification():
    context = OrchestrationContext()
    workflow = orchestrate(context)
    assert next(workflow)[0] == "dataprep_prepare"
    reference = {"runId": context.options["runId"], "planPath": "runs/plan.json"}
    assert workflow.send(reference)[0] == "dataprep_collect_batch"
    timer = workflow.send({"done": False, "retry": True, "retryAfter": 7200, "newRequests": 0})
    assert timer[0] == "timer"
    assert (timer[1] - context.current_utc_datetime).total_seconds() == 7200
    assert workflow.send(None)[0] == "dataprep_collect_batch"
    assert workflow.send({"done": True})[0] == "dataprep_process"
    assert workflow.send({"done": False, "stage": "normalize"})[0] == "dataprep_process"
    assert workflow.send({"done": True, "fileCount": 2}) == ("dataprep_verify_file", {**reference, "fileIndex": 0})
    assert workflow.send({"verified": True}) == ("dataprep_verify_file", {**reference, "fileIndex": 1})
    assert workflow.send({"verified": True})[0] == "dataprep_publish"
    with pytest.raises(StopIteration):
        workflow.send({"published": True})
    assert context.statuses[-1]["phase"] == "completed"


def test_orchestration_history_is_bounded_without_changing_frozen_run():
    context = OrchestrationContext()
    workflow = orchestrate(context)
    next(workflow)
    workflow.send({"runId": context.options["runId"], "planPath": "runs/plan.json"})
    for index in range(25):
        assert workflow.send({"done": False, "newRequests": 100, "retry": False})[0] == "timer"
        if index < 24:
            assert workflow.send(None)[0] == "dataprep_collect_batch"
        else:
            with pytest.raises(StopIteration):
                workflow.send(None)
    assert context.continued == {**context.options, "_failures": 0}


def test_repeated_failures_stop_explicitly_without_advancing_to_processing():
    context = OrchestrationContext()
    workflow = orchestrate(context)
    next(workflow)
    workflow.send({"runId": context.options["runId"], "planPath": "runs/plan.json"})
    for _ in range(11):
        workflow.send({"done": False, "newRequests": 0, "retry": True})
        workflow.send(None)
    with pytest.raises(RuntimeError, match="Repeated API failures"):
        workflow.send({"done": False, "newRequests": 0, "retry": True})
    assert all(status["phase"] == "collect" for status in context.statuses)
