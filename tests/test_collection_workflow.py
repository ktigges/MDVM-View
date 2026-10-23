import asyncio
import json
import hashlib
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from azure.core.exceptions import ResourceExistsError, ResourceModifiedError, ResourceNotFoundError

from vulnerability_view.collection_workflow import (
    INSTANCE_ID, RunStore, orchestrate, prepare_run, publish_run, run_prefix, start_collection, verify_file,
)
from vulnerability_view.config import Settings


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
