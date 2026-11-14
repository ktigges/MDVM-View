import asyncio
import json
import hashlib
import logging
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from azure.core.exceptions import ResourceExistsError, ResourceModifiedError, ResourceNotFoundError
from azure.durable_functions.models.DurableOrchestrationStatus import DurableOrchestrationStatus

from vulnerability_view.collection_workflow import (
    INSTANCE_ID, RunStore, ensure_current_baseline, orchestrate, prepare_run, publish_run, run_prefix, start_collection, verify_file,
)
from vulnerability_view.config import Settings
from vulnerability_view.collection_timing import OperationTotals
from test_collection_identity import TENANT, OTHER, credential as tenant_credential


@pytest.fixture(autouse=True)
def collection_credential(monkeypatch):
    monkeypatch.setattr("vulnerability_view.collection_workflow.create_credential", lambda *args: tenant_credential(TENANT))


def recent_run_options():
    snapshot = (datetime.now(UTC) - timedelta(minutes=1)).replace(microsecond=0)
    return {"runId": snapshot.strftime("live-%Y%m%dT%H%M%SZ"), "snapshotUtc": snapshot.isoformat()}
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
        (logging.INFO, "[run] runId=None [machine_vulnerabilities] machines complete: 50/200; 100 findings"),
        (logging.ERROR, "[run] runId=None [collection] endpoint failed"),
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


@pytest.mark.parametrize("stage", ["collect", "process"])
def test_worker_is_not_killed_at_the_former_wall_clock_deadline(monkeypatch, stage):
    popen = subprocess.Popen
    monkeypatch.setattr(collection_workflow, "WORKER_TIMEOUT_SECONDS", 0.05, raising=False)

    def worker(command, **kwargs):
        script = (
            "import json, pathlib, sys, time; time.sleep(0.15); "
            "pathlib.Path(sys.argv[1]).write_text(json.dumps({'done': True}))"
        )
        return popen([sys.executable, "-c", script, command[-1]], **kwargs)

    monkeypatch.setattr(collection_workflow.subprocess, "Popen", worker)
    started = time.monotonic()
    assert collection_workflow.execute_worker({"stage": stage}) == {"done": True}
    assert time.monotonic() - started >= 0.15


def test_worker_is_stopped_if_the_supervisor_is_interrupted(monkeypatch):
    popen = subprocess.Popen
    children = []

    def worker(command, **kwargs):
        child = popen(
            [sys.executable, "-c", "import time; print('INFO [processing] working', flush=True); time.sleep(10)"],
            **kwargs,
        )
        children.append(child)
        return child

    def interrupt(*args, **kwargs):
        raise RuntimeError("Supervisor interrupted")

    monkeypatch.setattr(collection_workflow.subprocess, "Popen", worker)
    monkeypatch.setattr(collection_workflow.logging, "log", interrupt)
    with pytest.raises(RuntimeError, match="Supervisor interrupted"):
        collection_workflow.execute_worker({"stage": "process"})
    assert children[0].returncode is not None
    assert children[0].returncode != 0


@pytest.mark.parametrize("stage", ["prepare", "collect", "process", "verify", "verify-batch", "publish"])
def test_original_deadline_kills_a_silent_worker_in_every_stage(monkeypatch, caplog, stage):
    popen = subprocess.Popen
    children = []

    def worker(command, **kwargs):
        child = popen([sys.executable, "-c", "import time; time.sleep(30)"], **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(collection_workflow.subprocess, "Popen", worker)
    action = {
        "stage": stage, "runId": datetime.now(UTC).strftime("live-%Y%m%dT%H%M%SZ"),
        "deadlineUtc": (datetime.now(UTC) + timedelta(seconds=0.35)).isoformat(),
    }
    started = time.monotonic()
    with caplog.at_level(logging.INFO):
        result = collection_workflow.execute_worker(action)
    assert result["timedOut"] is True and result["done"] is False
    assert result["deadlineUtc"] == action["deadlineUtc"]
    assert children[0].poll() is not None
    assert children[0].returncode != 0
    assert time.monotonic() - started < 5
    assert "worker stopped" in caplog.text
    assert "checkpoints retained" in caplog.text


def test_expired_run_never_launches_another_worker(monkeypatch):
    monkeypatch.setattr(collection_workflow.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("No expired worker"))
    result = collection_workflow.execute_worker({
        "stage": "process", "runId": "live-20261023T000000Z",
        "deadlineUtc": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
    })
    assert result["timedOut"] is True


def test_legacy_activity_uses_original_run_identity_not_a_new_eight_hour_budget(monkeypatch):
    monkeypatch.setattr(collection_workflow.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("No expired worker"))
    result = collection_workflow.execute_worker({"stage": "collect", "runId": "live-20261023T000000Z"})
    assert result["timedOut"] is True
    assert result["deadlineUtc"] == "2026-10-23T08:00:00+00:00"


def test_worker_finishing_before_run_deadline_keeps_normal_result(monkeypatch):
    popen = subprocess.Popen

    def worker(command, **kwargs):
        return popen([sys.executable, "-c",
                      "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('{\"done\": true}')",
                      command[-1]], **kwargs)

    monkeypatch.setattr(collection_workflow.subprocess, "Popen", worker)
    assert collection_workflow.execute_worker({
        "stage": "process", "deadlineUtc": (datetime.now(UTC) + timedelta(seconds=10)).isoformat(),
    }) == {"done": True}


class PlanStore:
    def __init__(self):
        self.files = {}
        self.timings = OperationTotals()
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


@pytest.mark.parametrize("source,reuse,mode", [(None, False, "full"), (OTHER, False, "full"), (TENANT, True, "auto")])
def test_plan_isolates_tenant_baselines_without_losing_publication_concurrency(source, reuse, mode):
    store = PlanStore()
    baseline = {"complete": True, "runId": "live-20261022T160000Z", "files": []}
    if source:
        baseline["sourceTenantId"] = source
    store.download_blob = lambda: SimpleNamespace(
        readall=lambda: json.dumps(baseline).encode(), properties=SimpleNamespace(etag="original-etag"),
    )
    reference = prepare_run({
        "runId": "live-20261023T160000Z", "snapshotUtc": "2026-10-23T16:00:00+00:00", "collection": "auto",
    }, store, {})
    frozen = store.json(reference["planPath"])
    assert frozen["sourceTenantId"] == TENANT
    assert frozen["reuseBaseline"] is reuse
    assert frozen["collection"] == mode
    assert frozen["baseline"] == baseline
    assert frozen["baselineEtag"] == "original-etag"
    ensure_current_baseline(frozen, store)


@pytest.mark.parametrize("source", [None, OTHER])
def test_explicit_delta_cannot_use_an_unverified_or_other_tenant_baseline(source):
    store = PlanStore()
    store.download_blob = lambda: SimpleNamespace(
        readall=lambda: json.dumps({"complete": True, "sourceTenantId": source}).encode(),
        properties=SimpleNamespace(etag="original-etag"),
    )
    with pytest.raises(ValueError, match="verified baseline"):
        prepare_run({"runId": "live-20261023T160000Z", "collection": "delta"}, store, {})
    assert store.files == {}


def test_resuming_after_a_source_tenant_change_fails_without_modifying_the_plan(monkeypatch):
    store = PlanStore()
    request = {"runId": "live-20261023T160000Z"}
    prepare_run(request, store, {})
    frozen = dict(store.files)
    monkeypatch.setattr(collection_workflow, "create_credential", lambda *args: tenant_credential(OTHER))
    with pytest.raises(ValueError, match="another source tenant"):
        prepare_run(request, store, {})
    assert store.files == frozen


@pytest.mark.parametrize("current_id", [None, "live-20261022T160000Z", "live-20261023T160000Z", "live-20261024T160000Z"])
def test_obsolete_run_fails_before_downloads_if_baseline_has_been_superseded(current_id):
    store = PlanStore()
    if current_id:
        store.download_blob = lambda: SimpleNamespace(readall=lambda: json.dumps({
            "complete": True, "runId": current_id,
        }).encode())
    plan = {"runId": "live-20261023T160000Z", "baseline": {"runId": "live-20261022T160000Z"}}
    if current_id == "live-20261024T160000Z":
        with pytest.raises(ValueError, match="superseded"):
            ensure_current_baseline(plan, store)
    else:
        ensure_current_baseline(plan, store)
    assert store.files == {}


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


def test_failed_run_restarts_execution_with_original_checkpoints_not_rewind(caplog):
    original = {
        **recent_run_options(),
        "collection": "auto", "enrichment": "targeted", "pageSize": 2500, "_failures": 12,
    }
    store = PlanStore()
    reference = prepare_run(original, store, {"policyVersion": "original"})
    frozen = dict(store.files)
    store.settings.exclude_scale_sets = True
    client = SimpleNamespace(
        get_status=AsyncMock(return_value=SimpleNamespace(
            runtime_status=SimpleNamespace(value="Failed"), input_=original,
        )),
        start_new=AsyncMock(return_value=INSTANCE_ID), rewind=AsyncMock(),
    )
    with caplog.at_level(logging.INFO):
        assert asyncio.run(start_collection(client, {"collection": "full", "pageSize": 100})) == INSTANCE_ID
    client.get_status.assert_awaited_once_with(INSTANCE_ID, show_input=True)
    client.rewind.assert_not_called()
    client.start_new.assert_awaited_once_with(
        "dataprep_orchestrator", INSTANCE_ID, {**original, "_failures": 0},
    )
    assert original["_failures"] == 12
    recovered = client.start_new.call_args.args[2]
    assert prepare_run(recovered, store, {"policyVersion": "changed"}) == reference
    assert store.files == frozen
    assert "Requested checkpoint recovery" in caplog.text
    assert original["runId"] in caplog.text


def test_explicit_fresh_request_replaces_failed_scope_but_not_its_evidence():
    original = {"runId": "live-20261023T160000Z", "snapshotUtc": "2026-10-23T16:00:00+00:00"}
    client = SimpleNamespace(
        get_status=AsyncMock(return_value=SimpleNamespace(
            runtime_status=SimpleNamespace(value="Failed"), input_=original,
        )),
        start_new=AsyncMock(return_value=INSTANCE_ID),
    )
    assert asyncio.run(start_collection(client, {"collection": "auto", "fresh": True})) == INSTANCE_ID
    request = client.start_new.call_args.args[2]
    assert request["runId"] != original["runId"]
    assert request["collection"] == "auto"
    assert "fresh" not in request
    assert "_failures" not in request
    assert original == {"runId": "live-20261023T160000Z", "snapshotUtc": "2026-10-23T16:00:00+00:00"}


@pytest.mark.parametrize("state", ["Running", "Pending", "Suspended", "ContinuedAsNew"])
def test_fresh_request_never_replaces_an_active_run(state):
    client = SimpleNamespace(
        get_status=AsyncMock(return_value=SimpleNamespace(runtime_status=SimpleNamespace(value=state))),
        start_new=AsyncMock(),
    )
    with pytest.raises(RuntimeError, match="explicitly stop"):
        asyncio.run(start_collection(client, {"fresh": True}))
    client.start_new.assert_not_called()


@pytest.mark.parametrize("original", [
    None, [], "{}", "{invalid", {},
    {"runId": "invalid", "snapshotUtc": "2026-10-23T16:00:00Z"},
    {"runId": "live-20261023T160000Z"},
    {"runId": "live-20261023T160000Z", "snapshotUtc": "invalid"},
    {"runId": "live-20261023T160000Z", "snapshotUtc": "2026-10-23T16:00:00"},
    {"runId": "live-20261023T160000Z", "snapshotUtc": "2026-10-23T17:00:00Z"},
])
def test_failed_run_without_valid_original_identity_does_not_start_fresh(original):
    client = SimpleNamespace(
        get_status=AsyncMock(return_value=SimpleNamespace(
            runtime_status=SimpleNamespace(value="Failed"), input_=original,
        )),
        start_new=AsyncMock(), rewind=AsyncMock(),
    )
    with pytest.raises(RuntimeError, match="Cannot recover failed collection"):
        asyncio.run(start_collection(client, {"collection": "full"}))
    client.start_new.assert_not_called()
    client.rewind.assert_not_called()


def test_failed_recovery_submission_does_not_log_success(caplog):
    client = SimpleNamespace(
        get_status=AsyncMock(return_value=SimpleNamespace(
            runtime_status=SimpleNamespace(value="Failed"), input_=recent_run_options(),
        )),
        start_new=AsyncMock(side_effect=RuntimeError("Durable unavailable")), rewind=AsyncMock(),
    )
    with caplog.at_level(logging.INFO), pytest.raises(RuntimeError, match="Durable unavailable"):
        asyncio.run(start_collection(client, {}))
    assert "Requested checkpoint recovery" not in caplog.text
    client.rewind.assert_not_called()


@pytest.mark.parametrize("identifier", [None, "unexpected-instance"])
def test_recovery_rejects_unconfirmed_submission(identifier, caplog):
    client = SimpleNamespace(
        get_status=AsyncMock(return_value=SimpleNamespace(
            runtime_status=SimpleNamespace(value="Failed"), input_=recent_run_options(),
        )),
        start_new=AsyncMock(return_value=identifier), rewind=AsyncMock(),
    )
    with caplog.at_level(logging.INFO), pytest.raises(RuntimeError, match="expected collection instance ID"):
        asyncio.run(start_collection(client, {}))
    assert "Requested checkpoint recovery" not in caplog.text
    client.rewind.assert_not_called()


def test_repeated_trigger_keeps_recovery_execution_when_pending():
    client = SimpleNamespace(
        get_status=AsyncMock(side_effect=[
            SimpleNamespace(runtime_status=SimpleNamespace(value="Failed"), input_=recent_run_options()),
            SimpleNamespace(runtime_status=SimpleNamespace(value="Pending")),
        ]),
        start_new=AsyncMock(return_value=INSTANCE_ID), rewind=AsyncMock(),
    )

    async def invoke_twice():
        assert await start_collection(client, {}) == INSTANCE_ID
        assert await start_collection(client, {"collection": "full"}) == INSTANCE_ID

    asyncio.run(invoke_twice())
    client.start_new.assert_awaited_once()
    client.rewind.assert_not_called()


def test_first_start_records_only_small_run_options():
    client = SimpleNamespace(get_status=AsyncMock(return_value=None), start_new=AsyncMock(return_value=INSTANCE_ID))
    asyncio.run(start_collection(client, {"pageSize": 2500, "collection": "auto"}))
    args = client.start_new.call_args.args
    assert args[1] == INSTANCE_ID
    assert args[2]["pageSize"] == 2500
    assert datetime.fromisoformat(args[2]["snapshotUtc"]).tzinfo == UTC
    assert "findings" not in args[2]
    assert datetime.fromisoformat(args[2]["deadlineUtc"]) - datetime.fromisoformat(args[2]["snapshotUtc"]) == timedelta(hours=8)


@pytest.mark.parametrize("legacy", [False, True])
def test_failed_expired_run_starts_fresh_without_recovering_its_original_identity(legacy):
    original = {
        "runId": "live-20261023T000000Z", "snapshotUtc": "2026-10-23T00:00:00+00:00",
        "deadlineUtc": "2026-10-23T06:00:00+00:00",
    }
    if legacy:
        original.pop("deadlineUtc")
    client = SimpleNamespace(
        get_status=AsyncMock(return_value=SimpleNamespace(
            runtime_status=SimpleNamespace(value="Failed"), input_=original,
        )), start_new=AsyncMock(return_value=INSTANCE_ID),
    )
    asyncio.run(start_collection(client, {"collection": "auto"}))
    request = client.start_new.call_args.args[2]
    assert request["runId"] != original["runId"]
    assert request["collection"] == "auto"
    assert "_failures" not in request


def test_next_trigger_starts_fresh_after_timed_out_execution_completed():
    client = SimpleNamespace(
        get_status=AsyncMock(return_value=SimpleNamespace(
            runtime_status=SimpleNamespace(value="Completed"),
            custom_status={"phase": "timed_out", "timedOut": True},
        )), start_new=AsyncMock(return_value=INSTANCE_ID),
    )
    asyncio.run(start_collection(client, {}))
    client.start_new.assert_awaited_once()
    request = client.start_new.call_args.args[2]
    assert datetime.fromisoformat(request["deadlineUtc"]) - datetime.fromisoformat(request["snapshotUtc"]) == timedelta(hours=8)


@pytest.mark.parametrize("legacy", [False, True])
def test_expired_active_run_requests_termination_without_starting_overlapping_work(legacy):
    original = {"runId": "live-20261023T000000Z"}
    if not legacy:
        original["deadlineUtc"] = "2026-10-23T06:00:00+00:00"
    client = SimpleNamespace(
        get_status=AsyncMock(return_value=SimpleNamespace(
            runtime_status=SimpleNamespace(value="Running"), input_=original,
        )), start_new=AsyncMock(), terminate=AsyncMock(),
    )
    asyncio.run(start_collection(client, {}))
    client.terminate.assert_awaited_once_with(INSTANCE_ID, "Collection run deadline exceeded")
    client.start_new.assert_not_called()


def test_first_run_accepts_sdk_empty_status_for_missing_instance():
    missing = DurableOrchestrationStatus.from_json("No instance with ID vulnerability-collection found")
    assert not missing
    client = SimpleNamespace(get_status=AsyncMock(return_value=missing), start_new=AsyncMock(return_value=INSTANCE_ID))
    assert asyncio.run(start_collection(client, {"pageSize": 2500})) == INSTANCE_ID
    client.start_new.assert_awaited_once()


@pytest.mark.parametrize("serialized", [False, True])
@pytest.mark.parametrize("state", ["Running", "Pending", "Suspended", "ContinuedAsNew", "Failed", "Completed"])
def test_starter_handles_actual_sdk_existing_instance_status(state, serialized):
    original = recent_run_options()
    status = DurableOrchestrationStatus(
        instanceId=INSTANCE_ID, runtimeStatus=state,
        createdTime="2026-10-23T16:00:00Z", lastUpdatedTime="2026-10-23T16:01:00Z",
        input=json.dumps(original) if serialized else original,
    )
    client = SimpleNamespace(get_status=AsyncMock(return_value=status), start_new=AsyncMock(return_value=INSTANCE_ID), rewind=AsyncMock())
    assert asyncio.run(start_collection(client, {})) == INSTANCE_ID
    if state == "Completed":
        client.start_new.assert_awaited_once()
    elif state == "Failed":
        client.start_new.assert_awaited_once_with(
            "dataprep_orchestrator", INSTANCE_ID, {**original, "_failures": 0},
        )
        client.rewind.assert_not_called()
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
            "sourceTenantId": TENANT,
            "snapshotTimeUtc": "2026-10-23T16:00:00Z",
            "endpointStatuses": [{"Status": "Success"}],
            "files": [{
                "path": "curated/2026/10/23/run/findings.json.gz",
                "sizeBytes": len(self.raw), "sha256": hashlib.sha256(self.raw).hexdigest(),
                "dataset": "findings", "rowCount": 10,
            }],
        }
        self.append_json(self.reference["planPath"], {
            "baselineEtag": baseline_etag, "sourceTenantId": TENANT, "reuseBaseline": False,
        })
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


@pytest.mark.parametrize("source", [None, OTHER])
def test_publication_rejects_missing_or_mismatched_tenant_even_with_verified_files(source):
    store = PublicationStore()
    store.manifest["sourceTenantId"] = source
    store.save_manifest()
    verify_file({**store.reference, "fileIndex": 0}, store)
    frozen = dict(store.files)
    with pytest.raises(ValueError, match="source tenant provenance"):
        publish_run(store.reference, store)
    store.pointer.upload_blob.assert_not_called()
    assert store.files == frozen


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


def test_unavailable_optional_endpoint_is_a_note_not_partial_success(caplog):
    store = PublicationStore()
    store.manifest["endpointStatuses"].append({"Status": "OptionalUnavailable"})
    store.save_manifest()
    verify_file({**store.reference, "fileIndex": 0}, store)
    with caplog.at_level("INFO"):
        publish_run(store.reference, store)
    assert "status=Success" in caplog.text
    assert "reportedIssues=0 optionalNotes=1" in caplog.text


def test_incomplete_endpoint_data_is_reported_as_partial_success(caplog):
    store = PublicationStore()
    store.manifest["endpointStatuses"].append({"Status": "PartialSuccess"})
    store.save_manifest()
    verify_file({**store.reference, "fileIndex": 0}, store)
    with caplog.at_level("INFO"):
        publish_run(store.reference, store)
    assert "status=PartialSuccess" in caplog.text
    assert "reportedIssues=1" in caplog.text


class OrchestrationContext:
    def __init__(self):
        self.is_replaying = False
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
    deadline = "2026-10-23T08:00:00+00:00"
    assert context.statuses == [{"phase": "prepare", "runId": context.options["runId"], "deadlineUtc": deadline}]
    reference = {"runId": context.options["runId"], "planPath": "runs/plan.json", "deadlineUtc": deadline}
    assert workflow.send(reference)[0] == "dataprep_collect_batch"
    assert context.statuses[-1] == {"phase": "collect", **reference}
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


def test_new_workflow_batches_verification_and_preserves_legacy_replay():
    context = OrchestrationContext()
    context.options["workflowVersion"] = 2
    workflow = orchestrate(context)
    next(workflow)
    reference = {"runId": context.options["runId"], "planPath": "runs/plan.json"}
    workflow.send(reference)
    workflow.send({"done": True})
    activity, value = workflow.send({"done": True, "fileCount": 65})
    assert activity == "dataprep_verify_batch_v1"
    assert value["fileIndex"] == 0
    assert workflow.send({"nextIndex": 32, "verified": True})[1]["fileIndex"] == 32
    assert workflow.send({"nextIndex": 64, "verified": True})[1]["fileIndex"] == 64
    assert workflow.send({"nextIndex": 65, "verified": True})[0] == "dataprep_publish"


def batch_store(count=65):
    store = PublicationStore()
    item = store.manifest["files"][0]
    store.manifest["files"] = [{**item, "path": f"curated/run/{index}.gz"} for index in range(count)]
    store.save_manifest()
    store.files[f"{store.prefix}/prepared.json"] = json.dumps({
        "manifestPath": f"{store.prefix}/manifest.json", "verificationVersion": 1,
    })
    store.history.download_blob = Mock(
        side_effect=lambda name, **kwargs: SimpleNamespace(chunks=lambda: iter([store.raw])),
    )
    return store


def test_verification_batches_cover_every_file_and_resume_without_redownload():
    store = batch_store()
    next_index = 0
    while next_index < 65:
        result = collection_workflow.verify_batch({**store.reference, "fileIndex": next_index}, store)
        assert 0 < result["nextIndex"] - next_index <= 32
        next_index = result["nextIndex"]
    assert store.history.download_blob.call_count == 65
    frozen = dict(store.files)
    result = collection_workflow.verify_batch({**store.reference, "fileIndex": 0}, store)
    assert result["nextIndex"] == 32
    assert store.files == frozen
    assert store.history.download_blob.call_count == 65
    assert publish_run(store.reference, store)["published"] is True


def test_batch_publication_rejects_missing_or_conflicting_coverage():
    store = batch_store(2)
    collection_workflow.verify_batch({**store.reference, "fileIndex": 0}, store)
    receipt_path = f"{store.prefix}/verified/batches/000000.json"
    receipt = json.loads(store.files[receipt_path])
    receipt["proofs"].pop()
    store.files[receipt_path] = json.dumps(receipt)
    with pytest.raises(ValueError, match="verification"):
        publish_run(store.reference, store)
    store.pointer.upload_blob.assert_not_called()


def test_batch_verification_never_commits_receipt_for_corrupt_bytes():
    store = batch_store(4)
    store.raw = b"corrupt"
    with pytest.raises(ValueError, match="verification"):
        collection_workflow.verify_batch({**store.reference, "fileIndex": 0}, store)
    assert not any("/verified/batches/" in name for name in store.files)
    store.pointer.upload_blob.assert_not_called()


def test_verification_batch_limits_bytes_and_handles_an_oversized_file():
    store = batch_store(3)
    store.manifest["files"][0]["sizeBytes"] = collection_workflow.VERIFICATION_BYTES + 1
    store.save_manifest()
    for index, item in enumerate(store.manifest["files"]):
        store.append_json(f"{store.prefix}/verified/{index:06d}.json", {
            key: item[key] for key in ("path", "sha256", "sizeBytes")
        })
    assert collection_workflow.verify_batch({**store.reference, "fileIndex": 0}, store)["nextIndex"] == 1
    assert collection_workflow.verify_batch({**store.reference, "fileIndex": 1}, store)["nextIndex"] == 3
    store.history.download_blob.assert_not_called()


def test_verification_batch_resumes_partial_proofs_but_rejects_wrong_proofs():
    store = batch_store(4)
    item = store.manifest["files"][0]
    path = f"{store.prefix}/verified/000000.json"
    store.append_json(path, {key: item[key] for key in ("path", "sha256", "sizeBytes")})
    assert collection_workflow.verify_batch({**store.reference, "fileIndex": 0}, store)["nextIndex"] == 4
    assert store.history.download_blob.call_count == 3
    del store.files[f"{store.prefix}/verified/batches/000000.json"]
    store.files[path] = json.dumps({"path": "wrong"})
    with pytest.raises(ValueError, match="proof mismatch"):
        collection_workflow.verify_batch({**store.reference, "fileIndex": 0}, store)


def test_verification_batch_caps_parallel_downloads():
    import threading

    store = batch_store(12)
    lock = threading.Lock()
    active = peak = 0

    def download(name, **kwargs):
        assert kwargs == {"max_concurrency": 1}

        def chunks():
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                time.sleep(0.01)
                yield store.raw
            finally:
                with lock:
                    active -= 1
        return SimpleNamespace(chunks=chunks)

    store.history.download_blob = download
    collection_workflow.verify_batch({**store.reference, "fileIndex": 0}, store)
    assert 1 < peak <= 4
    assert active == 0


def test_verification_batch_soft_budget_commits_completed_groups(monkeypatch):
    store = batch_store(12)
    clock = [0.0]
    monkeypatch.setattr(collection_workflow.time, "monotonic", lambda: clock[0])

    def download(name, **kwargs):
        clock[0] = collection_workflow.VERIFICATION_SECONDS + 1
        return SimpleNamespace(chunks=lambda: iter([store.raw]))

    store.history.download_blob = download
    assert collection_workflow.verify_batch({**store.reference, "fileIndex": 0}, store)["nextIndex"] == 4
    assert collection_workflow.verify_batch({**store.reference, "fileIndex": 4}, store)["nextIndex"] == 12


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
    assert context.continued == {**context.options, "_failures": 0, "deadlineUtc": "2026-10-23T08:00:00+00:00"}


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
    assert context.statuses[0]["phase"] == "prepare"
    assert all(status["phase"] == "collect" for status in context.statuses[1:])


def test_cooldown_is_clamped_to_original_deadline_and_does_not_schedule_more_work():
    context = OrchestrationContext()
    workflow = orchestrate(context)
    next(workflow)
    workflow.send({"runId": context.options["runId"], "planPath": "runs/plan.json"})
    timer = workflow.send({"done": False, "newRequests": 1, "retryAfter": 86400})
    assert timer == ("timer", datetime(2026, 10, 23, 8, tzinfo=UTC))
    context.current_utc_datetime = timer[1]
    with pytest.raises(StopIteration) as stopped:
        workflow.send(None)
    assert stopped.value.value["timedOut"] is True
    assert context.statuses[-1]["phase"] == "timed_out"
    assert context.continued is None


@pytest.mark.parametrize("stage", ["prepare", "collect", "process", "verify", "publish"])
def test_orchestrator_stops_on_activity_timeout_without_retries_or_publication(stage):
    context = OrchestrationContext()
    workflow = orchestrate(context)
    next(workflow)
    reference = {"runId": context.options["runId"], "planPath": "runs/plan.json"}
    if stage != "prepare":
        workflow.send(reference)
    if stage in {"process", "verify", "publish"}:
        workflow.send({"done": True})
    if stage in {"verify", "publish"}:
        workflow.send({"done": True, "fileCount": 1})
    if stage == "publish":
        workflow.send({"verified": True})
    with pytest.raises(StopIteration) as stopped:
        workflow.send({"timedOut": True, "done": False, "reason": "Six-hour deadline reached"})
    assert stopped.value.value["timedOut"] is True
    assert context.statuses[-1]["phase"] == "timed_out"
    assert all(status["phase"] != "completed" for status in context.statuses)


def test_continued_execution_does_not_reset_deadline():
    context = OrchestrationContext()
    context.options["deadlineUtc"] = "2026-10-23T06:00:00+00:00"
    context.current_utc_datetime = datetime(2026, 10, 23, 6, tzinfo=UTC)
    workflow = orchestrate(context)
    with pytest.raises(StopIteration) as stopped:
        next(workflow)
    assert stopped.value.value["deadlineUtc"] == context.options["deadlineUtc"]
    assert context.statuses[-1]["phase"] == "timed_out"


def test_requested_deadline_cannot_extend_eight_hour_original_run_limit():
    context = OrchestrationContext()
    context.options["deadlineUtc"] = "2026-10-24T00:00:00+00:00"
    request = next(orchestrate(context))[1]
    assert request["deadlineUtc"] == "2026-10-23T08:00:00+00:00"


@pytest.mark.parametrize("replaying", [False, True])
@pytest.mark.parametrize("state", ["Completed", "Failed", "TimedOut"])
def test_terminal_run_markers_are_correlated_and_not_duplicated_on_durable_replay(caplog, replaying, state):
    context = OrchestrationContext()
    context.is_replaying = replaying
    workflow = orchestrate(context)
    with caplog.at_level(logging.INFO):
        next(workflow)
        if state == "Failed":
            with pytest.raises(RuntimeError, match="activity failed"):
                workflow.throw(RuntimeError("activity failed"))
        elif state == "TimedOut":
            with pytest.raises(StopIteration):
                workflow.send({"timedOut": True, "reason": "Six-hour deadline reached"})
        else:
            workflow.send({"runId": context.options["runId"], "planPath": "runs/plan.json"})
            workflow.send({"done": True})
            workflow.send({"done": True, "fileCount": 0})
            with pytest.raises(StopIteration):
                workflow.send({"runId": context.options["runId"], "published": True})
    expected = f"[collector_run] runId={context.options['runId']} state={state}"
    assert (expected in caplog.text) is not replaying


def test_expired_run_cannot_replace_current_manifest():
    store = PublicationStore()
    reference = {**store.reference, "deadlineUtc": "2026-10-23T00:00:00+00:00"}
    with pytest.raises(collection_workflow.CollectionDeadlineExceeded):
        publish_run(reference, store)
    store.pointer.upload_blob.assert_not_called()


def test_expiry_during_publication_checks_prevents_pointer_update(monkeypatch):
    store = PublicationStore()
    for index in range(len(store.manifest["files"])):
        verify_file({**store.reference, "fileIndex": index}, store)
    guard = Mock(side_effect=[None, collection_workflow.CollectionDeadlineExceeded("Six-hour deadline reached")])
    monkeypatch.setattr(collection_workflow, "check_collection_deadline", guard)
    with pytest.raises(collection_workflow.CollectionDeadlineExceeded):
        publish_run(store.reference, store)
    assert guard.call_count == 2
    store.pointer.upload_blob.assert_not_called()
