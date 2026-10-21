import json
import logging
import threading
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
from unittest.mock import Mock
from zipfile import ZipFile

import pytest
import requests

import function_app
from vulnerability_view import collection_diagnostics as diagnostics, operations_cli
from vulnerability_view.config import Settings
from vulnerability_view.defender_client import DefenderClient


class Credential:
    def get_token(self, scope):
        return SimpleNamespace(token="secret-token")


@pytest.fixture
def diagnostic_storage(monkeypatch, tmp_path):
    uploads = {}
    heartbeat = threading.Event()
    failures = []

    class Container:
        def upload_blob(self, name, data, **kwargs):
            assert kwargs == {"overwrite": False, "timeout": 5}
            if failures:
                raise failures[0]
            assert name not in uploads
            uploads[name] = data
            if any(row["event"] == "heartbeat" for row in map(json.loads, data.decode().splitlines())):
                heartbeat.set()

    class Service:
        def __init__(self, **kwargs):
            assert kwargs["retry_total"] == 0

        def get_container_client(self, name):
            assert name == "history"
            return Container()

        def close(self):
            pass

    settings = Settings(
        auth_mode="managed_identity", storage_account_name="teststore", storage_container_name="history",
        client_secret="secret-value", client_id="configured-client", tenant_id="configured-tenant",
        exclude_scale_sets=True,
    )
    monkeypatch.setattr(diagnostics.Settings, "load", lambda: settings)
    monkeypatch.setattr(diagnostics, "create_credential", lambda *args: Credential())
    monkeypatch.setattr(diagnostics, "BlobServiceClient", Service)
    original = diagnostics.CollectionDiagnostics
    recorders = []

    def create(identifier, settings):
        recorder = original(identifier, settings, root=tmp_path, flush_seconds=0.01)
        recorders.append(recorder)
        return recorder

    monkeypatch.setattr(diagnostics, "CollectionDiagnostics", create)
    return SimpleNamespace(uploads=uploads, heartbeat=heartbeat, failures=failures, recorders=recorders)


def events(storage):
    return [
        json.loads(line)
        for name, content in sorted(storage.uploads.items())
        for line in content.decode().splitlines()
    ]


def response(status=200):
    result = requests.Response()
    result.status_code = status
    result._content = b'{"value": [{"private-device": "never-record-response-bodies"}]}'
    result.headers["x-ms-request-id"] = "11111111-2222-3333-4444-555555555555"
    return result


def test_request_capture_persists_before_request_returns_and_has_heartbeat(diagnostic_storage, monkeypatch):
    identifier = str(uuid4())
    client = DefenderClient("https://example.test", Credential())
    expected = response()
    url = "https://example.test/api/vulnerabilities/machinesVulnerabilities?%24filter=machineId+eq+%27private-device%27&%24top=100"
    calls = []

    def get(request_url, **kwargs):
        calls.append((request_url, kwargs))
        assert diagnostic_storage.heartbeat.wait(3), "Heartbeat must be durable while the API request is blocked"
        assert any(row["event"] == "request_started" for row in events(diagnostic_storage))
        return expected

    monkeypatch.setattr(client.session, "get", get)
    with diagnostics.manual_collection_diagnostics(identifier, "2026.10.21.1", "full", 100):
        assert client.request(url) is expected
    rows = events(diagnostic_storage)
    assert calls[0][0] == url
    assert calls[0][1]["timeout"] == (10, 90)
    assert len(calls) == 1
    finished = next(row for row in rows if row["event"] == "request_finished")
    assert finished["httpStatus"] == 200
    assert finished["responseHeaders"]["x-ms-request-id"] == expected.headers["x-ms-request-id"]
    assert finished["durationSeconds"] >= 0
    assert rows[-2]["event"] == "collection_completed"
    assert rows[-2]["publicationObserved"] is False
    assert rows[-1]["event"] == "capture_finished"
    text = json.dumps(rows)
    for secret in ("secret-token", "private-device", "never-record-response-bodies", "configured-client", "secret-value"):
        assert secret not in text
    assert all(name.startswith(diagnostics.diagnostic_prefix(identifier)) for name in diagnostic_storage.uploads)


@pytest.mark.parametrize("enabled", [False, True])
def test_diagnostics_do_not_change_shared_retry_budget_delays_or_exception(diagnostic_storage, monkeypatch, enabled):
    calls = []
    delays = []
    expected_error = requests.ReadTimeout("timeout")
    throttled = response(429)
    throttled.headers["Retry-After"] = "2"
    client = DefenderClient("https://example.test", Credential(), max_attempts=3)

    def get(url, **kwargs):
        calls.append((url, kwargs))
        if len(calls) == 1:
            return throttled
        raise expected_error

    monkeypatch.setattr(client.session, "get", get)
    monkeypatch.setattr("vulnerability_view.defender_client.time.sleep", delays.append)
    monkeypatch.setattr("vulnerability_view.defender_client.random.random", lambda: 0.5)
    from contextlib import nullcontext

    scope = diagnostics.manual_collection_diagnostics(str(uuid4()), "2026.10.21.1", "full", 100) if enabled else nullcontext()
    with pytest.raises(requests.ReadTimeout) as error:
        with scope:
            client.request("https://example.test/page")
    assert error.value is expected_error
    assert len(calls) == 3
    assert delays == [2, 2.5]
    assert all(kwargs["timeout"] == (10, 90) for _, kwargs in calls)
    if enabled:
        rows = events(diagnostic_storage)
        assert len([row for row in rows if row["event"] == "request_started"]) == 3
        assert len([row for row in rows if row["event"] == "retry_wait"]) == 2
        assert next(row for row in rows if row["event"] == "collection_failed")["errorType"] == "ReadTimeout"
    else:
        assert not diagnostic_storage.uploads


def test_storage_failure_preserves_collection_result_and_local_evidence(diagnostic_storage, caplog):
    diagnostic_storage.failures.append(PermissionError("Storage denied"))
    identifier = str(uuid4())
    with diagnostics.manual_collection_diagnostics(identifier, "2026.10.21.1", "full", 100):
        diagnostics.record_diagnostic("progress", message="still collecting")
    assert "Could not persist diagnostics" in caplog.text
    assert not diagnostic_storage.uploads
    files = list(diagnostic_storage.recorders[0].folder.glob("*.jsonl"))
    assert files
    assert "collection_completed" in "".join(path.read_text() for path in files)


def test_diagnostic_setup_failure_does_not_prevent_collection(monkeypatch, caplog):
    monkeypatch.setattr(diagnostics.Settings, "load", lambda: (_ for _ in ()).throw(ValueError("bad diagnostic configuration")))
    collected = []
    with diagnostics.manual_collection_diagnostics(str(uuid4()), "2026.10.21.1", "full", 100):
        collected.append(True)
    assert collected == [True]
    assert "Could not start manual collection diagnostics" in caplog.text
    assert diagnostics._current.get() is None


def test_manual_function_records_failure_without_changing_exception_or_parameters(diagnostic_storage, monkeypatch):
    expected = RuntimeError("private error with Bearer secret-token")
    calls = []

    def collect(*args, **kwargs):
        calls.append((args, kwargs))
        raise expected

    monkeypatch.setattr(function_app, "_run_dataprep", collect)
    identifier = str(uuid4())
    invocation = str(uuid4())
    with pytest.raises(RuntimeError) as error:
        function_app.dataprep_full_snapshot(
            json.dumps({"diagnosticId": identifier, "pageSize": 100}),
            Mock(spec=function_app.func.Context, invocation_id=invocation),
        )
    assert error.value is expected
    assert calls == [(("full", "full"), {"page_size": 100})]
    rows = events(diagnostic_storage)
    assert rows[0]["diagnosticId"] == identifier
    assert rows[0]["invocationId"] == invocation
    assert rows[0]["excludeScaleSets"] is True
    failure = next(row for row in rows if row["event"] == "collection_failed")
    assert failure["errorType"] == "RuntimeError"
    assert failure["stack"]
    assert "secret-token" not in json.dumps(rows)
    assert not any(row["event"] == "collection_completed" for row in rows)
    assert diagnostics._current.get() is None
    assert not any(isinstance(handler, diagnostics._DiagnosticLogHandler) for handler in logging.getLogger().handlers)


def test_capture_marks_publication_only_when_existing_publication_trace_is_emitted(diagnostic_storage, caplog):
    caplog.set_level(logging.INFO)
    with diagnostics.manual_collection_diagnostics(str(uuid4()), "2026.10.21.1", "full", 100):
        logging.info("[publication] runId=live-20261021T120000Z status=Success files=20")
    assert next(row for row in events(diagnostic_storage) if row["event"] == "collection_completed")["publicationObserved"] is True


def test_sanitizer_removes_credentials_identifiers_and_continuation_tokens():
    sanitizer = diagnostics.DiagnosticSanitizer(("secret-value",))
    url = "https://user:password@example.test/api/machines?sig=secret-sas&cursor=private-cursor&%24top=100"
    text = sanitizer.text(
        f'{url} Bearer secret-token secret-value x-functions-key: host-secret '
        'machine 2/5: "private-machine.example" (machineId=private-device) person@example.test 10.20.30.40'
    )
    for secret in ("user:password", "secret-sas", "private-cursor", "secret-token", "secret-value", "host-secret", "private-machine", "private-device", "person@", "10.20.30.40"):
        assert secret not in text
    assert "%24top=100" in text
    assert "/api/machines" in text
    assert sanitizer.text("503 after 5 attempts: private response body") == "503 after 5 attempts: [API_ERROR_BODY_OMITTED]"
    assert "quoted-secret" not in sanitizer.text('{"x-functions-key": "quoted-secret"}')
    assert "quoted-secret" not in sanitizer.text('{"client_secret": "quoted-secret"}')


@pytest.mark.parametrize("invalid", ["../escape", "not-a-uuid", "A" * 36, ""])
def test_diagnostic_paths_reject_invalid_ids(invalid):
    with pytest.raises(ValueError):
        diagnostics.diagnostic_prefix(invalid)


@pytest.fixture
def download_storage(monkeypatch, tmp_path):
    monkeypatch.setattr(operations_cli, "ROOT", tmp_path)
    monkeypatch.setattr(operations_cli, "_values", lambda: {
        "history_storage_account_name": "teststore", "history_container_name": "history", "tenant_id": "tenant",
    })
    monkeypatch.setattr(operations_cli, "AzureCliCredential", lambda **kwargs: Credential())
    blobs = {}
    reads = []

    class Container:
        def list_blobs(self, **kwargs):
            return [SimpleNamespace(name=name) for name in reversed(blobs) if name.startswith(kwargs["name_starts_with"])]

        def download_blob(self, name):
            reads.append(name)
            return SimpleNamespace(readall=lambda: blobs[name])

    class Service:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get_container_client(self, name):
            assert name == "history"
            return Container()

    monkeypatch.setattr(operations_cli, "BlobServiceClient", Service)
    return blobs, reads


@pytest.mark.parametrize("terminal", ["collection_completed", "collection_failed", None])
def test_download_bundle_is_correlated_ordered_and_reports_missing_terminal(download_storage, terminal, capsys):
    blobs, reads = download_storage
    identifier = str(uuid4())
    prefix = diagnostics.diagnostic_prefix(identifier)
    rows = [
        {"diagnosticId": identifier, "event": "collection_started"},
        {"diagnosticId": identifier, "event": terminal or "heartbeat", "publicationObserved": False},
    ]
    for index, row in enumerate(rows, start=1):
        blobs[f"{prefix}{index:08d}.jsonl"] = (json.dumps(row) + "\n").encode()
    blobs[f"{prefix}../../escape.jsonl"] = b"invalid"
    archive = operations_cli.download_collection_diagnostics(identifier)
    with ZipFile(archive) as bundle:
        summary = json.loads(bundle.read("summary.json"))
        downloaded = list(map(json.loads, bundle.read("events.jsonl").decode().splitlines()))
    assert downloaded == rows
    assert summary["outcome"] == (terminal or "UNCONFIRMED")
    assert summary["publicationObserved"] is False
    assert reads == [f"{prefix}{index:08d}.jsonl" for index in (1, 2)]
    assert "Evidence is incomplete" in capsys.readouterr().out


def test_download_latest_receipt_and_missing_chunk_warning(download_storage, tmp_path, capsys):
    blobs, _ = download_storage
    identifier = str(uuid4())
    receipt_folder = tmp_path / "output/diagnostics/manual-receipts"
    receipt_folder.mkdir(parents=True)
    (receipt_folder / f"{identifier}.json").write_text(json.dumps({"diagnosticId": identifier}))
    prefix = diagnostics.diagnostic_prefix(identifier)
    blobs[f"{prefix}00000002.jsonl"] = (json.dumps({"diagnosticId": identifier, "event": "capture_finished", "droppedEvents": 2}) + "\n").encode()
    archive = operations_cli.download_collection_diagnostics()
    with ZipFile(archive) as bundle:
        summary = json.loads(bundle.read("summary.json"))
    assert summary["missingChunks"] is True
    assert summary["droppedEvents"] == 2
    assert summary["outcome"] == "UNCONFIRMED"
    assert "incomplete" in capsys.readouterr().out


def test_download_absent_evidence_does_not_claim_success(download_storage):
    with pytest.raises(RuntimeError, match="No durable evidence found"):
        operations_cli.download_collection_diagnostics(str(uuid4()))


def test_download_no_local_receipt_requires_explicit_id(download_storage):
    with pytest.raises(RuntimeError, match="Supply --id"):
        operations_cli.download_collection_diagnostics()


def test_lost_trigger_response_preserves_receipt_and_does_not_retry(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(operations_cli, "ROOT", tmp_path)
    monkeypatch.setattr(operations_cli, "_tf_output", lambda name: {"resource_group_name": "rg-test", "function_app_name": "func-test"}[name])
    monkeypatch.setattr(operations_cli, "_az", lambda *args, **kwargs: SimpleNamespace(stdout="secret-host-key"))
    calls = []
    error = requests.ReadTimeout("Trigger response lost")

    def post(url, **kwargs):
        calls.append((url, kwargs))
        raise error

    monkeypatch.setattr(operations_cli.requests, "post", post)
    with pytest.raises(requests.ReadTimeout) as raised:
        operations_cli.invoke(True, page_size=100)
    assert raised.value is error
    assert len(calls) == 1
    receipt_path = next((tmp_path / "output/diagnostics/manual-receipts").glob("*.json"))
    receipt = json.loads(receipt_path.read_text())
    assert receipt["acceptance"] == "UNCONFIRMED"
    assert receipt["options"]["pageSize"] == 100
    text = json.dumps(receipt) + capsys.readouterr().out
    assert "secret-host-key" not in text
    assert receipt["diagnosticId"] in text


def test_receipt_write_failure_does_not_block_manual_trigger(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(operations_cli, "ROOT", tmp_path)
    monkeypatch.setattr(operations_cli, "_tf_output", lambda name: {"resource_group_name": "rg-test", "function_app_name": "func-test"}[name])
    monkeypatch.setattr(operations_cli, "_az", lambda *args, **kwargs: SimpleNamespace(stdout="secret-host-key"))
    monkeypatch.setattr(Path, "write_text", lambda *args, **kwargs: (_ for _ in ()).throw(PermissionError("Disk denied")))
    calls = []
    monkeypatch.setattr(operations_cli.requests, "post", lambda url, **kwargs: calls.append(url) or SimpleNamespace(status_code=202, raise_for_status=lambda: None))
    operations_cli.invoke(True, page_size=100)
    assert len(calls) == 1
    output = capsys.readouterr()
    assert "Could not save invocation receipt" in output.err
    assert "trigger accepted" in output.out
