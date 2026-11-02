import gzip
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError

from vulnerability_view.collection_transport import CheckpointYield, RequestCheckpoints, checkpoint_attempt, checkpoint_requests
from vulnerability_view.defender_client import ENDPOINTS, DefenderClient
from vulnerability_view.live_collector import _collect_referenced_catalog


class MemoryStore:
    def __init__(self):
        self.files = {}

    def read(self, name):
        if name not in self.files:
            raise ResourceNotFoundError("missing")
        return self.files[name]

    def append(self, name, content):
        if name in self.files:
            raise ResourceExistsError("exists")
        self.files[name] = content


def response(status=200, body=None):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(body or {"value": [{"id": "one"}]}).encode()
    return result


def test_restart_replays_verified_pages_without_network():
    store = MemoryStore()
    first = RequestCheckpoints(store, "raw/run/requests", {"example.test"}, request_limit=1)
    first.request("https://example.test/api/one", lambda: response())
    with pytest.raises(CheckpointYield):
        first.request("https://example.test/api/two", lambda: pytest.fail("budget exceeded"))
    restarted = RequestCheckpoints(store, "raw/run/requests", {"example.test"}, request_limit=1)
    replayed = restarted.request("https://example.test/api/one", lambda: pytest.fail("must not download again"))
    assert replayed.json() == {"value": [{"id": "one"}]}
    restarted.request("https://example.test/api/two", lambda: response())
    assert restarted.cached_requests == 1
    assert restarted.new_requests == 1
    assert len(store.files) == 2


def test_throttle_is_durable_delay_not_sleep_or_success_checkpoint():
    store = MemoryStore()
    checkpoints = RequestCheckpoints(store, "raw/run/requests", {"example.test"})
    with pytest.raises(CheckpointYield) as error:
        checkpoints.request("https://example.test/api", lambda: response(429), lambda value, attempt: 7200)
    assert error.value.delay == 7200
    assert store.files == {}


def test_corrupt_checkpoint_is_not_replaced_or_refetched():
    store = MemoryStore()
    checkpoints = RequestCheckpoints(store, "raw/run/requests", {"example.test"})
    checkpoints.request("https://example.test/api", lambda: response())
    name = next(iter(store.files))
    import gzip
    saved = json.loads(gzip.decompress(store.files[name]))
    saved["sha256"] = "bad"
    store.files[name] = gzip.compress(json.dumps(saved).encode())
    with pytest.raises(ValueError, match="integrity"):
        checkpoints.request("https://example.test/api", lambda: pytest.fail("corruption must fail"))


@pytest.mark.parametrize("url", ["http://example.test/api", "https://other.test/api", "https://example.test.evil/api"])
def test_checkpointed_requests_reject_untrusted_continuation_hosts(url):
    checkpoints = RequestCheckpoints(MemoryStore(), "raw/run/requests", {"example.test"})
    with pytest.raises(ValueError, match="approved HTTPS"):
        checkpoints.request(url, lambda: pytest.fail("must not send credentials"))


def test_cached_defender_page_does_not_request_token_again():
    class Credential:
        def get_token(self, scope):
            pytest.fail("cached page must not need token")

    store = MemoryStore()
    checkpoints = RequestCheckpoints(store, "raw/run/requests", {"example.test"})
    checkpoints.request("https://example.test/api", lambda: response())
    with checkpoint_requests(checkpoints):
        assert DefenderClient("https://example.test", Credential()).request("https://example.test/api").ok


def test_nonretryable_errors_are_not_cached():
    store = MemoryStore()
    checkpoints = RequestCheckpoints(store, "raw/run/requests", {"example.test"})
    assert checkpoints.request("https://example.test/api", lambda: response(403)).status_code == 403
    assert store.files == {}


def test_malformed_success_is_not_a_permanent_request_checkpoint():
    store = MemoryStore()
    checkpoints = RequestCheckpoints(store, "raw/run/requests", {"example.test"})
    invalid = response()
    invalid._content = b"not-json"
    with pytest.raises(requests.JSONDecodeError):
        checkpoints.request("https://example.test/api", lambda: invalid)
    assert store.files == {}


@pytest.mark.parametrize("body", [{"error": "bad page"}, {"value": None}, {"value": [1]}])
def test_invalid_success_page_is_not_cached(body):
    store = MemoryStore()
    checkpoints = RequestCheckpoints(store, "raw/run/requests", {"example.test"})
    with pytest.raises(ValueError, match="value list"):
        checkpoints.request("https://example.test/api", lambda: response(body=body))
    assert store.files == {}


def test_long_cached_replay_does_not_prevent_new_live_progress(monkeypatch):
    clock = [0]
    monkeypatch.setattr("vulnerability_view.collection_transport.time.monotonic", lambda: clock[0])
    store = MemoryStore()
    first = RequestCheckpoints(store, "raw/run/requests", {"example.test"})
    first.request("https://example.test/api/one", lambda: response())
    restarted = RequestCheckpoints(store, "raw/run/requests", {"example.test"})
    clock[0] = 600
    restarted.request("https://example.test/api/one", lambda: pytest.fail("saved request must replay"))
    restarted.request("https://example.test/api/two", lambda: response())
    assert restarted.cached_requests == restarted.saved_requests == 1


def test_new_http_work_is_still_time_bounded(monkeypatch):
    clock = [0]
    monkeypatch.setattr("vulnerability_view.collection_transport.time.monotonic", lambda: clock[0])
    checkpoints = RequestCheckpoints(MemoryStore(), "raw/run/requests", {"example.test"})

    def send():
        clock[0] += 241
        return response()

    checkpoints.request("https://example.test/api/one", send)
    with pytest.raises(CheckpointYield):
        checkpoints.request("https://example.test/api/two", lambda: pytest.fail("live budget exceeded"))


def catalog_client(tmp_path, monkeypatch, required_ids, payloads):
    folder = tmp_path / "live-20261023T160000Z"
    folder.mkdir()
    (folder / "machine_vulnerabilities-page-0001.json.gz").write_bytes(gzip.compress(json.dumps({
        "value": [{"cveId": value} for value in required_ids],
    }).encode()))
    calls = []

    def archive(name, page, content):
        (folder / f"{name}-page-{page:04d}.json.gz").write_bytes(gzip.compress(content))

    def send(url, **kwargs):
        calls.append(url)
        assert payloads, "Checkpoint replay must not make another live request"
        result = response(body={"value": payloads.pop(0)})
        result.url = url
        return result

    credential = SimpleNamespace(get_token=lambda *args: SimpleNamespace(token="test-token"))
    client = DefenderClient("https://example.test", credential, archive)
    monkeypatch.setattr(client.session, "get", send)
    endpoint = next(item for item in ENDPOINTS if item.name == "vulnerabilities")
    return client, endpoint, folder, calls


def test_missing_cve_refresh_targets_only_remaining_ids_and_replays_all_evidence(tmp_path, monkeypatch):
    ids = ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
    client, endpoint, folder, calls = catalog_client(
        tmp_path, monkeypatch, ids, [[{"id": value}] for value in ids],
    )
    store = MemoryStore()
    with checkpoint_requests(RequestCheckpoints(store, "raw/run/requests", {"example.test"})):
        _, status = _collect_referenced_catalog(client, endpoint, folder)
    assert status["RowCount"] == status["RequestedCveCount"] == 3
    assert status["PageCount"] == 3
    filters = [parse_qs(urlsplit(url).query)["$filter"][0] for url in calls]
    assert filters == [
        " or ".join(f"id eq '{value}'" for value in ids),
        " or ".join(f"id eq '{value}'" for value in ids[1:]),
        f"id eq '{ids[2]}'",
    ]
    archived = []
    for page in sorted(folder.glob("vulnerabilities-page-*.json.gz")):
        archived.extend(json.loads(gzip.decompress(page.read_bytes()))["value"])
    assert archived == [{"id": value} for value in ids]
    original = dict(store.files)
    replay = RequestCheckpoints(store, "raw/run/requests", {"example.test"})
    with checkpoint_requests(replay):
        _, repeated = _collect_referenced_catalog(client, endpoint, folder)
    assert repeated["RowCount"] == 3
    assert replay.cached_requests == 3
    assert replay.new_requests == 0
    assert store.files == original


def test_missing_single_cve_has_three_fresh_attempts_then_reports_partial_success_across_replay(tmp_path, monkeypatch, caplog):
    missing = "CVE-2026-0001"
    client, endpoint, folder, calls = catalog_client(tmp_path, monkeypatch, [missing], [[], [], [], []])
    store = MemoryStore()
    for replay in range(2):
        checkpoints = RequestCheckpoints(store, "raw/run/requests", {"example.test"})
        with checkpoint_requests(checkpoints):
            _, status = _collect_referenced_catalog(client, endpoint, folder)
        assert status["Status"] == "PartialSuccess"
        assert status["Required"] is False
        assert status["MissingCveIds"] == [missing]
        assert status["MissingCveCount"] == 1
        assert checkpoints.attempt == 0
        assert len(calls) == len(store.files) == 4
        assert len(set(calls)) == 1
        assert sum("/attempts/" in name for name in store.files) == 3
        if replay:
            assert checkpoints.new_requests == 0
            assert store.files == original
        else:
            original = dict(store.files)
    assert missing in caplog.text
    assert "retaining all findings" in caplog.text


def test_cve_refresh_preserves_activity_budget_and_continues_after_checkpoint_yield(tmp_path, monkeypatch):
    missing = "CVE-2026-0001"
    client, endpoint, folder, calls = catalog_client(
        tmp_path, monkeypatch, [missing], [[], [], [{"id": missing}]],
    )
    store = MemoryStore()
    for _ in range(2):
        checkpoints = RequestCheckpoints(store, "raw/run/requests", {"example.test"}, request_limit=1)
        with checkpoint_requests(checkpoints), pytest.raises(CheckpointYield):
            _collect_referenced_catalog(client, endpoint, folder)
        assert checkpoints.attempt == 0
        assert checkpoints.new_requests == 1
    checkpoints = RequestCheckpoints(store, "raw/run/requests", {"example.test"}, request_limit=1)
    with checkpoint_requests(checkpoints):
        _, status = _collect_referenced_catalog(client, endpoint, folder)
    assert status["RowCount"] == 1
    assert status["PageCount"] == 3
    assert checkpoints.new_requests == 1
    assert checkpoints.cached_requests == 2
    assert len(calls) == len(store.files) == 3


@pytest.mark.parametrize("on_refresh", [False, True])
def test_unexpected_cve_is_not_accepted_or_retried_further(tmp_path, monkeypatch, on_refresh):
    payloads = ([[]] if on_refresh else []) + [[{"id": "CVE-2099-9999"}]]
    client, endpoint, folder, calls = catalog_client(tmp_path, monkeypatch, ["CVE-2026-0001"], payloads)
    checkpoints = RequestCheckpoints(MemoryStore(), "raw/run/requests", {"example.test"})
    with checkpoint_requests(checkpoints), pytest.raises(RuntimeError, match="unexpected IDs: CVE-2099-9999"):
        _collect_referenced_catalog(client, endpoint, folder)
    assert len(calls) == (2 if on_refresh else 1)
    assert checkpoints.attempt == 0


def test_refresh_scope_restores_original_namespace_after_throttling():
    store = MemoryStore()
    checkpoints = RequestCheckpoints(store, "raw/run/requests", {"example.test"})
    with checkpoint_requests(checkpoints), pytest.raises(CheckpointYield):
        with checkpoint_attempt(1):
            checkpoints.request("https://example.test/api", lambda: response(429))
    assert checkpoints.attempt == 0
    assert store.files == {}


@pytest.mark.parametrize("failure", [429, 503, "timeout"])
def test_metadata_transport_unavailability_is_non_blocking_and_not_fabricated(tmp_path, monkeypatch, failure):
    ids = ["CVE-2026-0001", "CVE-2026-61359"]
    client, endpoint, folder, _ = catalog_client(tmp_path, monkeypatch, ids, [])
    sent = []

    def send(url, **kwargs):
        sent.append(url)
        if failure == "timeout":
            raise requests.ReadTimeout("Metadata endpoint timed out")
        result = response(status=failure, body={"value": []})
        result.url = url
        return result

    monkeypatch.setattr(client.session, "get", send)
    store = MemoryStore()
    checkpoints = RequestCheckpoints(store, "raw/run/requests", {"example.test"})
    with checkpoint_requests(checkpoints):
        _, status = _collect_referenced_catalog(client, endpoint, folder)
    assert status["Status"] == "PartialSuccess"
    assert status["MissingCveIds"] == ids
    assert status["MissingCveCount"] == 2
    assert status["Required"] is False
    assert status["Error"]
    assert len(sent) == 1
    assert store.files == {}
    assert not list(folder.glob("vulnerabilities-page-*.json.gz"))


def test_missing_cve_does_not_prevent_collection_of_later_catalog_batches(tmp_path, monkeypatch):
    ids = [f"CVE-2026-{index:04}" for index in range(1, 52)]
    payloads = [[{"id": value} for value in ids[1:50]], [], [], [], [{"id": ids[50]}]]
    client, endpoint, folder, calls = catalog_client(tmp_path, monkeypatch, ids, payloads)
    with checkpoint_requests(RequestCheckpoints(MemoryStore(), "raw/run/requests", {"example.test"})):
        _, status = _collect_referenced_catalog(client, endpoint, folder, cve_batch_size=50)
    assert status["MissingCveIds"] == [ids[0]]
    assert status["MissingCveCount"] == 1
    assert status["RequestedCveCount"] == 51
    assert status["RowCount"] == 50
    assert len(calls) == status["PageCount"] == 5
    assert parse_qs(urlsplit(calls[-1]).query)["$filter"] == [f"id eq '{ids[50]}'"]


def test_metadata_http_failure_after_a_page_preserves_received_catalog_rows(tmp_path, monkeypatch):
    ids = ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-61359"]
    client, endpoint, folder, _ = catalog_client(tmp_path, monkeypatch, ids, [[{"id": value} for value in ids[:2]]])
    client.page_size = 2
    original_get = client.session.get

    def get(url, **kwargs):
        if "$skip" in parse_qs(urlsplit(url).query):
            result = response(status=404, body={"value": []})
            result.url = url
            return result
        return original_get(url, **kwargs)

    monkeypatch.setattr(client.session, "get", get)
    with checkpoint_requests(RequestCheckpoints(MemoryStore(), "raw/run/requests", {"example.test"})):
        _, status = _collect_referenced_catalog(client, endpoint, folder)
    assert status["Status"] == "PartialSuccess"
    assert status["RowCount"] == 2
    assert status["PageCount"] == 1
    assert status["MissingCveIds"] == [ids[-1]]
    pages = list(folder.glob("vulnerabilities-page-*.json.gz"))
    assert len(pages) == 1
    assert json.loads(gzip.decompress(pages[0].read_bytes()))["value"] == [{"id": value} for value in ids[:2]]
