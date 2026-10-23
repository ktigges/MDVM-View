import json

import pytest
import requests
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError

from vulnerability_view.collection_transport import CheckpointYield, RequestCheckpoints, checkpoint_requests
from vulnerability_view.defender_client import DefenderClient


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
