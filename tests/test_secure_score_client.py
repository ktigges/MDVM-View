import json

import pytest
import requests

from test_collection_transport import MemoryStore
from vulnerability_view.collection_transport import CheckpointYield, RequestCheckpoints, checkpoint_requests
from vulnerability_view.secure_score_client import GRAPH_SCOPE, collect_secure_scores


class Credential:
    def get_token(self, scope):
        assert scope == GRAPH_SCOPE
        return type("Token", (), {"token": "not-a-real-token"})()


def test_collect_secure_scores_uses_graph_and_archives(monkeypatch):
    archived = []
    response = requests.Response()
    response.status_code = 200
    response._content = json.dumps({"value": [{"currentScore": 42.0, "maxScore": 100.0}]}).encode()

    def fake_get(url, headers, timeout):
        assert url == "https://graph.microsoft.com/v1.0/security/secureScores?$top=1"
        assert headers["Authorization"] == "Bearer not-a-real-token"
        assert timeout == (10, 90)
        return response

    monkeypatch.setattr("requests.get", fake_get)

    rows, status = collect_secure_scores(Credential(), lambda content: archived.append(content))

    assert rows == [{"currentScore": 42.0, "maxScore": 100.0}]
    assert status["Status"] == "Success"
    assert archived == [response.content]


@pytest.mark.parametrize("failure", [504, 429, "ReadTimeout"])
def test_optional_secure_score_failure_does_not_yield_collection(monkeypatch, caplog, failure):
    transport = RequestCheckpoints(MemoryStore(), "raw/run/requests", {"graph.microsoft.com"})
    archived = []
    calls = []

    def get(url, **kwargs):
        calls.append(url)
        if failure == "ReadTimeout":
            raise requests.ReadTimeout("Graph lookup timed out")
        response = requests.Response()
        response.status_code = failure
        response._content = b"gateway or throttling error"
        return response

    monkeypatch.setattr(requests, "get", get)
    with checkpoint_requests(transport):
        rows, status = collect_secure_scores(Credential(), archived.append)

    assert rows == []
    assert status["Status"] == "OptionalUnavailable"
    assert status["Error"] == (failure if isinstance(failure, str) else f"HTTP {failure}")
    assert len(calls) == 1
    assert archived == []
    assert "continuing without Secure Score" in caplog.text


def test_secure_score_preserves_normal_batch_budget_yield(monkeypatch):
    transport = RequestCheckpoints(
        MemoryStore(), "raw/run/requests", {"graph.microsoft.com"}, request_limit=0,
    )
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: pytest.fail("No network call within exhausted budget"))
    with checkpoint_requests(transport), pytest.raises(CheckpointYield, match="activity budget reached"):
        collect_secure_scores(Credential())