import json

import requests

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