import json

import requests

from vulnerability_view.azure_subscription_client import (
    ARM_SCOPE,
    ARM_SUBSCRIPTIONS_URL,
    collect_azure_subscriptions,
)


class Credential:
    def get_token(self, scope):
        assert scope == ARM_SCOPE
        return type("Token", (), {"token": "not-a-real-token"})()


def test_collect_azure_subscriptions_archives_accessible_inventory(monkeypatch):
    archived = []
    response = requests.Response()
    response.status_code = 200
    response._content = json.dumps({
        "value": [{
            "subscriptionId": "subscription-1",
            "displayName": "Production",
            "state": "Enabled",
            "tenantId": "tenant-1",
        }],
    }).encode()

    def fake_get(url, headers, timeout):
        assert url == ARM_SUBSCRIPTIONS_URL
        assert headers["Authorization"] == "Bearer not-a-real-token"
        assert timeout == (10, 90)
        return response

    monkeypatch.setattr("requests.get", fake_get)

    rows, status = collect_azure_subscriptions(Credential(), lambda page, content: archived.append((page, content)))

    assert rows[0]["displayName"] == "Production"
    assert status["Status"] == "Success"
    assert archived == [(1, response.content)]


def test_collect_azure_subscriptions_reports_missing_access(monkeypatch):
    response = requests.Response()
    response.status_code = 403
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: response)

    rows, status = collect_azure_subscriptions(Credential())

    assert rows == []
    assert status["Status"] == "OptionalUnavailable"
    assert "Reader access" in status["Error"]


def test_collect_azure_subscriptions_follows_next_link(monkeypatch):
    first = requests.Response()
    first.status_code = 200
    first._content = json.dumps({"value": [{"subscriptionId": "subscription-1"}], "nextLink": "https://next.test"}).encode()
    second = requests.Response()
    second.status_code = 200
    second._content = json.dumps({"value": [{"subscriptionId": "subscription-2"}]}).encode()
    responses = iter((first, second))
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: next(responses))

    rows, status = collect_azure_subscriptions(Credential())

    assert [row["subscriptionId"] for row in rows] == ["subscription-1", "subscription-2"]
    assert status["PageCount"] == 2
