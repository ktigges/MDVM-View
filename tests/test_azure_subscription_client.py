import json

import requests

from vulnerability_view.azure_subscription_client import (
    ARM_MANAGEMENT_GROUP_DESCENDANTS_URL,
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


def test_collect_azure_subscriptions_uses_management_group_descendants(monkeypatch):
    response = requests.Response()
    response.status_code = 200
    response._content = json.dumps({
        "value": [
            {
                "type": "Microsoft.Management/managementGroups",
                "name": "nested-group",
                "properties": {"displayName": "Nested"},
            },
            {
                "type": "Microsoft.Management/managementGroups/subscriptions",
                "name": "subscription-1",
                "properties": {"displayName": "Production"},
            },
        ],
    }).encode()

    def fake_get(url, headers, timeout):
        assert url == ARM_MANAGEMENT_GROUP_DESCENDANTS_URL.format(management_group_id="customer-group")
        return response

    monkeypatch.setattr("requests.get", fake_get)

    rows, status = collect_azure_subscriptions(Credential(), management_group_id="customer-group")

    assert rows == [{
        "subscriptionId": "subscription-1",
        "displayName": "Production",
        "state": "",
        "tenantId": "",
    }]
    assert status["RowCount"] == 1


def _graph_response(status_code, payload=None):
    response = requests.Response()
    response.status_code = status_code
    response._content = json.dumps(payload or {}).encode()
    return response


def test_collect_scale_set_members_pages_resource_graph_and_archives_each_page(monkeypatch):
    from vulnerability_view.azure_subscription_client import ARG_RESOURCES_URL, collect_scale_set_members

    pages = [
        {"data": [{"id": "/SUBSCRIPTIONS/s/RESOURCEGROUPS/rg/providers/Microsoft.Compute/virtualMachines/flex_1",
                   "scaleSetId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/flex"}],
         "$skipToken": "next"},
        {"data": [{"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/flex_2"}]},
    ]
    bodies, archived = [], []

    def fake_post(url, headers, json, timeout):
        assert url == ARG_RESOURCES_URL
        assert headers["Authorization"] == "Bearer not-a-real-token"
        bodies.append(json)
        return _graph_response(200, pages[len(bodies) - 1])

    monkeypatch.setattr("requests.post", fake_post)
    rows, status = collect_scale_set_members(Credential(), lambda page, content: archived.append(page), "mg-1")

    assert [row["ResourceId"] for row in rows] == [
        "/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/flex_1",
        "/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/flex_2",
    ]
    assert rows[0]["ScaleSetId"].endswith("/virtualmachinescalesets/flex")
    assert "$skipToken" not in bodies[0]["options"] and bodies[1]["options"]["$skipToken"] == "next"
    assert bodies[0]["managementGroups"] == ["mg-1"]
    assert "virtualMachineScaleSet" in bodies[0]["query"]
    assert status["Status"] == "Success" and status["RowCount"] == 2 and status["PageCount"] == 2
    assert archived == [1, 2]


def test_collect_scale_set_members_without_reader_falls_back_empty(monkeypatch):
    from vulnerability_view.azure_subscription_client import collect_scale_set_members

    monkeypatch.setattr("requests.post", lambda *args, **kwargs: _graph_response(403))
    rows, status = collect_scale_set_members(Credential())
    assert rows == []
    assert status["Status"] == "OptionalUnavailable"
    assert "Reader" in status["Error"] and "Flexible" in status["Error"]


def test_collect_scale_set_members_errors_never_raise(monkeypatch):
    from vulnerability_view.azure_subscription_client import collect_scale_set_members

    class Broken:
        def get_token(self, scope):
            raise RuntimeError("no token")

    rows, status = collect_scale_set_members(Broken())
    assert rows == [] and status["Status"] == "OptionalUnavailable" and status["Error"] == "no token"

    def partial(url, headers, json, timeout):
        if json["options"].get("$skipToken"):
            raise requests.ConnectionError("network down")
        return _graph_response(200, {"data": [{"id": "/a/virtualMachines/x"}], "$skipToken": "t"})

    monkeypatch.setattr("requests.post", partial)
    rows, status = collect_scale_set_members(Credential())
    assert rows == [] and status["Status"] == "OptionalUnavailable" and status["RowCount"] == 0
