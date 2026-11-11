import pytest


@pytest.fixture
def configured_function_target(monkeypatch):
    from vulnerability_view import operations_cli

    monkeypatch.setattr(operations_cli, "_values", lambda: {
        "tenant_id": "tenant",
        "subscription_id": "subscription",
        "resource_group_name": "rg-test",
        "function_app_name": "func-test",
    })
    monkeypatch.setattr(operations_cli, "_azure_json", lambda *args: {"tenantId": "tenant", "id": "subscription"})
    monkeypatch.setattr(operations_cli, "_tf", lambda *args, **kwargs: pytest.fail("Function operations must not require Terraform"))


@pytest.fixture
def configured_webapp_target(monkeypatch):
    from vulnerability_view import operations_cli

    values = {
        "tenant_id": "tenant",
        "subscription_id": "subscription",
        "resource_group_name": "rg-test",
        "web_app_name": "app-test",
    }
    monkeypatch.setattr(operations_cli, "_values", lambda: values)
    monkeypatch.setattr(operations_cli, "_azure_json", lambda *args: {"tenantId": "tenant", "id": "subscription"})
    monkeypatch.setattr(operations_cli, "_tf", lambda *args, **kwargs: pytest.fail("Web App code operations must not require Terraform"))
    return values
