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
