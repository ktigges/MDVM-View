from vulnerability_view.credentials import create_credential, resolve_auth_mode


def test_auto_mode_uses_local_credentials_off_azure(monkeypatch):
    for name in ("WEBSITE_HOSTNAME", "IDENTITY_ENDPOINT", "MSI_ENDPOINT"):
        monkeypatch.delenv(name, raising=False)

    assert resolve_auth_mode("auto") == "local"


def test_auto_mode_uses_managed_identity_in_azure(monkeypatch):
    monkeypatch.setenv("IDENTITY_ENDPOINT", "http://identity.test")

    assert resolve_auth_mode("auto") == "managed_identity"


def test_local_credential_excludes_environment_secret(monkeypatch):
    captured = {}

    class Credential:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr("azure.identity.DefaultAzureCredential", Credential)

    create_credential("local")

    assert captured["exclude_environment_credential"] is True
    assert captured["exclude_managed_identity_credential"] is True
    assert captured["exclude_workload_identity_credential"] is True


def test_managed_identity_uses_configured_user_assigned_client_id(monkeypatch):
    captured = {}

    class Credential:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr("azure.identity.ManagedIdentityCredential", Credential)

    create_credential("managed_identity", "client-id")

    assert captured == {"client_id": "client-id"}


def test_client_secret_credential_requires_explicit_local_acknowledgement(monkeypatch):
    monkeypatch.delenv("ALLOW_LOCAL_CLIENT_SECRET", raising=False)

    try:
        create_credential("client_secret", "client-id", "tenant-id", "secret")
    except ValueError as error:
        assert "ALLOW_LOCAL_CLIENT_SECRET=true" in str(error)
    else:
        raise AssertionError("Expected unacknowledged client-secret authentication to fail")


def test_client_secret_credential_is_local_only(monkeypatch):
    monkeypatch.setenv("WEBSITE_HOSTNAME", "host.azurewebsites.net")

    try:
        create_credential("client_secret", "client-id", "tenant-id", "secret", True)
    except RuntimeError as error:
        assert "restricted to local development" in str(error)
    else:
        raise AssertionError("Expected client-secret authentication to fail on an Azure host")


def test_client_secret_credential_uses_explicit_values(monkeypatch):
    captured = {}

    class Credential:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    for name in ("WEBSITE_HOSTNAME", "IDENTITY_ENDPOINT", "MSI_ENDPOINT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("azure.identity.ClientSecretCredential", Credential)

    create_credential("client_secret", "client-id", "tenant-id", "secret", True)

    assert captured == {"tenant_id": "tenant-id", "client_id": "client-id", "client_secret": "secret"}
