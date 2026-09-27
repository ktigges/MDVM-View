from pathlib import Path

from vulnerability_view.config import Settings


ENVIRONMENT_KEYS = (
    "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "DEFENDER_API_BASE_URL",
    "AZURE_SUBSCRIPTION_ID", "AZURE_RESOURCE_GROUP", "AZURE_LOCATION", "STORAGE_ACCOUNT_NAME",
    "STORAGE_CONTAINER_NAME", "STORAGE_CURRENT_CONTAINER_NAME", "APP_MODE", "SYNTHETIC_SEED", "SYNTHETIC_MONTHS", "SYNTHETIC_DEVICE_COUNT",
    "RECOMMENDATION_ENRICHMENT_MODE", "ENABLE_EXPERIMENTAL_ENDPOINTS", "FULL_ENRICHMENT_WEEKDAY", "DASHBOARD_DATA_SOURCE", "DASHBOARD_STATIC_DIR", "DASHBOARD_CACHE_SECONDS",
    "DASHBOARD_AUTH_ENABLED",
    "DASHBOARD_DATA_BROWSER_ENABLED", "DASHBOARD_DATA_BROWSER_ROLE",
)


def test_settings_loads_dotenv_and_trims_values(monkeypatch, tmp_path: Path):
    for key in ENVIRONMENT_KEYS:
        monkeypatch.delenv(key, raising=False)
    env_path = tmp_path / ".env"
    env_path.write_text("AZURE_TENANT_ID=tenant-from-file\nSTORAGE_ACCOUNT_NAME=storagefromfile   \n", encoding="utf-8")

    settings = Settings.load(env_path=env_path)

    assert settings.tenant_id == "tenant-from-file"
    assert settings.storage_account_name == "storagefromfile"


def test_exported_environment_overrides_dotenv(monkeypatch, tmp_path: Path):
    for key in ENVIRONMENT_KEYS:
        monkeypatch.delenv(key, raising=False)
    env_path = tmp_path / ".env"
    env_path.write_text("AZURE_TENANT_ID=tenant-from-file\n", encoding="utf-8")
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-from-shell")

    settings = Settings.load(env_path=env_path)

    assert settings.tenant_id == "tenant-from-shell"


def test_enrichment_defaults_to_daily_targeted_with_weekly_full():
    settings = Settings()

    assert settings.storage_container_name == "dvm-history"
    assert settings.recommendation_enrichment_mode == "auto"
    assert settings.enable_experimental_endpoints is False
    assert settings.full_enrichment_weekday == 6
    assert settings.dashboard_data_source == "local"
    assert settings.dashboard_static_dir == ""
    assert settings.dashboard_cache_seconds == 30
    assert settings.dashboard_auth_enabled is False
    assert settings.dashboard_data_browser_enabled is False
    assert settings.dashboard_data_browser_role == ""
    assert settings.synthetic_device_count == 2500


def test_synthetic_device_count_can_be_configured(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SYNTHETIC_DEVICE_COUNT", "3200")

    settings = Settings.load(env_path=tmp_path / ".env")

    assert settings.synthetic_device_count == 3200


def test_experimental_endpoints_require_explicit_opt_in(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("ENABLE_EXPERIMENTAL_ENDPOINTS", "true")

    settings = Settings.load(env_path=tmp_path / ".env")

    assert settings.enable_experimental_endpoints is True


def test_dashboard_authentication_requires_explicit_opt_in(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("DASHBOARD_AUTH_ENABLED", "true")

    settings = Settings.load(env_path=tmp_path / ".env")

    assert settings.dashboard_auth_enabled is True


def test_dashboard_data_browser_requires_explicit_opt_in(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("DASHBOARD_DATA_BROWSER_ENABLED", "true")
    monkeypatch.setenv("DASHBOARD_DATA_BROWSER_ROLE", "Data.Evidence.Reader")

    settings = Settings.load(env_path=tmp_path / ".env")

    assert settings.dashboard_data_browser_enabled is True
    assert settings.dashboard_data_browser_role == "Data.Evidence.Reader"


def test_dashboard_data_source_rejects_unknown_value(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("DASHBOARD_DATA_SOURCE", "remote-ish")

    try:
        Settings.load(env_path=tmp_path / ".env")
    except ValueError as error:
        assert str(error) == "DASHBOARD_DATA_SOURCE must be local or azure"
    else:
        raise AssertionError("Expected invalid dashboard data source to fail")