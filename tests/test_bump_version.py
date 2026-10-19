from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def make_workspace(tmp_path: Path) -> tuple[Path, Path, Path]:
    script = tmp_path / "bump-version.sh"
    tfvars = tmp_path / "infra/terraform/main.tfvars.json"
    config = tmp_path / "dashboard/config.js"
    shutil.copy2(ROOT / "bump-version.sh", script)
    tfvars.parent.mkdir(parents=True)
    config.parent.mkdir(parents=True)
    tfvars.write_text(json.dumps({
        "function_version": "2000.01.01.9",
        "dashboard_version": "2000.01.01.8",
    }, indent=2), encoding="utf-8")
    config.write_text(
        'window.VULNERABILITY_VIEW_CONFIG = {\n'
        '  version: "2000.01.01.8",\n'
        '  revision: "2000-01-01T00:00:00Z",\n'
        '};\n',
        encoding="utf-8",
    )
    (tmp_path / "function-version.json").write_text(json.dumps({
        "version": "2000.01.01.9",
        "revision": "2000-01-01T00:00:00Z",
    }), encoding="utf-8")
    tfvars.with_name("main.tfvars.example.json").write_text(tfvars.read_text(), encoding="utf-8")
    return script, tfvars, config


def run_bump(script: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(script), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )


def test_bump_version_requires_explicit_target(tmp_path: Path):
    script, _, _ = make_workspace(tmp_path)

    result = run_bump(script)

    assert result.returncode == 2
    assert "Usage: ./bump-version.sh <web|function> [--dry-run]" in result.stderr


def test_bump_version_updates_only_function_target(tmp_path: Path):
    script, tfvars, config = make_workspace(tmp_path)
    original_config = config.read_text(encoding="utf-8")

    result = run_bump(script, "function")

    values = json.loads(tfvars.read_text(encoding="utf-8"))
    today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    assert result.returncode == 0
    assert values["function_version"] == f"{today}.1"
    assert values["dashboard_version"] == "2000.01.01.8"
    assert config.read_text(encoding="utf-8") == original_config
    assert "UI revision:" not in result.stdout
    source = json.loads((tmp_path / "function-version.json").read_text())
    assert source["version"] == values["function_version"]
    assert source["revision"] != "2000-01-01T00:00:00Z"
    assert json.loads(tfvars.with_name("main.tfvars.example.json").read_text())["function_version"] == source["version"]


def test_bump_version_updates_only_web_target(tmp_path: Path):
    script, tfvars, config = make_workspace(tmp_path)
    original_function = (tmp_path / "function-version.json").read_text()

    result = run_bump(script, "web")

    values = json.loads(tfvars.read_text(encoding="utf-8"))
    config_text = config.read_text(encoding="utf-8")
    today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    assert result.returncode == 0
    assert values["function_version"] == "2000.01.01.9"
    assert values["dashboard_version"] == f"{today}.1"
    assert f'version: "{today}.1"' in config_text
    assert 'revision: "2000-01-01T00:00:00Z"' not in config_text
    assert "UI revision:" in result.stdout
    assert (tmp_path / "function-version.json").read_text() == original_function


def test_bump_version_dry_run_does_not_change_selected_target(tmp_path: Path):
    script, tfvars, config = make_workspace(tmp_path)
    original_tfvars = tfvars.read_text(encoding="utf-8")
    original_config = config.read_text(encoding="utf-8")

    result = run_bump(script, "web", "--dry-run")

    assert result.returncode == 0
    assert tfvars.read_text(encoding="utf-8") == original_tfvars
    assert config.read_text(encoding="utf-8") == original_config
    assert "Dry run only; no files changed." in result.stdout


def test_function_bump_uses_source_version_not_stale_terraform_value(tmp_path: Path):
    script, tfvars, _ = make_workspace(tmp_path)
    today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    source = tmp_path / "function-version.json"
    source.write_text(json.dumps({"version": f"{today}.7"}))

    result = run_bump(script, "function")

    assert result.returncode == 0
    assert json.loads(source.read_text())["version"] == f"{today}.8"
    assert json.loads(tfvars.read_text())["function_version"] == f"{today}.8"


def test_function_bump_does_not_require_customer_terraform_configuration(tmp_path: Path):
    script, tfvars, _ = make_workspace(tmp_path)
    tfvars.unlink()

    result = run_bump(script, "function")

    assert result.returncode == 0
    assert json.loads((tmp_path / "function-version.json").read_text())["version"].endswith(".1")
    assert not tfvars.exists()


def test_function_dry_run_preserves_source_and_terraform_files(tmp_path: Path):
    script, tfvars, _ = make_workspace(tmp_path)
    paths = [tmp_path / "function-version.json", tfvars, tfvars.with_name("main.tfvars.example.json")]
    original = {path: path.read_text() for path in paths}

    result = run_bump(script, "function", "--dry-run")

    assert result.returncode == 0
    assert all(path.read_text() == content for path, content in original.items())


def test_function_bump_fails_if_version_source_is_missing(tmp_path: Path):
    script, tfvars, _ = make_workspace(tmp_path)
    original = tfvars.read_text()
    (tmp_path / "function-version.json").unlink()

    result = run_bump(script, "function")

    assert result.returncode != 0
    assert "Missing Function version file" in result.stderr
    assert tfvars.read_text() == original
