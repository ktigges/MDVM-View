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


def test_bump_version_updates_only_web_target(tmp_path: Path):
    script, tfvars, config = make_workspace(tmp_path)

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


def test_bump_version_dry_run_does_not_change_selected_target(tmp_path: Path):
    script, tfvars, config = make_workspace(tmp_path)
    original_tfvars = tfvars.read_text(encoding="utf-8")
    original_config = config.read_text(encoding="utf-8")

    result = run_bump(script, "web", "--dry-run")

    assert result.returncode == 0
    assert tfvars.read_text(encoding="utf-8") == original_tfvars
    assert config.read_text(encoding="utf-8") == original_config
    assert "Dry run only; no files changed." in result.stdout
