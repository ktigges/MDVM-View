"""Last modified: 2026-10-08.
Purpose: Verify cross-platform operations parsing, versioning, packaging, and safety behavior.
"""

import json
import subprocess
from pathlib import Path
from zipfile import ZipFile

from vulnerability_view import operations_cli


def test_parser_exposes_identical_cross_platform_commands():
    assert operations_cli.build_parser().parse_args(["deploy", "function"]).stage == "function"
    assert operations_cli.build_parser().parse_args(["show", "foundation"]).stage == "foundation"
    assert operations_cli.build_parser().parse_args(["output", "function_app_name"]).name == "function_app_name"
    assert operations_cli.build_parser().parse_args(["check-runs", "--limit", "5", "--progress"]).progress is True
    assert operations_cli.build_parser().parse_args(["invoke", "function", "--confirm"]).confirm is True


def test_require_prefers_repository_local_terraform_exe(monkeypatch, tmp_path: Path):
    terraform = tmp_path / "terraform.exe"
    terraform.write_bytes(b"local terraform")
    monkeypatch.setattr(operations_cli, "ROOT", tmp_path)
    monkeypatch.setattr(
        operations_cli.shutil,
        "which",
        lambda command: (_ for _ in ()).throw(AssertionError(f"PATH lookup should not run for {command}")),
    )

    assert operations_cli._require("terraform") == str(terraform)


def test_function_version_prefers_override_then_values(monkeypatch):
    monkeypatch.setenv("FUNCTION_VERSION", "release/one")
    assert operations_cli._function_version({"function_version": "values-version"}) == "release-one"
    monkeypatch.delenv("FUNCTION_VERSION")
    assert operations_cli._function_version({"function_version": "2026.10.08.1"}) == "2026.10.08.1"


def test_zip_tree_excludes_generated_dashboard_data(monkeypatch, tmp_path: Path):
    root = tmp_path / "repo"
    dashboard = root / "dashboard"
    dashboard.mkdir(parents=True)
    (dashboard / "index.html").write_text("dashboard")
    (dashboard / "data").mkdir()
    (dashboard / "data/current.json").write_text(json.dumps({"secret": "not-packaged"}))
    destination = root / "webapp.zip"
    monkeypatch.setattr(operations_cli, "ROOT", root)

    operations_cli._zip_tree(destination, [dashboard], {"dashboard/data"})

    with ZipFile(destination) as archive:
        assert archive.namelist() == ["dashboard/index.html"]


def test_web_package_stamps_version_revision_and_cache_keys(tmp_path: Path):
    package = tmp_path / "webapp.zip"
    with ZipFile(package, "w") as archive:
        archive.writestr("dashboard/config.js", 'version: "old", revision: "old"')
        archive.writestr(
            "dashboard/index.html",
            '<link href="styles.css?v=old"><script src="config.js?v=old"></script><script src="app.js?v=old"></script>',
        )

    operations_cli._stamp_web_package(package, "2026.10.08.2", "2026-10-08T15:00:00Z")

    with ZipFile(package) as archive:
        configuration = archive.read("dashboard/config.js").decode()
        html = archive.read("dashboard/index.html").decode()
    assert 'version: "2026.10.08.2"' in configuration
    assert 'revision: "2026-10-08T15:00:00Z"' in configuration
    assert html.count("?v=20261008150000") == 3


def test_invoke_requires_platform_neutral_confirmation(monkeypatch):
    monkeypatch.delenv("CONFIRM_LIVE_COLLECTION", raising=False)

    try:
        operations_cli.invoke()
    except RuntimeError as error:
        assert "--confirm" in str(error)
    else:
        raise AssertionError("invoke should require explicit confirmation")


def test_verify_function_allows_greenfield_before_first_run(monkeypatch, capsys):
    outputs = {
        "resource_group_name": "rg-test",
        "function_app_name": "func-test",
        "history_storage_account_name": "historytest",
        "history_container_name": "dvm-history",
        "current_container_name": "dvm-current",
    }
    monkeypatch.setattr(operations_cli, "_tf_output", lambda name: outputs[name])
    monkeypatch.setattr(
        operations_cli,
        "_az",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout="2026.10.08.1\n"),
    )
    monkeypatch.setattr(operations_cli, "_az_json", lambda *args: {"exists": False})
    monkeypatch.setattr(
        operations_cli,
        "_run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("status should not run without a manifest")),
    )

    operations_cli.verify("function")

    assert "No current manifest is published yet" in capsys.readouterr().out
