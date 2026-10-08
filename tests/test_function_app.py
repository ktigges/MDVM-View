from pathlib import Path

import function_app


def test_run_dataprep_uses_temporary_writable_workspace(monkeypatch):
    original_directory = Path.cwd()
    observed: dict[str, Path] = {}

    def fake_main(arguments: list[str]) -> int:
        observed["work_root"] = Path.cwd()
        assert arguments == ["collect-live", "--skip-local-exports"]
        assert observed["work_root"].parent == Path("/tmp").resolve()
        assert (observed["work_root"] / "config/sla-policies.json").is_file()
        output = observed["work_root"] / "output/raw/live-test"
        output.mkdir(parents=True)
        (output / "page.json").write_text("{}")
        return 0

    monkeypatch.setattr(function_app, "main", fake_main)

    assert function_app._run_dataprep() == 0
    assert Path.cwd() == original_directory
    assert not observed["work_root"].exists()


def test_run_dataprep_restores_directory_after_failure(monkeypatch):
    original_directory = Path.cwd()

    def failing_main(arguments: list[str]) -> int:
        assert arguments == ["collect-live", "--skip-local-exports"]
        raise RuntimeError("collection failed")

    monkeypatch.setattr(function_app, "main", failing_main)

    try:
        function_app._run_dataprep()
    except RuntimeError as error:
        assert str(error) == "collection failed"
    else:
        raise AssertionError("Expected collection failure")

    assert Path.cwd() == original_directory
