import subprocess

import pytest

from vulnerability_view import github_workflow_cli


def test_parser_supports_publish_and_promote():
    args = github_workflow_cli.build_parser().parse_args([
        "publish-and-promote",
        "--message",
        "release message",
    ])

    assert args.command == "publish-and-promote"
    assert args.message == "release message"


def test_publish_and_promote_runs_tests_once_and_pushes_both_branches(monkeypatch, capsys):
    calls: list[tuple[str, ...]] = []
    test_runs = []

    monkeypatch.setattr(github_workflow_cli, "_require_repository", lambda: None)
    monkeypatch.setattr(github_workflow_cli, "_require_main", lambda: None)
    monkeypatch.setattr(github_workflow_cli, "_require_clean", lambda: None)
    monkeypatch.setattr(github_workflow_cli, "_fetch_main", lambda remote: None)
    monkeypatch.setattr(github_workflow_cli, "_is_ancestor", lambda ancestor, descendant: True)
    monkeypatch.setattr(github_workflow_cli, "_remote_branch_exists", lambda remote, branch: True)
    monkeypatch.setattr(github_workflow_cli, "_run_tests", lambda: test_runs.append(True))
    monkeypatch.setattr(github_workflow_cli, "_worktree_fingerprint", lambda: "unchanged")

    def fake_output(*args: str) -> str:
        if args == ("status", "--porcelain"):
            return ""
        if args == ("rev-parse", "HEAD"):
            return "new-commit"
        if args == ("rev-parse", "origin/main"):
            return "new-commit"
        if args == ("rev-parse", "origin/latest"):
            return "old-commit"
        if args == ("rev-parse", "--short", "origin/main"):
            return "new1234"
        raise AssertionError(f"Unexpected git output request: {args}")

    def fake_git(*args: str, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(github_workflow_cli, "_output", fake_output)
    monkeypatch.setattr(github_workflow_cli, "_git", fake_git)

    github_workflow_cli.publish_and_promote("origin", "")

    assert test_runs == [True]
    pushes = [call for call in calls if call and call[0] == "push"]
    assert pushes == [
        ("push", "origin", "HEAD:refs/heads/main"),
        ("push", "origin", "refs/remotes/origin/main:refs/heads/latest"),
    ]
    output = capsys.readouterr().out
    assert "tests will run once before either push" in output
    assert "Publishing tested commit to origin/main" in output
    assert "Development push finished" in output
    assert "tests are not repeated" in output
    assert output.index("Publishing tested commit") < output.index("Development push finished") < output.index("Promoting the same tested commit")


def test_validation_reports_test_progress_command_and_elapsed_time(monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_WORKFLOW_TEST_COMMAND", raising=False)
    calls = []

    def run(command, **kwargs):
        assert "[validation] Running:" in capsys.readouterr().out
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(github_workflow_cli.subprocess, "run", run)
    github_workflow_cli._run_tests()
    command, kwargs = calls[0]
    assert command == [github_workflow_cli.sys.executable, "-m", "pytest", "-vv", "--durations=10"]
    assert kwargs["env"]["PYTHONUNBUFFERED"] == "1"
    assert kwargs["env"]["DASHBOARD_AUTH_ENABLED"] == "false"
    assert kwargs["check"] is True
    assert "[validation] PASSED in" in capsys.readouterr().out


def test_validation_keeps_custom_command_unchanged(monkeypatch):
    monkeypatch.setenv("GITHUB_WORKFLOW_TEST_COMMAND", "custom-runner --focused")
    calls = []
    monkeypatch.setattr(github_workflow_cli.subprocess, "run", lambda command, **kwargs: calls.append(command))
    github_workflow_cli._run_tests()
    assert calls == [["custom-runner", "--focused"]]


def test_validation_reports_failure_and_preserves_exception(monkeypatch, capsys):
    error = subprocess.CalledProcessError(1, ["pytest"])

    def run(*args, **kwargs):
        raise error

    monkeypatch.setattr(github_workflow_cli.subprocess, "run", run)
    with pytest.raises(subprocess.CalledProcessError) as raised:
        github_workflow_cli._run_tests()
    assert raised.value is error
    output = capsys.readouterr().out
    assert "[validation] FAILED after" in output
    assert "PASSED" not in output


@pytest.mark.parametrize("operation", ["fetch", "push", "ls-remote", "add", "diff", "commit"])
def test_git_operations_print_flushed_start_before_execution(monkeypatch, capsys, operation):
    def run(*args, **kwargs):
        assert f"[git] Running: git {operation}" in capsys.readouterr().out
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(github_workflow_cli, "_run", run)
    assert github_workflow_cli._git(operation).returncode == 0
    assert "[git] Finished in" in capsys.readouterr().out


def test_git_failure_is_reported_without_success_message(monkeypatch, capsys):
    error = subprocess.CalledProcessError(1, ["git", "push"])

    def run(*args, **kwargs):
        raise error

    monkeypatch.setattr(github_workflow_cli, "_run", run)
    with pytest.raises(subprocess.CalledProcessError) as raised:
        github_workflow_cli._git("push", "origin", "main")
    assert raised.value is error
    output = capsys.readouterr().out
    assert "[git] Failed after" in output
    assert "[git] Finished" not in output


def test_release_stops_before_any_push_when_files_change_during_tests(monkeypatch):
    calls = []
    monkeypatch.setattr(github_workflow_cli, "_require_repository", lambda: None)
    monkeypatch.setattr(github_workflow_cli, "_require_main", lambda: None)
    monkeypatch.setattr(github_workflow_cli, "_fetch_main", lambda remote: None)
    monkeypatch.setattr(github_workflow_cli, "_is_ancestor", lambda *args: True)
    fingerprints = iter(["before-tests", "after-tests"])
    monkeypatch.setattr(github_workflow_cli, "_worktree_fingerprint", lambda: next(fingerprints))
    monkeypatch.setattr(github_workflow_cli, "_run_tests", lambda: None)
    monkeypatch.setattr(github_workflow_cli, "_output", lambda *args: "" if args == ("status", "--porcelain") else " M changed.py")
    monkeypatch.setattr(github_workflow_cli, "_git", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(RuntimeError, match="changed while validation"):
        github_workflow_cli.publish_and_promote("origin", "")
    assert calls == []


def test_worktree_fingerprint_detects_changes_to_already_dirty_and_untracked_files(monkeypatch, tmp_path):
    monkeypatch.setattr(github_workflow_cli, "ROOT", tmp_path)
    state = {"diff": "tracked diff", "head": "first-commit"}
    monkeypatch.setattr(
        github_workflow_cli, "_output",
        lambda *args: state["diff"] if args[0] == "diff" else state["head"] if args[0] == "rev-parse" else " M existing.py\n?? new.py",
    )
    monkeypatch.setattr(
        github_workflow_cli, "_git",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout="new.py\0"),
    )
    untracked = tmp_path / "new.py"
    untracked.write_text("first contents")
    first = github_workflow_cli._worktree_fingerprint()
    assert github_workflow_cli._worktree_fingerprint() == first
    untracked.write_text("second contents")
    second = github_workflow_cli._worktree_fingerprint()
    assert second != first
    state["diff"] = "modified tracked diff"
    third = github_workflow_cli._worktree_fingerprint()
    assert third != second
    state["head"] = "new-commit"
    assert github_workflow_cli._worktree_fingerprint() != third


def test_clean_worktree_failure_lists_files_and_recovery_step(monkeypatch):
    monkeypatch.setattr(github_workflow_cli, "_output", lambda *args: " M config.py\n?? new.py")
    with pytest.raises(RuntimeError) as raised:
        github_workflow_cli._require_clean()
    assert "config.py" in str(raised.value)
    assert "new.py" in str(raised.value)
    assert "option 3" in str(raised.value)
