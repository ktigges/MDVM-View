import subprocess

import pytest

from vulnerability_view import github_workflow_cli


@pytest.mark.parametrize("name", [
    "infra/terraform/main.tfvars.example.json:sec.endpointdlp",
    "infra/terraform/main.tfvars.json:sec.endpointdlp",
    "infra/terraform/main.tfvars.json:Zone.Identifier",
])
def test_publish_ignores_windows_alternate_stream_metadata(monkeypatch, tmp_path, name):
    (tmp_path / ".gitignore").write_text((github_workflow_cli.ROOT / ".gitignore").read_text())
    monkeypatch.setattr(github_workflow_cli, "ROOT", tmp_path)
    github_workflow_cli._git("init", "--quiet")

    assert github_workflow_cli._output("check-ignore", "--no-index", "--", name) == name


def test_tracked_paths_are_free_of_windows_invalid_stream_names():
    paths = github_workflow_cli._output("ls-files", "-z").split("\0")

    assert not [name for name in paths if ":" in name]


def test_publish_staging_excludes_generated_test_workspace(monkeypatch, tmp_path):
    ignore_rules = (github_workflow_cli.ROOT / ".gitignore").read_text()
    (tmp_path / ".gitignore").write_text(ignore_rules)
    cache = tmp_path / ".test-work" / "query-engine" / "customer-cache" / "history.sqlite3"
    cache.parent.mkdir(parents=True)
    cache.write_bytes(b"generated local database")
    (tmp_path / "release.py").write_text("VERSION = 'test'\n")
    monkeypatch.setattr(github_workflow_cli, "ROOT", tmp_path)
    github_workflow_cli._git("init", "--quiet")

    github_workflow_cli._git("add", "-A")

    assert set(github_workflow_cli._output("ls-files", "-z").split("\0")) == {
        ".gitignore", "release.py", "",
    }
    assert cache.read_bytes() == b"generated local database"


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


def _patch(monkeypatch, *, branch="refactor/work", status="", head="abc", remote_head="abc", main="m1",
           remote_main="m1", ancestor=True, remote_exists=True, tests_fail=False):
    calls = []
    answers = {
        ("branch", "--show-current"): branch,
        ("status", "--porcelain"): status,
        ("status", "--short"): status,
        ("rev-parse", "HEAD"): head,
        ("rev-parse", f"origin/{branch}"): remote_head,
        ("rev-parse", "main"): main,
        ("rev-parse", "origin/main"): remote_main,
        ("rev-parse", "--short", "HEAD"): "abc1234",
    }

    def fake_git(*args, capture=False, check=True):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    def fake_run_tests():
        if tests_fail:
            raise subprocess.CalledProcessError(1, ["pytest"])

    monkeypatch.setattr(github_workflow_cli, "_output", lambda *args: answers.get(args, ""))
    monkeypatch.setattr(github_workflow_cli, "_git", fake_git)
    monkeypatch.setattr(github_workflow_cli, "_require_repository", lambda: None)
    monkeypatch.setattr(github_workflow_cli, "_require_clean", lambda: None)
    monkeypatch.setattr(github_workflow_cli, "_remote_branch_exists", lambda remote, name: remote_exists)
    monkeypatch.setattr(github_workflow_cli, "_is_ancestor", lambda ancestor_ref, descendant: ancestor)
    monkeypatch.setattr(github_workflow_cli, "_worktree_fingerprint", lambda: "same")
    monkeypatch.setattr(github_workflow_cli, "_run_tests", fake_run_tests)
    return calls


def _pushes(calls):
    return [call for call in calls if call and call[0] == "push"]


@pytest.mark.parametrize("branch", ["main", "latest", "archive/pre-sla-simplification", ""])
def test_work_branch_guard_refuses_main_latest_archive_and_detached(monkeypatch, branch):
    _patch(monkeypatch, branch=branch)
    with pytest.raises(RuntimeError):
        github_workflow_cli._require_work_branch()


def test_work_branch_guard_returns_work_branch(monkeypatch):
    _patch(monkeypatch, branch="refactor/sla-simplification")
    assert github_workflow_cli._require_work_branch() == "refactor/sla-simplification"


def test_main_only_commands_point_work_branches_to_new_options(monkeypatch):
    _patch(monkeypatch, branch="refactor/sla-simplification")
    with pytest.raises(RuntimeError, match="option 5"):
        github_workflow_cli._require_main()


def test_publish_branch_pushes_only_the_work_branch(monkeypatch):
    calls = _patch(monkeypatch, status=" M file.py")
    github_workflow_cli.publish_branch("origin", "step 1", "PUSH", False)
    assert _pushes(calls) == [("push", "--set-upstream", "origin", "HEAD:refs/heads/refactor/work")]
    assert ("commit", "-m", "step 1") in calls
    assert not any("refs/heads/main" in arg or "refs/heads/latest" in arg for call in calls for arg in call)


def test_publish_branch_requires_push_confirmation(monkeypatch):
    calls = _patch(monkeypatch)
    with pytest.raises(RuntimeError, match="PUSH confirmation"):
        github_workflow_cli.publish_branch("origin", "step 1", "", False)
    assert _pushes(calls) == []


def test_publish_branch_stops_on_failing_tests_by_default(monkeypatch):
    calls = _patch(monkeypatch, tests_fail=True)
    with pytest.raises(subprocess.CalledProcessError):
        github_workflow_cli.publish_branch("origin", "step 1", "PUSH", False)
    assert _pushes(calls) == []


def test_publish_branch_can_explicitly_push_with_failing_tests(monkeypatch, capsys):
    calls = _patch(monkeypatch, tests_fail=True)
    github_workflow_cli.publish_branch("origin", "step 1", "PUSH", True)
    assert _pushes(calls) == [("push", "--set-upstream", "origin", "HEAD:refs/heads/refactor/work")]
    assert "Tests FAILED" in capsys.readouterr().out


def test_publish_branch_refuses_diverged_remote(monkeypatch):
    calls = _patch(monkeypatch, ancestor=False)
    with pytest.raises(RuntimeError, match="behind or diverged"):
        github_workflow_cli.publish_branch("origin", "step 1", "PUSH", False)
    assert _pushes(calls) == []


def test_merge_into_main_fast_forwards_without_pushing(monkeypatch):
    calls = _patch(monkeypatch)
    github_workflow_cli.merge_into_main("origin", "MERGE")
    assert ("switch", "main") in calls
    assert ("merge", "--ff-only", "refactor/work") in calls
    assert _pushes(calls) == []


def test_merge_into_main_requires_pushed_branch(monkeypatch):
    calls = _patch(monkeypatch, head="abc", remote_head="old")
    with pytest.raises(RuntimeError, match="Push refactor/work first"):
        github_workflow_cli.merge_into_main("origin", "MERGE")
    assert ("switch", "main") not in calls


def test_merge_into_main_refuses_when_main_moved(monkeypatch):
    calls = _patch(monkeypatch, ancestor=False)
    with pytest.raises(RuntimeError, match="has commits that"):
        github_workflow_cli.merge_into_main("origin", "MERGE")
    assert ("switch", "main") not in calls


def test_merge_into_main_requires_merge_confirmation(monkeypatch):
    calls = _patch(monkeypatch)
    with pytest.raises(RuntimeError, match="MERGE confirmation"):
        github_workflow_cli.merge_into_main("origin", "")
    assert ("switch", "main") not in calls
