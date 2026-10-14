import subprocess

from vulnerability_view import github_workflow_cli


def test_parser_supports_publish_and_promote():
    args = github_workflow_cli.build_parser().parse_args([
        "publish-and-promote",
        "--message",
        "release message",
        "--confirm",
        "RELEASE",
    ])

    assert args.command == "publish-and-promote"
    assert args.message == "release message"
    assert args.confirm == "RELEASE"


def test_publish_and_promote_runs_tests_once_and_pushes_both_branches(monkeypatch):
    calls: list[tuple[str, ...]] = []
    test_runs = []

    monkeypatch.setattr(github_workflow_cli, "_require_repository", lambda: None)
    monkeypatch.setattr(github_workflow_cli, "_require_main", lambda: None)
    monkeypatch.setattr(github_workflow_cli, "_require_clean", lambda: None)
    monkeypatch.setattr(github_workflow_cli, "_fetch_main", lambda remote: None)
    monkeypatch.setattr(github_workflow_cli, "_is_ancestor", lambda ancestor, descendant: True)
    monkeypatch.setattr(github_workflow_cli, "_remote_branch_exists", lambda remote, branch: True)
    monkeypatch.setattr(github_workflow_cli, "_run_tests", lambda: test_runs.append(True))

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

    github_workflow_cli.publish_and_promote("origin", "", "RELEASE")

    assert test_runs == [True]
    pushes = [call for call in calls if call and call[0] == "push"]
    assert pushes == [
        ("push", "origin", "HEAD:refs/heads/main"),
        ("push", "origin", "refs/remotes/origin/main:refs/heads/latest"),
    ]
