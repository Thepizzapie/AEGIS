"""AEGI-5: git/CI enforcement surface — same policy engine at the change boundary."""
from aegis.policy import Policy, Rule, Action
from aegis import gitsurface, cli

GIT_POLICY = Policy(rules=[
    Rule(name="no-commit-env", action=Action.DENY, actions=["git"],
         argument_patterns={"operation": "commit", "file": "*.env*"}, message="no secrets"),
    Rule(name="no-push-main", action=Action.DENY, actions=["git"],
         argument_patterns={"operation": "push", "branch": "main"}, message="no push main"),
])


def test_check_commit_blocks_secret_files():
    denied = gitsurface.check_commit(GIT_POLICY, ["app.py", ".env", "src/.env.local"], branch="feat")
    files = [f for f, _ in denied]
    assert ".env" in files and "src/.env.local" in files
    assert "app.py" not in files
    assert denied[0][1].message == "no secrets"


def test_check_push_blocks_main_only():
    assert gitsurface.check_push(GIT_POLICY, branch="main").blocked
    assert not gitsurface.check_push(GIT_POLICY, branch="feat/x").blocked


def test_install_git_hooks_non_clobber_and_idempotent(tmp_path):
    hooks = tmp_path / ".git" / "hooks"
    hooks.mkdir(parents=True)
    pre_commit = hooks / "pre-commit"
    pre_commit.write_text("#!/bin/sh\necho existing-hook\n", encoding="utf-8")

    n = cli.install_git_hooks(tmp_path)
    content = pre_commit.read_text()
    assert "echo existing-hook" in content              # not clobbered
    assert "git-hook commit" in content           # ours appended
    assert "git-hook push" in (hooks / "pre-push").read_text()
    assert n == 2

    cli.install_git_hooks(tmp_path)                      # idempotent
    assert pre_commit.read_text().count("git-hook commit") == 1
