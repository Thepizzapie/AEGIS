"""Branch strand guard — don't create a new branch while current has unmerged work."""
import subprocess

import pytest

from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Policy

EMPTY = Policy()


def _shell(cmd, cwd=None):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash",
                      args={"command": cmd}, cwd=cwd)


def _init_repo(tmp_path, ahead=0):
    """Create a test git repo on main with `ahead` extra commits on a feature branch."""
    r = str(tmp_path / "repo")
    subprocess.run(["git", "init", r], capture_output=True, check=True)
    subprocess.run(["git", "-C", r, "checkout", "-b", "main"], capture_output=True)
    # initial commit so main exists
    (tmp_path / "repo" / "f.txt").write_text("init")
    subprocess.run(["git", "-C", r, "add", "."], capture_output=True)
    subprocess.run(["git", "-C", r, "commit", "-m", "init"], capture_output=True)
    if ahead > 0:
        subprocess.run(["git", "-C", r, "checkout", "-b", "feat"], capture_output=True)
        for i in range(ahead):
            (tmp_path / "repo" / f"g{i}.txt").write_text(f"change {i}")
            subprocess.run(["git", "-C", r, "add", "."], capture_output=True)
            subprocess.run(["git", "-C", r, "commit", "-m", f"feat {i}"],
                           capture_output=True)
    return r


class TestPatternMatching:
    """Pattern-level tests (no git needed — just regex matching)."""

    def test_checkout_b_matches(self):
        from aegis.patterns import NEW_BRANCH_RE
        assert NEW_BRANCH_RE.search("git checkout -b my-feature")

    def test_switch_c_matches(self):
        from aegis.patterns import NEW_BRANCH_RE
        assert NEW_BRANCH_RE.search("git switch -c my-feature")

    def test_plain_checkout_no_match(self):
        from aegis.patterns import NEW_BRANCH_RE
        assert not NEW_BRANCH_RE.search("git checkout main")

    def test_branch_list_no_match(self):
        from aegis.patterns import NEW_BRANCH_RE
        assert not NEW_BRANCH_RE.search("git branch")


class TestRuleIntegration:
    """Full rule tests with real git repos."""

    def test_blocked_when_ahead(self, tmp_path):
        repo = _init_repo(tmp_path, ahead=2)
        d = evaluate(_shell("git checkout -b new-feat", cwd=repo), EMPTY)
        assert d.blocked
        assert d.rule == "branch-strand"
        assert "2 commit(s)" in d.message

    def test_allowed_when_on_main(self, tmp_path):
        repo = _init_repo(tmp_path, ahead=0)
        d = evaluate(_shell("git checkout -b new-feat", cwd=repo), EMPTY)
        assert not d.blocked

    def test_escapable_with_override(self, tmp_path):
        repo = _init_repo(tmp_path, ahead=2)
        d = evaluate(_shell("git checkout -b new-feat  # aegis-allow", cwd=repo), EMPTY)
        assert not d.blocked

    def test_escapable_with_env(self, tmp_path, monkeypatch):
        repo = _init_repo(tmp_path, ahead=2)
        monkeypatch.setenv("AEGIS_ALLOW_STRAND", "1")
        d = evaluate(_shell("git checkout -b new-feat", cwd=repo), EMPTY)
        assert not d.blocked

    def test_agent_cannot_self_escape(self, tmp_path, monkeypatch):
        repo = _init_repo(tmp_path, ahead=2)
        monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
        d = evaluate(_shell("git checkout -b new-feat  # aegis-allow", cwd=repo), EMPTY)
        assert d.blocked

    def test_non_branch_command_ignored(self, tmp_path):
        repo = _init_repo(tmp_path, ahead=2)
        d = evaluate(_shell("git status", cwd=repo), EMPTY)
        assert not d.blocked

    def test_switch_c_blocked(self, tmp_path):
        repo = _init_repo(tmp_path, ahead=1)
        d = evaluate(_shell("git switch -c another", cwd=repo), EMPTY)
        assert d.blocked
