"""git / CI enforcement surface (AEGI-5).

A second hook surface — still hooks, not MCP — that runs the SAME policy engine
at the change boundary (git pre-commit / pre-push) and in CI, so coverage does
not depend on hooking the agent runtime. Works for any agent or human.

Git operations are modelled as ``action: git`` events with ``operation``
(commit|push), ``file``, and ``branch`` arguments, so the existing rule schema
(``argument_patterns``) targets them with no new concepts.
"""
from __future__ import annotations

import os
import subprocess

from .engine import safe_evaluate
from .events import ActionClass, Event, HookEvent
from .policy import Decision, Policy

_CREATE_NO_WINDOW = 0x08000000  # Windows: don't flash a console


def _git(repo, *args) -> str:
    try:
        flags = _CREATE_NO_WINDOW if os.name == "nt" else 0
        out = subprocess.run(["git", "-C", str(repo), *args],
                             capture_output=True, text=True,
                             creationflags=flags)
        return out.stdout.strip()
    except Exception:
        return ""


def current_branch(repo) -> str:
    return _git(repo, "rev-parse", "--abbrev-ref", "HEAD")


def staged_files(repo) -> list:
    out = _git(repo, "diff", "--cached", "--name-only")
    return [line for line in out.splitlines() if line.strip()]


def changed_files(repo, base) -> list:
    out = _git(repo, "diff", "--name-only", f"{base}...HEAD")
    return [line for line in out.splitlines() if line.strip()]


def git_event(operation, file="", branch="", **kw) -> Event:
    return Event.make(HookEvent.PRE_TOOL_USE, tool="git", action=ActionClass.GIT,
                      args={"operation": operation, "file": file, "branch": branch}, **kw)


def check_commit(policy: Policy, files, branch="") -> list:
    """Return ``[(file, Decision)]`` for each file a commit would violate."""
    denied = []
    for f in files:
        d = safe_evaluate(git_event("commit", file=f, branch=branch), policy)
        if d.blocked:
            denied.append((f, d))
    return denied


def check_push(policy: Policy, branch="") -> Decision:
    return safe_evaluate(git_event("push", branch=branch), policy)
