"""Git-worktree confinement + accountability.

Covers the worktree lifecycle events: WorktreeCreate / WorktreeRemove.

One enforcing rule lives here:

- ``rule_worktree_confine`` (WorktreeCreate, BLOCKABLE) — extends workspace
  confinement to the worktree surface. A git worktree is a NEW working directory;
  an agent confined to a project root could `git worktree add ../escape` and edit
  files outside its confinement. When a confinement root is set, the new
  worktree path must resolve inside the root (or a workspace.allow root), else
  DENY. Mirrors ``rules.rule_workspace_confine`` for the worktree path.

Intentionally OMITTED (audit-only — no enforcing rule):

- WorktreeRemove: observational accountability, handled by the audit layer (the
  caller records it automatically). WorktreeRemove is NOT in BLOCKABLE, so a
  Decision could not enforce anything; per the project contract we do NOT
  register always-None rules, so we omit a rule for it entirely.
"""
from __future__ import annotations

from typing import Optional

from ..events import Event, HookEvent
from ..policy import Action, Decision
from ._common import abspath, confine_allow, confine_root, within


def _worktree_path(ev: Event) -> Optional[str]:
    """The path of the worktree being created. Prefer the normalized
    ``ev.worktree``; fall back to common worktree fields on the raw payload."""
    if ev.worktree:
        return ev.worktree
    raw = ev.raw or {}
    for key in ("worktree", "worktree_path", "path", "target"):
        val = raw.get(key)
        if val:
            return str(val)
    return None


def rule_worktree_confine(ev: Event, policy=None) -> Optional[Decision]:
    """Hard-block creating a git worktree outside the agent's project root. A
    worktree is a new working directory — an agent confined to a project could
    `git worktree add ../escape` to edit files elsewhere, so confinement must
    cover this surface too. When confine_root(policy) is set, resolve the
    worktree path against ev.cwd and DENY unless it is within the root or a
    confine_allow(policy) root. Off (None) when confinement is off or no
    worktree path is present. WorktreeCreate is blockable, so this DENY holds.
    Fail-open: any error -> None."""
    try:
        if ev.event != HookEvent.WORKTREE_CREATE:
            return None
        root = confine_root(policy)
        if not root:
            return None
        target = _worktree_path(ev)
        if not target:
            return None
        import os
        ap = abspath(target, ev.cwd)
        roots = [os.path.abspath(os.path.expanduser(root))] + confine_allow(policy)
        if any(within(ap, r) for r in roots):
            return None
        return Decision(Action.DENY, "worktree-confine",
                        f"Out-of-project worktree blocked: {ap} is outside the agent's "
                        f"project root {roots[0]}. A worktree is a new working directory; "
                        "the identity is confined to its project — widen it with "
                        "workspace.allow or rebind the identity.")
    except Exception:
        return None


RULES = (rule_worktree_confine,)
