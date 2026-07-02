"""Lifecycle-hook rules (AEGI: full hook-surface coverage).

The original engine wired only PreToolUse / PostToolUse / SessionStart / Stop /
UserPromptSubmit. Claude Code emits ~26 lifecycle events; this package adds the
enforcement + accountability behavior for the rest, grouped by concern:

- ``integrity``    — ConfigChange / FileChanged / CwdChanged / Setup / InstructionsLoaded
- ``team``         — SubagentStart / SubagentStop / TaskCreated / TaskCompleted / TeammateIdle
- ``session``      — SessionEnd / PreCompact / PostCompact / StopFailure / Notification
- ``interaction``  — PostToolUseFailure / PermissionRequest / Elicitation / ElicitationResult
- ``worktree``     — WorktreeCreate / WorktreeRemove

Each submodule exposes ``RULES`` (a tuple of ``(Event, Policy) -> Decision | None``
functions). ``LIFECYCLE_RULES`` flattens them for the engine to fold into its
built-in rule chain. Submodules must NOT import ``aegis.rules`` (that module
imports this one — keep the dependency one-way).
"""
from __future__ import annotations


_SUBMODULES = ("integrity", "team", "session", "interaction", "worktree")


def lifecycle_rules() -> tuple:
    """Flatten every submodule's ``RULES`` tuple, in a stable order, for the engine
    to fold into its built-in chain. Computed on demand (not at package import) so
    importing one submodule never forces its siblings to exist."""
    import importlib

    out = []
    for name in _SUBMODULES:
        mod = importlib.import_module(f"{__name__}.{name}")
        out.extend(getattr(mod, "RULES", ()))
    return tuple(out)
