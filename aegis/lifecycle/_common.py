"""Shared helpers for lifecycle-hook rules.

Kept dependency-light (events / policy only, plus optional identity) so every
lifecycle submodule can reuse confinement + attribution logic without importing
``aegis.rules`` (which would be circular).
"""
from __future__ import annotations

import os
from typing import Optional

from ..events import Event


def is_agent() -> bool:
    """True when this process is a SPAWNED agent (carries AEGIS_AGENT_NAME), as
    opposed to a human / orchestrator. Escapable guards never let an agent wave
    itself past; lifecycle governance keys off the same signal."""
    return bool(os.environ.get("AEGIS_AGENT_NAME"))


def within(path: str, root: str) -> bool:
    return path == root or path.startswith(root + os.sep)


def confine_root(policy) -> Optional[str]:
    """The project root the agent is confined to. Precedence: a VERIFIED token's
    ``project`` claim -> AEGIS_PROJECT -> policy.workspace.root -> AEGIS_WORKSPACE
    -> policy.project. None -> confinement is off. Mirrors ``rules._confine_root``
    (duplicated, not imported, to keep the dependency one-way)."""
    cfg = getattr(policy, "workspace", None) or {}
    try:
        from .. import identity
        claims = identity.current() or {}
    except Exception:
        claims = {}
    return (claims.get("project")
            or os.environ.get("AEGIS_PROJECT")
            or cfg.get("root")
            or os.environ.get("AEGIS_WORKSPACE")
            or getattr(policy, "project", None))


def confine_allow(policy) -> list:
    """Extra roots a confined agent may also write to (policy.workspace.allow)."""
    cfg = getattr(policy, "workspace", None) or {}
    return [os.path.abspath(os.path.expanduser(p)) for p in (cfg.get("allow") or [])]


def abspath(path: str, base: Optional[str]) -> str:
    base = base or os.getcwd()
    return os.path.abspath(os.path.join(base, os.path.expanduser(path)))


def flatten_strings(v, _depth: int = 0) -> list:
    """Every string/number leaf inside a (possibly nested) value, depth-capped.
    Mirrors ``rules._flatten_strings`` (duplicated, not imported, to keep the
    lifecycle -> rules dependency one-way — see module docstring). Used to scan
    arbitrary-shaped event payloads (MCP tool args, an Elicitation request's
    message/requestedSchema) without assuming a fixed set of key names, since
    that shape varies by MCP server/runtime with no fixed convention."""
    if _depth > 12:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return [str(v)]
    if isinstance(v, dict):
        out = []
        for x in v.values():
            out.extend(flatten_strings(x, _depth + 1))
        return out
    if isinstance(v, (list, tuple)):
        out = []
        for x in v:
            out.extend(flatten_strings(x, _depth + 1))
        return out
    return []
