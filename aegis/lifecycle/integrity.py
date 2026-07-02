"""Config / environment-integrity lifecycle rules (AEGI: hook-surface coverage).

The crown-jewel guarantee: *a spawned agent must not be able to disable Aegis or
escape its workspace mid-session.* These rules gate the lifecycle events that let
an agent rewrite the guard's own config, wander out of its confinement root, or
quietly mutate secrets:

- ``ConfigChange``  — settings.json / policy / skills changed (BLOCKABLE).
- ``CwdChanged``    — the working directory moved (NOT blockable: surfaced for
                      accountability, can't physically stop the move).
- ``FileChanged``   — a watched ``.env``/``.envrc`` was touched (observational).

``Setup`` and ``InstructionsLoaded`` carry nothing to enforce — the caller audits
them automatically — so this module deliberately ships NO rule for them.

Submodules must NOT import ``aegis.rules`` (circular); shared confinement /
attribution helpers live in ``aegis.lifecycle._common``. Every rule is fail-open:
an internal error returns None, never raises.
"""
from __future__ import annotations

import os
from typing import Optional

from .. import patterns
from ..events import Event, HookEvent
from ..policy import Action, Decision
from ._common import abspath, confine_allow, confine_root, is_agent, within

# Config-type matchers (ev.matcher) an agent must never be allowed to rewrite:
# the local + policy settings ARE the enforcement layer, so editing them mid-
# session is "neutering the guard". User/project/skills matchers are not auto-
# denied here (a path check below still catches Aegis's own files).
_PROTECTED_MATCHERS = frozenset({"policy_settings", "local_settings"})


def _changed_paths(ev: Event) -> list:
    """Every candidate path a ConfigChange might carry, across adapter shapes —
    typed args plus the raw payload (path / file_path / paths / changed / files).
    Fail-safe: anything non-string is coerced to str."""
    out = []
    sources = []
    sources.append(ev.args or {})
    sources.append(ev.raw or {})
    for src in sources:
        for key in ("path", "file_path", "config_path", "newpath"):
            v = src.get(key)
            if v:
                out.append(str(v))
        for key in ("paths", "changed", "files", "changed_paths"):
            v = src.get(key)
            if isinstance(v, (list, tuple)):
                out.extend(str(x) for x in v if x)
    return out


def rule_config_change_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block a SPAWNED agent from tampering with Aegis's own policy/settings
    mid-session — the "can't neuter the guard" guarantee. A human/orchestrator
    (no AEGIS_AGENT_NAME) may legitimately reconfigure, so abstain for them.

    DENY when the config type (``ev.matcher``) is ``policy_settings`` or
    ``local_settings``, OR when any changed path is one of Aegis's enforcement /
    config / engine-source files (ENFORCEMENT_PATH_RE / AEGIS_SOURCE_RE /
    CONFIG_DIR_RE). BLOCKABLE, so this actually stops the change."""
    try:
        if ev.event != HookEvent.CONFIG_CHANGE:
            return None
        if not is_agent():
            return None  # human / orchestrator may change config
        matcher = (ev.matcher or "").strip().lower()
        if matcher in _PROTECTED_MATCHERS:
            return Decision(Action.DENY, "config-change-protect",
                            f"Changing Aegis '{matcher}' is blocked — a spawned agent may "
                            "not rewrite the policy/settings that enforce it (neutering the "
                            "guard mid-session).")
        for p in _changed_paths(ev):
            if (patterns.ENFORCEMENT_PATH_RE.search(p)
                    or patterns.AEGIS_SOURCE_RE.search(p)
                    or patterns.CONFIG_DIR_RE.search(p)):
                return Decision(Action.DENY, "config-change-protect",
                                f"Changing Aegis's own config/policy/source is blocked: {p}. "
                                "A spawned agent cannot disable its own guard.")
        return None
    except Exception:
        return None  # fail-open


def _new_cwd(ev: Event) -> Optional[str]:
    """The destination directory of a CwdChanged event, across adapter shapes:
    ev.cwd, or raw ``newcwd`` / ``new_cwd`` / ``cwd`` / ``to``."""
    if ev.cwd:
        return ev.cwd
    raw = ev.raw or {}
    for key in ("newcwd", "new_cwd", "cwd", "to", "newpath"):
        v = raw.get(key)
        if v:
            return str(v)
    return None


def rule_cwd_confine(ev: Event, policy=None) -> Optional[Decision]:
    """Surface (for accountability) an agent stepping its working directory
    OUTSIDE its confinement root + allow list. CwdChanged is NOT blockable, so
    the DENY is recorded/visible but does not physically stop Claude Code — the
    point is an audit trail of an attempted workspace escape. Off when no
    confinement root is configured (confine_root is None)."""
    try:
        if ev.event != HookEvent.CWD_CHANGED:
            return None
        root = confine_root(policy)
        if not root:
            return None  # confinement off
        target = _new_cwd(ev)
        if not target:
            return None
        roots = [abspath(root, None)] + confine_allow(policy)
        ap = abspath(target, None)
        if any(within(ap, r) for r in roots):
            return None
        return Decision(Action.DENY, "cwd-confine",
                        f"Working directory moved outside the agent's confinement root: "
                        f"{ap} is not under {roots[0]}. Recorded as an attempted workspace "
                        "escape (CwdChanged is observational — surfaced, not blocked).")
    except Exception:
        return None  # fail-open


def rule_env_file_changed(ev: Event, policy=None) -> Optional[Decision]:
    """A watched secrets file (``.env`` / ``.envrc``) changed. Observational by
    default — the caller's audit records every FileChanged, which is exactly the
    trail you want for secrets touches — so we abstain (return None) unless the
    payload shows a clear tamper signal: the SPAWNED agent ITSELF wrote the file
    (raw ``actor``/``source``/``by`` == 'agent', or an ``agent_id`` is attached).
    Then surface an ASK so an agent silently editing secrets is at least flagged.
    NOT blockable: an ASK/DENY here is visibility, not enforcement. Conservative
    on purpose — an external/human edit stays a plain audit record."""
    try:
        if ev.event != HookEvent.FILE_CHANGED:
            return None
        if not is_agent():
            return None  # external / human change -> let the audit record it
        raw = ev.raw or {}
        actor = str(raw.get("actor") or raw.get("source") or raw.get("by") or "").lower()
        agent_self = actor in ("agent", "assistant", "model") or bool(ev.agent_id)
        if not agent_self:
            return None  # no clear tamper signal -> audit-only
        path = ""
        for p in _changed_paths(ev):
            path = p
            break
        return Decision(Action.ASK, "env-file-changed",
                        f"The agent changed a secrets file ({path or '.env/.envrc'}). "
                        "Flagged for review — agent edits to environment secrets warrant an "
                        "audit trail and confirmation.")
    except Exception:
        return None  # fail-open


# Priority order: config tamper (the hard block) first, then confinement escape,
# then the conservative secrets-file flag. Setup / InstructionsLoaded are audit-
# only and intentionally absent (no rule that can only ever return None).
RULES = (
    rule_config_change_protect,
    rule_cwd_confine,
    rule_env_file_changed,
)
