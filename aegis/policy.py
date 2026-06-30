"""Policy model, decision type, and rule matching (AEGI-1).

AEGI-1 defines the rule/decision shapes and the matching the engine needs.
AEGI-3 adds the YAML authoring / loader / ``aegis validate`` layer on top.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .events import Event


class Action(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


def _as_values(items) -> list:
    return [it.value if isinstance(it, Enum) else str(it) for it in items]


def _any_glob(globs, value: str) -> bool:
    return any(fnmatch.fnmatch(value, g) for g in globs)


@dataclass
class Rule:
    """A single policy rule. An empty selector list means "matches any". A rule
    matches an event only when *all* of its non-empty selectors match."""

    name: str
    action: Action = Action.DENY
    events: list = field(default_factory=list)             # HookEvent values; [] = any
    tools: list = field(default_factory=list)              # globs on tool name; [] = any
    actions: list = field(default_factory=list)            # ActionClass values; [] = any
    roles: list = field(default_factory=list)              # caller roles; [] = any
    argument_patterns: dict = field(default_factory=dict)  # arg name -> glob (or list of globs)
    regex: dict = field(default_factory=dict)              # arg name -> regex (re.search)
    message: Optional[str] = None
    priority: int = 0
    description: Optional[str] = None

    def matches(self, ev: Event) -> bool:
        if self.events and ev.event.value not in _as_values(self.events):
            return False
        if self.actions and ev.action.value not in _as_values(self.actions):
            return False
        if self.tools and not _any_glob(self.tools, ev.tool or ""):
            return False
        if self.roles and not (set(self.roles) & set(ev.roles or [])):
            return False
        for key, pat in (self.argument_patterns or {}).items():
            val = ev.args.get(key)
            if val is None:
                return False
            # a pattern may be a single glob OR a list of globs (match if ANY) —
            # so one rule can cover a dangerous action across shells/phrasings
            # (rm -rf, Remove-Item -Recurse -Force, rmdir /s, ...).
            pats = pat if isinstance(pat, (list, tuple)) else [pat]
            if not any(fnmatch.fnmatch(str(val), str(p)) for p in pats):
                return False
        for key, rx in (self.regex or {}).items():
            val = ev.args.get(key)
            if val is None or not re.search(str(rx), str(val), re.IGNORECASE):
                return False
        return True


@dataclass
class Decision:
    action: Action
    rule: Optional[str] = None
    message: Optional[str] = None

    @property
    def blocked(self) -> bool:
        return self.action == Action.DENY


@dataclass
class Policy:
    rules: list = field(default_factory=list)
    default_action: Action = Action.ALLOW
    # Fail-safe: if evaluation itself errors, a broken hook must not brick the
    # agent. Default ALLOW (fail-open); set DENY for fail-closed enforcement.
    on_error: Action = Action.ALLOW
    # Network egress governance: {default: allow|deny, allow: [host globs], deny: [...]}
    egress: dict = field(default_factory=dict)
    # Custom guard plugin module paths (loaded via aegis.plugins)
    plugins: list = field(default_factory=list)
    # Workspace confinement: {root: <path>, allow: [<path>, ...]} (opt-in)
    workspace: dict = field(default_factory=dict)
    # Project root the agent identity is bound to. When set, file mutations
    # outside it are hard-blocked (out-of-project edits). .aegis default; a
    # token `project` claim or AEGIS_PROJECT take precedence at the hook.
    project: Optional[str] = None
    # Default agent label when no AEGIS_AGENT_NAME is set -> zero-config
    # attribution for a repo's agents.
    agent_label: Optional[str] = None
    # Forced install review: {mode: off|monitor|ask, deep: bool,
    # require_pinned: bool, allow: [regex on command]}. Empty -> defaults
    # (mode=ask) apply. See rules.rule_install_review.
    install_review: dict = field(default_factory=dict)
