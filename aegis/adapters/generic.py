"""Generic JSON adapter (AEGI-7).

The universal fallback for any runtime that can invoke a command hook: it speaks
a normalized JSON contract instead of a runtime-specific one, so a new runtime
needs zero adapter code — just point its hook at ``aegis hook --runtime generic``.

Input (stdin JSON): ``{event, tool, args, identity, roles, session_id, cwd}``
Output (stdout JSON): ``{decision, rule, message}`` — exit code 2 = deny (block),
0 = allow / ask.
"""
from __future__ import annotations

import json
from typing import Tuple

from ..events import Event, HookEvent
from ..policy import Action, Decision

_VALID_EVENTS = {e.value for e in HookEvent}

RUNTIME = "generic"


def parse_event(payload: dict) -> Event:
    name = payload.get("event") or payload.get("hook_event_name") or "PreToolUse"
    if name not in _VALID_EVENTS:
        name = HookEvent.PRE_TOOL_USE.value
    return Event.make(
        name,
        tool=payload.get("tool"),
        args=payload.get("args") or {},
        identity=payload.get("identity"),
        roles=list(payload.get("roles") or []),
        session_id=payload.get("session_id"),
        cwd=payload.get("cwd"),
        agent=payload.get("agent"),
        agent_id=payload.get("agent_id"),
        agent_type=payload.get("agent_type"),
        worktree=payload.get("worktree"),
        matcher=payload.get("matcher"),
        raw=payload,
    )


def render_decision(event: Event, decision: Decision) -> Tuple[int, str, str]:
    out = json.dumps({
        "decision": decision.action.value,
        "rule": decision.rule,
        "message": decision.message,
    })
    code = 2 if decision.action == Action.DENY else 0
    return code, out + "\n", ""
