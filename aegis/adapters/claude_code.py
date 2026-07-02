"""Claude Code hook adapter (AEGI-2).

Translates Claude Code hook payloads into the runtime-agnostic :class:`Event`,
and renders an Aegis :class:`Decision` into what Claude Code expects:

- **deny** on a blockable event -> exit code 2 + reason on stderr. Claude Code
  blocks the action and feeds the stderr text back to the model as the reason.
- **ask** on PreToolUse -> ``permissionDecision: ask`` JSON on stdout, exit 0.
- **allow** (or a deny on a non-blockable event) -> exit 0.
"""
from __future__ import annotations

import json
from typing import Tuple

from ..events import BLOCKABLE, Event, HookEvent
from ..policy import Action, Decision

# Events where exit code 2 meaningfully blocks and stderr is fed to the model.
# Sourced from the central taxonomy so adapter + engine never disagree.
_BLOCKABLE = BLOCKABLE

# Default agent label when the spawner sets no explicit identity.
RUNTIME = "claude-code"

# Per-event payload key that carries the native "matcher" value (config type,
# notification type, compaction type, termination reason, error type). Captured
# into Event.matcher so lifecycle rules can target it without re-reading raw.
_MATCHER_KEYS = (
    "matcher", "trigger", "source", "config_type", "notification_type",
    "compact_type", "reason", "error_type", "permission_mode",
)


def parse_event(payload: dict) -> Event:
    name = payload.get("hook_event_name") or payload.get("hookEventName")
    tool = payload.get("tool_name")
    raw_args = payload.get("tool_input")
    if isinstance(raw_args, dict):
        args = raw_args
    elif raw_args is None:
        args = {}
    else:
        args = {"value": raw_args}
    matcher = next((str(payload[k]) for k in _MATCHER_KEYS if payload.get(k)), None)
    return Event.make(
        name,
        tool=tool,
        args=args,
        session_id=payload.get("session_id"),
        cwd=payload.get("cwd"),
        agent=payload.get("agent") or payload.get("agent_name"),
        agent_id=payload.get("agent_id"),
        agent_type=payload.get("agent_type"),
        worktree=(payload.get("worktree") or payload.get("worktree_path")),
        matcher=matcher,
        raw=payload,
    )


def render_decision(event: Event, decision: Decision) -> Tuple[int, str, str]:
    """Return ``(exit_code, stdout, stderr)`` for Claude Code."""
    msg = decision.message or _default_message(decision)
    if decision.action == Action.DENY and event.event in _BLOCKABLE:
        return 2, "", f"[Aegis] {msg}\n"
    if decision.action == Action.ASK and event.event == HookEvent.PRE_TOOL_USE:
        out = json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": msg,
        }})
        return 0, out, ""
    if decision.action == Action.DENY:
        # policy says deny but this event can't be blocked — surface, don't fail
        return 0, "", f"[Aegis] (cannot block {event.event.value}) {msg}\n"
    return 0, "", ""


def _default_message(decision: Decision) -> str:
    rule = f" (rule: {decision.rule})" if decision.rule else ""
    if decision.action == Action.DENY:
        return f"Blocked by Aegis policy{rule}"
    if decision.action == Action.ASK:
        return f"Confirmation required by Aegis policy{rule}"
    return ""
