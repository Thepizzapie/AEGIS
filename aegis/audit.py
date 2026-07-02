"""Audit sink: append one JSONL record per hook decision, with optional token-
usage capture.

Accountability views (blame / did-it-do-the-task / cost) read this stream.
Writing audit must NEVER block the action, so callers wrap it.
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

# Common field names runtimes use to report token usage in hook payloads.
# Checked in event.raw (the unmodified payload) so we capture whatever the
# runtime sends without coupling to its schema.
_USAGE_FIELDS = {
    "input_tokens", "output_tokens",
    "cache_creation_input_tokens", "cache_read_input_tokens",
    "num_turns", "total_cost", "cost_usd", "duration_ms",
    "model",
}


def _extract_usage(event) -> dict:
    """Best-effort extraction of token/cost metadata from the raw hook payload.
    Returns only the fields that are present and non-None.  A runtime that sends
    no usage data -> empty dict; never fails."""
    raw = getattr(event, "raw", None) or {}
    usage: dict = {}
    # Top-level fields (some runtimes put them flat)
    for k in _USAGE_FIELDS:
        if k in raw and raw[k] is not None:
            usage[k] = raw[k]
    # Nested 'usage' dict (Anthropic API style: {input_tokens, output_tokens, …})
    nested = raw.get("usage")
    if isinstance(nested, dict):
        for k, v in nested.items():
            if v is not None:
                usage[k] = v
    # 'result' or 'tool_result' may carry per-call usage
    for wrapper in ("result", "tool_result"):
        inner = raw.get(wrapper)
        if isinstance(inner, dict):
            for k in _USAGE_FIELDS:
                if k in inner and inner[k] is not None:
                    usage.setdefault(k, inner[k])
            nested2 = inner.get("usage")
            if isinstance(nested2, dict):
                for k, v in nested2.items():
                    if v is not None:
                        usage.setdefault(k, v)
    return usage


def write_event(event, decision, path) -> dict:
    """Append a structured audit record for ``(event, decision)`` to ``path``
    (JSONL). Returns the record."""
    rec = {
        "ts": _dt.datetime.now().astimezone().isoformat(),
        "event": event.event.value,
        "tool": event.tool,
        "action": event.action.value,
        "decision": decision.action.value,
        "rule": decision.rule,
        "message": decision.message,
        "identity": event.identity,
        "agent": event.agent,
        "session_id": event.session_id,
        "cwd": event.cwd,
        "args": event.args,
    }
    # Lifecycle attribution fields — recorded only when the event carries them, so
    # tool-use records stay lean while subagent/team/worktree records stay traceable.
    for k in ("agent_id", "agent_type", "worktree", "matcher"):
        v = getattr(event, k, None)
        if v:
            rec[k] = v
    usage = _extract_usage(event)
    if usage:
        rec["usage"] = usage
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, default=str) + "\n")
    return rec
