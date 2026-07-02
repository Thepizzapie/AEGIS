"""Ingest an OpenAI-style chat message trace into a Ledger.

The OpenAI chat-completions message format (`role`/`content`/`tool_calls`/
`tool_call_id`) is a de-facto standard many agent frameworks emit or can export.
This adapter walks such a transcript and records each *tool result* as evidence —
those are the observations the agent actually made, the ground truth Receipts
checks claims against. Pure-python; no SDK required.

A tool result is a message with `role == "tool"`. We map its tool name to an
evidence kind via `name_to_kind` (extend as needed); unknown names fall back to
the generic TOOL_CALL kind.
"""

from __future__ import annotations

from typing import Iterable

from ..ledger import Ledger
from ..models import EvidenceKind

# Map common tool-name substrings to evidence kinds. First match wins.
_DEFAULT_KIND_MAP: list[tuple[str, EvidenceKind]] = [
    ("search", EvidenceKind.WEB_SEARCH),
    ("fetch", EvidenceKind.WEB_FETCH),
    ("browse", EvidenceKind.WEB_FETCH),
    ("read", EvidenceKind.FILE_READ),
    ("file", EvidenceKind.FILE_READ),
    ("cat", EvidenceKind.FILE_READ),
    ("test", EvidenceKind.TEST_RUN),
    ("pytest", EvidenceKind.TEST_RUN),
    ("bash", EvidenceKind.COMMAND),
    ("shell", EvidenceKind.COMMAND),
    ("exec", EvidenceKind.COMMAND),
    ("run", EvidenceKind.COMMAND),
]


def _infer_kind(name: str) -> EvidenceKind:
    low = (name or "").lower()
    for needle, kind in _DEFAULT_KIND_MAP:
        if needle in low:
            return kind
    return EvidenceKind.TOOL_CALL


def from_openai_messages(
    ledger: Ledger,
    messages: Iterable[dict],
    *,
    name_to_kind=None,
) -> Ledger:
    """Record every tool-result message in an OpenAI-style trace as evidence.

    `name_to_kind` optionally overrides the inferred kind: a callable taking the
    tool name and returning an `EvidenceKind` (or None to fall back to inference).
    Returns the same ledger for chaining.
    """
    # Resolve tool names: a tool message carries tool_call_id; the name lives on
    # the assistant message's tool_calls. Build that lookup first.
    id_to_name: dict[str, str] = {}
    for m in messages if isinstance(messages, list) else (messages := list(messages)):
        for call in m.get("tool_calls") or []:
            cid = call.get("id")
            fn = (call.get("function") or {}).get("name") or call.get("name")
            if cid and fn:
                id_to_name[cid] = fn

    for m in messages:
        if m.get("role") != "tool":
            continue
        name = m.get("name") or id_to_name.get(m.get("tool_call_id", ""), "tool")
        kind = None
        if name_to_kind is not None:
            kind = name_to_kind(name)
        kind = kind or _infer_kind(name)
        ledger.record(kind, name, _stringify(m.get("content", "")))
    return ledger


def _stringify(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        # OpenAI content parts: join any text parts.
        parts = [p.get("text", "") if isinstance(p, dict) else str(p) for p in value]
        return "\n".join(p for p in parts if p)
    return repr(value)
