"""Ingest an Anthropic / Claude Agent SDK conversation into a Ledger.

Works with the Anthropic Messages API conversation shape and the Claude Agent
SDK's message stream — both express tool use as content blocks: an assistant
`tool_use` block names the tool, and a later user `tool_result` block carries what
the tool returned (the observation Receipts treats as evidence).

Blocks may be plain dicts (raw API / JSON transcripts) or SDK objects (attribute
access); this adapter handles both. Pure Python, no SDK required to run.
"""

from __future__ import annotations

from typing import Iterable

from ..ledger import Ledger
from .openai_trace import _infer_kind


def _get(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _content_blocks(message) -> list:
    content = _get(message, "content", [])
    if isinstance(content, str):
        return []  # plain-text turn, no tool blocks
    return list(content or [])


def _result_text(content) -> str:
    """tool_result content is a string or a list of {type: text, text: ...} blocks."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for b in content:
            if _get(b, "type") == "text" or _get(b, "text") is not None:
                parts.append(str(_get(b, "text", "")))
            else:
                parts.append(str(b))
        return "\n".join(p for p in parts if p)
    return "" if content is None else str(content)


def from_anthropic_messages(
    ledger: Ledger,
    messages: Iterable,
    *,
    name_to_kind=None,
) -> Ledger:
    """Record every `tool_result` block in an Anthropic-style conversation.

    `messages` is the list of message dicts/objects (Messages API format, or the
    Claude Agent SDK message stream). Returns the same ledger for chaining.
    """
    messages = list(messages)

    # First pass: map tool_use ids to their tool names (from assistant turns).
    id_to_name: dict[str, str] = {}
    for m in messages:
        for block in _content_blocks(m):
            if _get(block, "type") == "tool_use":
                bid = _get(block, "id")
                name = _get(block, "name")
                if bid and name:
                    id_to_name[bid] = name

    # Second pass: record tool_result blocks as evidence.
    for m in messages:
        for block in _content_blocks(m):
            if _get(block, "type") != "tool_result":
                continue
            name = id_to_name.get(_get(block, "tool_use_id", ""), "tool")
            kind = None
            if name_to_kind is not None:
                kind = name_to_kind(name)
            kind = kind or _infer_kind(name)
            text = _result_text(_get(block, "content", ""))
            err = bool(_get(block, "is_error", False))
            ledger.record(kind, name, text, is_error=err)
    return ledger
