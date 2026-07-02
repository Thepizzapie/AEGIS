"""Build a grounding :class:`Ledger` from Aegis's own audit trail.

Aegis already records every tool the agent ran (and, on PostToolUse, what the tool
returned) to a JSONL audit stream. That stream IS the evidence a grounding check
needs — so an agent's final answer can be gated against what it actually did,
without any separate instrumentation. This is the seam between the two halves of
Aegis: enforcement (what an agent may do) and grounding (what an agent may claim).
"""
from __future__ import annotations

import json
from pathlib import Path

from .ledger import Ledger
from .models import EvidenceKind

# Aegis ActionClass (audit "action" field) -> grounding EvidenceKind.
_ACTION_TO_KIND = {
    "read": EvidenceKind.FILE_READ,
    "edit": EvidenceKind.FILE_READ,
    "write": EvidenceKind.FILE_READ,
    "shell": EvidenceKind.COMMAND,
    "git": EvidenceKind.COMMAND,
    "net": EvidenceKind.WEB_FETCH,
    "mcp": EvidenceKind.TOOL_CALL,
    "subagent": EvidenceKind.TOOL_CALL,
    "other": EvidenceKind.TOOL_CALL,
}

# Where the human-meaningful "source" lives inside a tool's args, by field name.
_SOURCE_KEYS = ("command", "file_path", "path", "url", "query", "pattern", "value")


def _source(rec: dict) -> str:
    args = rec.get("args") or {}
    if isinstance(args, dict):
        for k in _SOURCE_KEYS:
            v = args.get(k)
            if v:
                return str(v)
    return rec.get("tool") or rec.get("action") or "tool"


def ledger_from_audit(path, *, only_allowed: bool = True) -> Ledger:
    """Read an Aegis audit JSONL file and return a grounding Ledger.

    Only records that captured a tool ``output`` become evidence (a claim is
    grounded in what a tool RETURNED, not merely that it was called). By default
    denied actions are skipped (``only_allowed``) — a blocked tool call produced
    no real observation, so it can't back a claim.
    """
    ledger = Ledger()
    p = Path(path)
    if not p.exists():
        return ledger
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        output = rec.get("output")
        if not output:
            continue  # no observation captured -> nothing to ground against
        if only_allowed and rec.get("decision") == "deny":
            continue
        kind = _ACTION_TO_KIND.get(rec.get("action"), EvidenceKind.TOOL_CALL)
        ledger.record(kind, _source(rec), str(output))
    return ledger
