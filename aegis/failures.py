"""Failure-loop ledger — session-scoped record of failed tool calls (AEGI-20).

An agent that retries the exact same failing call is thrashing: each retry burns
tokens, learns nothing, and (for shell) can repeat a half-destructive operation.
The runtime reports failures at PostToolUseFailure — which is observational, so
nothing can be blocked THERE. This ledger turns those observations into state the
blockable PreToolUse guard (``rules.rule_failure_loop``) can act on: deny the
Nth identical retry, with a reason that pushes the model to change approach.

Mechanics (mirrors the ``review`` read-coverage ledger):

- ``observe`` is a CLI-hook side effect. A PostToolUseFailure appends a ``fail``
  row for the call's signature; a successful PostToolUse of a signature that had
  failures appends an ``ok`` row (so a call that eventually succeeded — e.g. the
  environment was fixed — re-arms cleanly instead of blocking forever).
- The signature is the tool name + a canonical hash of its args: only an
  *identical* retry counts. Changing anything about the call (the fix the deny
  message asks for) starts a fresh signature.
- ``failure_count`` returns consecutive failures since the last ``ok``.

Everything is best-effort and fail-safe: a ledger error degrades to "no
failures recorded" (the guard abstains), never an exception into the hook.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from typing import List, Optional

from . import config
from .events import Event, HookEvent


def _failures_dir():
    return config.aegis_home() / "failures"


def _ledger_path(session: Optional[str]):
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", str(session or "nosession"))[:120]
    return _failures_dir() / f"{safe}.jsonl"


def signature(tool: Optional[str], args: Optional[dict]) -> str:
    """Stable id for one exact call: tool name + canonical (sorted-key) args.
    Non-serializable arg values are coerced via ``default=str``."""
    try:
        blob = json.dumps(args or {}, sort_keys=True, default=str)
    except Exception:
        blob = str(args)
    h = hashlib.sha256(f"{(tool or '').strip().lower()}\x00{blob}".encode(
        "utf-8", errors="replace"))
    return h.hexdigest()[:32]


def _append(session: Optional[str], record: dict) -> None:
    try:
        d = _failures_dir()
        d.mkdir(parents=True, exist_ok=True)
        with open(_ledger_path(session), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception:
        pass  # the ledger is advisory; a write failure must never block the agent


def _read_records(session: Optional[str]) -> List[dict]:
    try:
        p = _ledger_path(session)
        if not p.exists():
            return []
        out = []
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
        return out
    except Exception:
        return []


def observe(event: Event) -> None:
    """CLI-hook side effect. PostToolUseFailure -> record a ``fail`` row for the
    call's signature. PostToolUse (success) -> record an ``ok`` row, but only when
    that signature already has rows (a clean session writes no ledger at all).
    No-op for every other event."""
    try:
        if event.event not in (HookEvent.POST_TOOL_USE,
                               HookEvent.POST_TOOL_USE_FAILURE):
            return
        if not event.tool:
            return
        session = event.session_id or os.environ.get("AEGIS_SESSION_ID")
        sig = signature(event.tool, event.args)
        if event.event == HookEvent.POST_TOOL_USE_FAILURE:
            _append(session, {"sig": sig, "tool": event.tool, "outcome": "fail",
                              "ts": _now()})
            return
        # success: clear the signature's streak iff it has any recorded failures
        if any(r.get("sig") == sig for r in _read_records(session)):
            _append(session, {"sig": sig, "tool": event.tool, "outcome": "ok",
                              "ts": _now()})
    except Exception:
        pass


def failure_count(session: Optional[str], sig: str) -> int:
    """Consecutive ``fail`` rows for this signature since its last ``ok``.
    0 on any uncertainty — the guard abstains rather than false-denies."""
    n = 0
    for r in _read_records(session):
        if r.get("sig") != sig:
            continue
        if r.get("outcome") == "ok":
            n = 0
        elif r.get("outcome") == "fail":
            n += 1
    return n


def _now() -> str:
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return ""
