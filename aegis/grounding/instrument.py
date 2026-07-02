"""Instrumentation: how real tool calls get into the Ledger automatically.

Framework-agnostic. You either:
  * call `ledger.record(...)` directly,
  * wrap a tool function with `@track(ledger, kind=...)`, or
  * ingest an existing trace with `ingest_trace(...)`.

The point is that evidence is captured from the *execution*, not self-reported by
the agent. A model cannot write a `file_read` evidence record without a file
actually having been read through the wrapper.
"""

from __future__ import annotations

import functools
from typing import Callable, Iterable

from .ledger import Ledger
from .models import EvidenceKind


def track(
    ledger: Ledger,
    kind: EvidenceKind | str,
    *,
    source: Callable[..., str] | str | None = None,
):
    """Decorator that records a tool's return value as evidence.

    `source` may be a static string or a callable mapping the call args to a
    source label (path/url/command).
    """

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            result = fn(*args, **kwargs)
            if callable(source):
                src = source(*args, **kwargs)
            elif source is not None:
                src = source
            else:
                src = fn.__name__
            ledger.record(kind, src, _stringify(result))
            return result

        return wrapper

    return decorator


def ingest_trace(ledger: Ledger, events: Iterable[dict]) -> Ledger:
    """Load evidence from a pre-existing execution trace.

    Each event is a dict: {"kind", "source", "content", ...meta}. This is the
    post-hoc / auditor entry point — point it at a logged agent run.
    """
    for ev in events:
        meta = {k: v for k, v in ev.items() if k not in {"kind", "source", "content"}}
        ledger.record(ev["kind"], ev["source"], _stringify(ev.get("content", "")), **meta)
    return ledger


def _stringify(value) -> str:
    return value if isinstance(value, str) else repr(value)
