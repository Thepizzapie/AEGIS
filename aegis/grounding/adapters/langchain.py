"""LangChain / LangGraph capture: record tool outputs to the Ledger live.

A LangChain callback handler that writes each tool result into the Ledger as it
happens, so an existing LangChain agent gains evidence capture without changing
its tool code. `langchain_handler(ledger)` returns a ready handler — pass it in
`config={"callbacks": [...]}` (or to the agent executor).

The recording logic lives in the plain `record_tool_end` function so it's
testable without langchain installed; the handler is a thin wrapper around it and
lazy-imports `langchain_core` only when you actually build one.
"""

from __future__ import annotations

from ..ledger import Ledger
from .openai_trace import _infer_kind, _stringify


def record_tool_end(ledger: Ledger, name: str, output, *, name_to_kind=None):
    """Record one finished tool call as evidence. Returns the Evidence record."""
    kind = None
    if name_to_kind is not None:
        kind = name_to_kind(name)
    kind = kind or _infer_kind(name or "")
    return ledger.record(kind, name or "tool", _stringify(output))


def langchain_handler(ledger: Ledger, *, name_to_kind=None):
    """Build a LangChain `BaseCallbackHandler` that captures tool results.

    Usage:
        handler = langchain_handler(ledger)
        agent.invoke(inputs, config={"callbacks": [handler]})
    """
    try:
        from langchain_core.callbacks import BaseCallbackHandler
    except ImportError as e:  # pragma: no cover - env-dependent
        raise ImportError(
            "langchain_handler needs langchain-core: pip install langchain-core"
        ) from e

    class ReceiptsCallbackHandler(BaseCallbackHandler):
        def __init__(self) -> None:
            super().__init__()
            self._names: dict = {}

        def on_tool_start(self, serialized, input_str, *, run_id=None, **kwargs):
            self._names[run_id] = (serialized or {}).get("name")

        def on_tool_end(self, output, *, run_id=None, **kwargs):
            name = self._names.pop(run_id, None) or kwargs.get("name") or "tool"
            record_tool_end(ledger, name, output, name_to_kind=name_to_kind)

    return ReceiptsCallbackHandler()
