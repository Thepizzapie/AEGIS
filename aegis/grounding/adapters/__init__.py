"""Framework adapters that feed real tool-call traces into a Ledger.

Capture is framework-agnostic at the core (`@track`, `ingest_trace`); these
adapters map specific ecosystems' trace formats onto the Ledger so you don't have
to hand-translate. Each is import-light and optional.
"""

from .anthropic_trace import from_anthropic_messages
from .langchain import langchain_handler, record_tool_end
from .openai_trace import from_openai_messages

__all__ = [
    "from_openai_messages",
    "from_anthropic_messages",
    "langchain_handler",
    "record_tool_end",
]
