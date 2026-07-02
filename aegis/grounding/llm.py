"""Pluggable LLM backend for the semantic pieces (support check, extraction).

The core engine is deterministic and dependency-free. Only the two genuinely
semantic features — judging whether evidence supports a claim, and breaking a
free-text answer into structured claims — need a model. Both go through the small
`LLM` protocol below so the core never imports a vendor SDK directly.

`AnthropicLLM` is the production backend (lazy-imports `anthropic`); `FakeLLM` is
a deterministic stand-in for tests and offline use.
"""

from __future__ import annotations

import json
from typing import Callable, Protocol

# Anthropic's most capable model; the judge/extractor want accuracy over speed.
DEFAULT_MODEL = "claude-opus-4-8"


class LLM(Protocol):
    """Returns a JSON object matching `schema` for the given prompt."""

    def complete_json(self, system: str, user: str, schema: dict) -> dict: ...


class AnthropicLLM:
    """Anthropic-backed LLM. Uses structured outputs so the reply is valid JSON.

    Requires `pip install receipts-gate[anthropic]` and ANTHROPIC_API_KEY in the env.
    """

    def __init__(self, model: str = DEFAULT_MODEL, max_tokens: int = 4096) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import anthropic
            except ImportError as e:  # pragma: no cover - env-dependent
                raise ImportError(
                    "AnthropicLLM needs the 'anthropic' package: "
                    "pip install 'receipts-gate[anthropic]'"
                ) from e
            self._client = anthropic.Anthropic()
        return self._client

    def complete_json(self, system: str, user: str, schema: dict) -> dict:
        client = self._get_client()
        resp = client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"format": {"type": "json_schema", "schema": schema}},
        )
        # output_config.format guarantees the first text block is valid JSON.
        text = next(b.text for b in resp.content if b.type == "text")
        return json.loads(text)


class FakeLLM:
    """Deterministic LLM for tests. Supply a handler mapping prompt -> dict."""

    def __init__(self, handler: Callable[[str, str, dict], dict]) -> None:
        self._handler = handler
        self.calls: list[tuple[str, str]] = []

    def complete_json(self, system: str, user: str, schema: dict) -> dict:
        self.calls.append((system, user))
        return self._handler(system, user, schema)
