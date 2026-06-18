"""Runtime adapters: translate a runtime's native hook payloads <-> the
runtime-agnostic event model, and render an Aegis Decision into the output that
runtime expects.

Each adapter is a module exposing ``parse_event(payload) -> Event`` and
``render_decision(event, decision) -> (exit_code, stdout, stderr)``. Register it
in ``_REGISTRY`` and it becomes selectable via ``aegis hook --runtime <name>``.

- ``claude-code`` — the reference adapter (AEGI-2), native CC hook contract.
- ``generic``     — universal fallback (AEGI-7): a normalized JSON contract for
  any runtime that can invoke a command hook.

See ADAPTERS.md for the per-runtime status matrix.
"""
from __future__ import annotations

from . import claude_code, generic

_REGISTRY = {
    "claude-code": claude_code,
    "claude": claude_code,
    "cc": claude_code,
    "generic": generic,
}


def get_adapter(name):
    """Resolve an adapter module by name (default: claude-code). Raises KeyError
    for an unknown name."""
    if not name:
        return claude_code
    adapter = _REGISTRY.get(str(name).lower())
    if adapter is None:
        raise KeyError(f"unknown adapter '{name}' (available: {available()})")
    return adapter


def available() -> list:
    return sorted(set(_REGISTRY))
