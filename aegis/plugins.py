"""Custom guard plugins — how individuals / orgs / MCP providers add their OWN
rules without forking Aegis.

A plugin is a Python module that either calls ``aegis.plugins.register_rule(fn)``
at import, or exposes a module-level ``RULES = [fn, ...]``. Each rule is the same
``(Event, Policy) -> Decision | None`` contract as the built-ins, so a custom rule
can read ``policy`` for its own config.

Load them via the ``AEGIS_PLUGINS`` env (comma-separated module paths) or a
policy ``plugins:`` list. A broken plugin never breaks the engine (fail-open).
"""
from __future__ import annotations

import importlib
import os

_REGISTERED: list = []
_ENV_LOADED = False


def register_rule(fn):
    """Register a custom rule function. Usable as a decorator."""
    if fn not in _REGISTERED:
        _REGISTERED.append(fn)
    return fn


def load_modules(modules) -> None:
    """Import plugin modules so they self-register (or expose RULES). Fail-safe."""
    for mod in (modules or []):
        try:
            m = importlib.import_module(str(mod))
            for r in (getattr(m, "RULES", None) or []):
                register_rule(r)
        except Exception:
            pass  # a broken plugin must not break the engine


def _ensure_env_loaded() -> None:
    global _ENV_LOADED
    if _ENV_LOADED:
        return
    _ENV_LOADED = True
    spec = os.environ.get("AEGIS_PLUGINS") or ""
    load_modules([m.strip() for m in spec.split(",") if m.strip()])


def active_rules() -> list:
    """All registered custom rules (env plugins loaded lazily on first use)."""
    _ensure_env_loaded()
    return list(_REGISTERED)


def reset() -> None:
    """Clear the registry (tests)."""
    global _ENV_LOADED
    _REGISTERED.clear()
    _ENV_LOADED = False
