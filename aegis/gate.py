"""Server-side identity gate.

The hook-level rogue gate (rules.rule_attest_session) can be skipped by a runtime
that bypasses hooks. This refusal lives in plain Python — importable by an API or
MCP server — so it holds regardless of how the runtime handles permissions: a
process claiming an agent identity (AEGIS_AGENT_NAME) without a valid signed token
is refused when enforcement (AEGIS_IDENTITY_ENFORCE) is armed. Every untrusted
attempt is recorded (detection log) even in MONITOR mode. Fail-open on error.
"""
from __future__ import annotations

import os

from . import identity


class Refused(Exception):
    """Raised by require() when an untokened agent is refused under enforcement."""


def caller_is_trusted() -> bool:
    if not os.environ.get("AEGIS_AGENT_NAME"):
        return True  # human / orchestrator — makes no agent claim
    try:
        return identity.current() is not None
    except Exception:
        return True  # fail-open on a crypto hiccup


def gate(action="action", *, claimed=None):
    """Deny-reason if this process claims an identity without a valid token AND
    enforcement is armed; else None. Records the attempt regardless."""
    try:
        if caller_is_trusted():
            return None
        name = os.environ.get("AEGIS_AGENT_NAME") or "?"
        from . import attest
        attest.record(
            attest.classify({"agent": name, "token": os.environ.get("AEGIS_AGENT_TOKEN")}),
            source=os.environ.get("AEGIS_SESSION_ID") or name)
        if not identity.enforce_enabled():
            return None  # MONITOR — record + allow
        return (f"Aegis identity gate: process claims agent '{name}' but carries no "
                f"valid signed token. '{action}' refused server-side.")
    except Exception:
        return None


def require(action="action", *, claimed=None) -> None:
    """gate(), but raise Refused on denial. For an API/MCP write surface."""
    reason = gate(action, claimed=claimed)
    if reason:
        raise Refused(reason)
