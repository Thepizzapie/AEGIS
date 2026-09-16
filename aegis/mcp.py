"""Embed Aegis in your own MCP server.

A hook governs the agent runtime; this governs the *tool side*. An MCP provider
wraps their tools so Aegis policy (built-ins + the org's custom plugin rules) is
enforced INSIDE the server — defense the client can't bypass:

    from aegis import mcp

    @mcp.guarded                       # decorator on a tool handler
    def delete_record(id): ...

    # or inline / as middleware:
    d = mcp.check("vault:get_secret", {"key": "prod"})
    if d.blocked: ...

`check` builds a PreToolUse event, resolves the caller identity (signed token if
present), loads the policy + plugins, and evaluates. Fail-open (never raises into
the host except the explicit Denied from `guard`).

That covers a tool *call*. A tool's *catalog entry* (name/description/schema,
fetched once via ``tools/list`` and typically trusted for the rest of the
session) is a distinct surface no call-level check ever sees — a server can
poison a description with hidden instructions, or silently swap one in after
a human already approved it (a "rug pull"). So are its two sibling catalog
endpoints, ``resources/list`` and ``prompts/list`` — the same one-time-trust
shape, one layer over. See ``audit_tool_list``/``audit_resource_list``/
``audit_prompt_list`` below (``aegis.mcp_integrity``) for those guards.
"""
from __future__ import annotations

import functools

from . import config, identity, mcp_integrity, plugins
from .engine import safe_evaluate
from .events import Event
from .policy import Decision, Policy

# Catalog integrity (poisoning + rug-pull drift), all three MCP list
# endpoints — re-exported here so every catalog-level defense lives behind
# `from aegis import mcp`, alongside the tool-CALL guard above.
audit_tool_list = mcp_integrity.audit_tools
audit_resource_list = mcp_integrity.audit_resources
audit_prompt_list = mcp_integrity.audit_prompts
forget_tool_pins = mcp_integrity.forget


class Denied(Exception):
    """Raised by ``guard``/``guarded`` when a tool call is blocked by policy."""

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(decision.message or f"blocked by Aegis ({decision.rule})")


def _policy() -> Policy:
    try:
        from .loader import load_policy
        p = load_policy(config.policy_dir())
        plugins.load_modules(getattr(p, "plugins", []) or [])
        return p
    except Exception:
        return Policy()


def check(tool_name, arguments=None, *, identity_name=None, roles=None,
          event="PreToolUse") -> Decision:
    """Evaluate an MCP tool call against policy. Returns a Decision (never raises).
    The server-side identity gate runs first: an untokened agent under enforcement
    is refused before policy is even consulted."""
    from . import gate as _gate
    from .policy import Action
    reason = _gate.gate(tool_name)
    if reason:
        return Decision(Action.DENY, "identity-gate", reason)
    ident, rls = identity.resolve_identity()
    ev = Event.make(event, tool=tool_name, args=arguments or {},
                    identity=identity_name or ident, roles=roles or rls)
    return safe_evaluate(ev, _policy())


def guard(tool_name, arguments=None, **kw) -> Decision:
    """check(), but raise ``Denied`` if the call is blocked. Returns the Decision otherwise."""
    d = check(tool_name, arguments, **kw)
    if d.blocked:
        raise Denied(d)
    return d


def guarded(fn=None, *, tool_name=None):
    """Decorator: enforce policy before a tool handler runs. The handler's kwargs are
    the tool arguments. Raises ``Denied`` on a blocked call."""
    def deco(f):
        name = tool_name or getattr(f, "__name__", "tool")

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            guard(name, kwargs)
            return f(*args, **kwargs)
        return wrapper

    return deco(fn) if callable(fn) else deco
