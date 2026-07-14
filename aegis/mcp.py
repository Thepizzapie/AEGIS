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
"""
from __future__ import annotations

import functools

from . import config, identity, plugins
from .engine import safe_evaluate
from .events import ActionClass, Event
from .policy import Decision, Policy


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
          event="PreToolUse", action=None) -> Decision:
    """Evaluate an MCP tool call against policy. Returns a Decision (never raises).
    The server-side identity gate runs first: an untokened agent under enforcement
    is refused before policy is even consulted.

    Every call through this API IS an MCP tool call, and now ALWAYS defaults
    to ``ActionClass.MCP`` regardless of ``tool_name`` — pass ``action`` to
    force a specific class instead (e.g. ``ActionClass.SHELL`` to
    deliberately reuse Aegis's shell guards for a pass-through tool).

    A first version of this fix (round 8 QA) instead fell back to
    ``events.classify()``'s name-based guess whenever it recognized
    ``tool_name`` as something other than an MCP shape, reasoning that a
    caller might deliberately reuse a Claude-native name (``"Bash"``,
    ``"Read"``) to get its matching guards. Round 9 QA found that guess
    unsafe: ``classify()``'s table also contains ordinary, plausible names a
    THIRD-PARTY MCP tool might use with no such intent — ``read``, ``write``,
    ``bash``, and critically ``task``/``agent`` (-> ``ActionClass.SUBAGENT``,
    a class ``rule_containment`` has no branch for at all) — so an MCP
    server naming its own tool ``"agent"`` or ``"task"`` got ZERO
    containment scanning, end-to-end through the documented ``@guarded``
    pattern, purely by an unintentional name collision. Defaulting
    unconditionally to MCP and requiring an explicit opt-in for anything
    else closes that: a real collision can no longer silently downgrade
    the scan a caller didn't ask for."""
    from . import gate as _gate
    from .policy import Action
    reason = _gate.gate(tool_name)
    if reason:
        return Decision(Action.DENY, "identity-gate", reason)
    ident, rls = identity.resolve_identity()
    ev = Event.make(event, tool=tool_name, args=arguments or {},
                    action=action or ActionClass.MCP,
                    identity=identity_name or ident, roles=roles or rls)
    return safe_evaluate(ev, _policy())


def guard(tool_name, arguments=None, **kw) -> Decision:
    """check(), but raise ``Denied`` if the call is blocked. Returns the Decision otherwise."""
    d = check(tool_name, arguments, **kw)
    if d.blocked:
        raise Denied(d)
    return d


def guarded(fn=None, *, tool_name=None, action=None):
    """Decorator: enforce policy before a tool handler runs. The handler's kwargs are
    the tool arguments. Raises ``Denied`` on a blocked call. Pass ``action`` to
    force a specific ActionClass (see ``check``'s docstring) instead of the
    ``ActionClass.MCP`` default."""
    def deco(f):
        name = tool_name or getattr(f, "__name__", "tool")

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            guard(name, kwargs, action=action)
            return f(*args, **kwargs)
        return wrapper

    return deco(fn) if callable(fn) else deco
