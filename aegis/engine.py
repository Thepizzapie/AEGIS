"""The enforcement engine.

Evaluation order (first-deny-wins, fail-open per rule so one bad rule can't brick
the agent):
  1. built-in secure-by-default rules (``aegis.rules``). Disable: ``AEGIS_NO_BUILTINS=1``.
  2. registered plugin rules (``aegis.plugins`` — org / MCP-provider custom guards).
  3. user declarative rules (highest priority first, first match wins).
  4. the policy's ``default_action``.

Rules are ``(Event, Policy) -> Decision | None`` so custom rules can read policy config.
"""
from __future__ import annotations

import os
import sys
from typing import Optional

from . import plugins, rules as _rules
from .events import Event
from .policy import Action, Decision, Policy


def _builtins_enabled() -> bool:
    return not os.environ.get("AEGIS_NO_BUILTINS")


def _run(rule_fns, event, policy) -> Optional[Decision]:
    for rule in rule_fns:
        try:
            decision = rule(event, policy)
        except Exception:
            decision = None  # fail-open per rule
        if decision is not None and decision.action != Action.ALLOW:
            return decision
    return None


def evaluate(event: Event, policy: Policy) -> Decision:
    if _builtins_enabled():
        d = _run(_rules.BUILTIN_RULES, event, policy)
        if d is not None:
            return d
    # Load plugins declared in the policy YAML (in addition to AEGIS_PLUGINS env)
    if policy.plugins:
        plugins.load_modules(policy.plugins)
    d = _run(plugins.active_rules(), event, policy)  # custom guards
    if d is not None:
        return d
    for rule in sorted(policy.rules, key=lambda r: r.priority, reverse=True):
        try:
            if rule.matches(event):
                return Decision(rule.action, rule.name, rule.message)
        except Exception:
            continue  # fail-open per rule
    return Decision(policy.default_action, None, None)


def safe_evaluate(event: Event, policy: Policy, *,
                  on_error: Optional[Action] = None) -> Decision:
    """evaluate() wrapped so it NEVER raises. On a catastrophic error, fall back to
    ``on_error`` / ``policy.on_error`` / ALLOW."""
    try:
        return evaluate(event, policy)
    except Exception as exc:  # noqa: BLE001
        fallback = on_error or getattr(policy, "on_error", Action.ALLOW)
        print(f"aegis: policy evaluation error ({exc!r}); failing to "
              f"{fallback.value}", file=sys.stderr)
        return Decision(fallback, "<error>",
                        "Aegis internal error" if fallback == Action.DENY else None)
