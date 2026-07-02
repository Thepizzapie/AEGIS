"""Context injection — the policy-posture digest (AEGI-20).

The rules an agent runs under are only as durable as its context. SessionStart
is the natural place to put them in front of the model — and context compaction
is where they silently fall out: a summarizer keeps the task and drops the
governance. This module composes a compact digest of the ACTIVE policy posture
(not the full policy — a summary the model can act on) and decides which events
it is injected on.

Default: inject on SessionStart and PostCompact. PostCompact is the reliability
point — it fires right after the in-context rules were destroyed, so re-injecting
there is what makes the posture survive a long session. Opt out with
``policy.inject: {mode: off}``.

Injection is advisory (the model can still ignore it); enforcement stays in the
hooks. The digest exists so the agent can comply on the first try instead of
discovering the policy one deny at a time. Everything here is fail-safe: any
error yields an empty digest, never an exception into the hook path.
"""
from __future__ import annotations

from .events import Event, HookEvent
from .policy import Action

# Events the digest is injected on when policy doesn't say otherwise.
DEFAULT_EVENTS = frozenset({HookEvent.SESSION_START, HookEvent.POST_COMPACT})


def _is_off(mode) -> bool:
    """YAML 1.1 parses an unquoted ``off`` as boolean False — accept both."""
    return mode is False or str(mode).strip().lower() in ("off", "false", "0")


def should_inject(event: Event, policy) -> bool:
    """Whether this event gets the posture digest. ``policy.inject.mode: off``
    disables; anything else (including no config) -> DEFAULT_EVENTS."""
    try:
        cfg = getattr(policy, "inject", None) or {}
        if _is_off(cfg.get("mode", "on")):
            return False
        return event.event in DEFAULT_EVENTS
    except Exception:
        return False


def _optins(policy) -> list:
    """Human-readable list of the opt-in knobs that are actually ON."""
    out = []
    try:
        if (getattr(policy, "team", None) or {}).get("require_verification"):
            out.append("task completion requires recorded verification")
        if (getattr(policy, "compaction", None) or {}).get("block_auto"):
            out.append("auto-compaction is blocked (checkpoint, then /compact)")
        if (getattr(policy, "permission", None) or {}).get("deny_escalation"):
            out.append("permission escalations auto-deny for spawned agents")
        if (getattr(policy, "mcp", None) or {}).get("block_elicitation"):
            out.append("MCP elicitation is blocked for spawned agents")
        if (getattr(policy, "completion", None) or {}).get("require_tests"):
            out.append("stopping after edits requires a post-edit test run")
        ws = getattr(policy, "workspace", None) or {}
        root = ws.get("root") or getattr(policy, "project", None)
        if root:
            out.append(f"file writes are confined to {root}")
        eg = getattr(policy, "egress", None) or {}
        if str(eg.get("default", "")).lower() == "deny":
            out.append("network egress is deny-by-default (allowlist only)")
    except Exception:
        pass
    return out


def compose(policy) -> str:
    """The digest text. Compact on purpose — this is injected into the model's
    context on every session start / compaction, so it must earn its tokens."""
    try:
        default = getattr(policy, "default_action", Action.ALLOW)
        default = default.value if hasattr(default, "value") else str(default)
        n_rules = len(getattr(policy, "rules", None) or [])
        fl = getattr(policy, "failures", None) or {}
        fl_mode = "off" if _is_off(fl.get("mode", "deny")) \
            else str(fl.get("mode", "deny")).lower()
        try:
            fl_n = int(fl.get("max_repeats", 3))
        except (TypeError, ValueError):
            fl_n = 3

        lines = [
            "[Aegis] Enforcement is active: every action is policy-checked "
            "before it runs and recorded to an audit trail.",
            f"Posture: default_action={default}; built-in guards + "
            f"{n_rules} policy rule(s).",
            "Never available to you: credential stores, persistence installs, "
            "uploading local files, editing Aegis config/policy/source, and "
            "writing MCP server configs.",
            "Human-only escapes: '# aegis-allow' overrides (destructive "
            "git/delete/SQL, obfuscated commands, fetch-piped-to-shell, "
            "unreviewed installs) are honored only for a human, never for a "
            "spawned agent.",
        ]
        if fl_mode != "off":
            lines.append(
                f"Reliability: re-running a call identical to one that already "
                f"failed {fl_n}x this session is {'flagged' if fl_mode == 'ask' else 'denied'} "
                f"— read the error and change approach instead of retrying.")
        opts = _optins(policy)
        if opts:
            lines.append("Also active: " + "; ".join(opts) + ".")
        lines.append(
            "When blocked, the [Aegis] reason says why and how to comply — "
            "follow it; bypass attempts are themselves recorded.")
        return "\n".join(lines)
    except Exception:
        return ""
