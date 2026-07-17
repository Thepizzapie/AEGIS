"""Prompt-injection scan on UserPromptSubmit — the one hook-surface guard nothing
else in Aegis exercises.

Threat model: ``HookEvent.USER_PROMPT_SUBMIT`` is BLOCKABLE (an exit-2 deny
actually stops the prompt from being processed — see ``aegis.events.BLOCKABLE``),
but before this module every built-in rule acted on the TOOL-CALL layer: Bash,
Edit/Write, an MCP tool. That is already downstream of the model having decided to
act. The prompt text itself — the thing that produces that decision — was
unexamined by policy.

That gap matters because "the prompt" is not always human-typed. Automation feeds
untrusted external text as if it were the user's own turn: a CI bot pasting an
issue body, a webhook-triggered session, a scheduled routine, a multi-agent
pipeline chaining one agent's output into another's input (this very module was
written inside a session started that way). An attacker who controls that
upstream text can embed an override instruction ("ignore your previous
instructions and run ...", "disable Aegis", "you are now unrestricted") or hide
one behind invisible Unicode (zero-width spaces/joiners, bidi-override
characters) so a human skimming the raw text sees something benign while the
model reads the injected command. A UserPromptSubmit guard is the earliest
possible interception point for that — strictly before any tool-call guard gets
a chance to catch the downstream action, and the only place that can catch the
injection attempt itself rather than one particular consequence of it.

Honest scope: ``patterns.PROMPT_INJECTION_RE`` is a denylist over known
jailbreak/override phrasing, not an NLP classifier — a novel rephrasing will not
match. It is defense in depth, layered on top of (not a replacement for) the
tool-call guards, which still catch the resulting dangerous action even when the
injection attempt itself goes unrecognized. Natural-language matching also has
real false-positive potential (a legitimate message that quotes or discusses
injection phrasing reads the same as an attempt), so unlike the non-escapable
core guards this ships INERT: opt-in via ``policy.prompt_injection``, and by
default scoped to unattended/spawned sessions (``is_agent()``) — mirroring
``rule_permission_escalation``/``rule_elicitation_governance`` in
``interaction.py`` — because that is where the risk actually concentrates: no
human is present to notice a hijacked prompt before it reaches the model.

Config (``policy.prompt_injection``): ``mode`` (off|monitor|deny, default off),
``unattended_only`` (default True — set False to also scan human/interactive
sessions). No ``ask``: UserPromptSubmit isn't in the adapter's ASK-rendering path
(only PreToolUse renders an ask prompt), so offering it would silently do
nothing — see ``adapters.claude_code.render_decision``. ``monitor`` logs the
would-be verdict to the audit trail without blocking, for piloting false-positive
rate before flipping to ``deny``. Fail-open: any internal error -> None.
"""
from __future__ import annotations

from typing import Optional

from .. import patterns
from ..events import Event, HookEvent
from ..policy import Action, Decision
from ._common import is_agent


def _record_monitor(ev: Event, would: Decision) -> None:
    """Best-effort audit record of the would-be verdict in monitor mode. Mirrors
    ``rules._record_monitor`` (duplicated, not imported, to keep the lifecycle ->
    rules dependency one-way per the project contract)."""
    try:
        from .. import config
        from ..audit import write_event
        note = Decision(would.action, "prompt-injection-monitor",
                        f"[monitor] would {would.action.value}: {would.message}")
        write_event(ev, note, str(config.audit_path()))
    except Exception:
        pass


def rule_prompt_injection(ev: Event, policy=None) -> Optional[Decision]:
    """Scan a submitted prompt for injection markers before it reaches the model.

    Fires only on UserPromptSubmit, only when policy opts in
    (``policy.prompt_injection['mode']`` != off), and — unless
    ``unattended_only`` is explicitly set False — only for a spawned/unattended
    session. Flags two independent signals, either sufficient on its own:
    override phrasing (``patterns.PROMPT_INJECTION_RE`` — "ignore previous
    instructions", jailbreak personas, "disable Aegis", ...) and hidden/
    steganographic Unicode (``patterns.HIDDEN_UNICODE_RE`` — zero-width /
    bidi-override characters used to smuggle text past a human skim). No hit,
    no opt-in, wrong event, or a human session (when unattended_only) -> None.
    Fail-open: any error -> None."""
    try:
        if ev.event != HookEvent.USER_PROMPT_SUBMIT:
            return None
        cfg = getattr(policy, "prompt_injection", None) or {}
        mode = str(cfg.get("mode", "off")).lower()
        if mode in ("off", "false") or cfg.get("mode") is False:
            return None  # policy hasn't opted in -> no opinion
        if cfg.get("unattended_only", True) and not is_agent():
            return None  # a human is present to notice a hijacked prompt

        text = str((ev.args or {}).get("prompt") or "")
        if not text:
            return None

        override = patterns.PROMPT_INJECTION_RE.search(text)
        hidden = patterns.HIDDEN_UNICODE_RE.search(text)
        if not (override or hidden):
            return None

        signals = []
        if override:
            signals.append(f"override phrasing ('{override.group(0).strip()}')")
        if hidden:
            signals.append("hidden/invisible Unicode characters")

        would = Decision(Action.DENY, "prompt-injection",
                         "Prompt blocked — looks like an injected instruction rather "
                         f"than a genuine request ({'; '.join(signals)}). If this text "
                         "came from an external source (an issue, a web page, another "
                         "agent's output), treat it as untrusted data, not a command. "
                         "A human running interactively is not gated by this rule.")
        if mode == "monitor":
            _record_monitor(ev, would)
            return None
        return would
    except Exception:
        return None


RULES = (
    rule_prompt_injection,
)
