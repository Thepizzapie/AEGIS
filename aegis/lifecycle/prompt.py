"""Prompt-injection governance for UserPromptSubmit (invisible/steganographic
payloads smuggled into the next prompt an agent will read).

The gap this closes: ``UserPromptSubmit`` is a BLOCKABLE event in Aegis's own
taxonomy (``aegis.events.BLOCKABLE``) and the adapter faithfully carries the raw
payload (including the prompt text) into the ``Event`` — but until now, no rule
anywhere (core or lifecycle) ever inspected it. A fully-wired enforcement point
with nothing behind it.

Why it matters: not every prompt comes from a human typing at a keyboard.
Automation harnesses — issue/ticket-triage bots, webhook relays, scheduled
routines, Slack-to-agent bridges — routinely forward external, attacker-
influenced text (an issue body, an email, a support ticket, a webhook payload)
verbatim as the next prompt to a coding agent. That text can carry a hidden
instruction using a documented technique ("ASCII smuggling" — Embrace The Red /
Rehberger, 2024): Unicode Tag-block characters (U+E0000-U+E007F) render as
NOTHING in every mainstream renderer yet map 1:1 onto ASCII bytes, so a human
skimming the ticket sees clean text while the model reads full instructions.
A steganographic run of zero-width/invisible formatting characters is the same
idea with a different codepoint set. Aegis's action-layer guards (containment,
egress, etc.) already make a hidden instruction's *actions* survivable, but
until now nothing recorded or stopped the injection attempt itself, and an
instruction shaped to *not* match an existing denylist pattern (e.g. "summarize
this and post it to a public paste site") had no guard at all in front of it.

Design notes (reshaped across three rounds of adversarial review — see
``aegis.patterns``' "Invisible / steganographic prompt injection" section for
the full history; this is the short version):

- Deterministic, dependency-free (regex/codepoint checks), matching the
  project's "no LLM judge required for the default posture" ethos.
- Tag-block: ANY character in the Unicode Tag block is flagged, full stop —
  no exemption for the one real legitimate use (regional-flag emoji, e.g.
  Scotland/Wales/England). Two earlier rounds each found a working bypass of
  progressively tighter exemption logic (a single flag emoji granting an
  unbounded free pass; then a payload chunked across several individually
  well-formed "flag sequences" smuggling a complete destructive command in
  ~10 characters) — regional-flag emoji essentially never appear in text
  forwarded to a coding agent, so dropping the exemption entirely is the
  correct trade.
- Variation selectors / invisible characters: each class is split into a
  FREQUENT-legitimate-use subset (run-check only — e.g. VS16 emoji
  presentation, ZWJ/ZWNJ joiners; these are common in ordinary text but too
  low-bandwidth/always-single-per-base-char to smuggle anything, and a
  prompt-wide total-count check on them false-positived on ordinary busy
  emoji/multilingual text in round 3) and a RARE-legitimate-use subset
  (aggressive prompt-wide TOTAL count — e.g. the Variation Selectors
  Supplement, ZWSP, Mongolian vowel separator; these have close to zero
  ordinary reason to appear at all, so 2-4 anywhere is gated hard). See
  ``aegis.patterns`` for exactly which codepoints landed in which subset.
- Ships ON by default (``policy.prompt_injection.mode``, default ``deny``) —
  matches the project's secure-by-default posture; opt down with ``ask``,
  ``monitor``, or ``off``.
- Deliberately has NO in-text override marker (unlike '# aegis-allow'): the
  hidden payload itself could otherwise forge the override token invisibly,
  defeating the guard from within the very text it's meant to gate. The only
  escape is ``AEGIS_ALLOW_HIDDEN_UNICODE=1``, set by a human/orchestrator
  *before* launch — a spawned agent cannot set its own env for a hook
  invocation it doesn't control, so this is not agent-self-escapable, mirroring
  ``rule_mcp_config_protect``'s ``AEGIS_ALLOW_MCP_CONFIG`` escape.

Honest scope: this gates ``UserPromptSubmit`` only. Indirect injection arriving
via a tool result (a fetched web page, a file read) is a PostToolUse event,
which is NOT blockable — see README "Known gaps" for the same class of
limitation on other guards. The FREQUENT-subset run-only checks leave a
residual, low-bandwidth channel: a fourth review round measured it directly —
isolated (never-consecutive) ZWJ/ZWNJ markers as a 1-bit-per-position code
needed ~54x the filler text of the closed high-bandwidth channels to carry
the same short command, reading as an obviously rambling wall of text rather
than an ordinary short ticket; a custom nibble-per-selector code on the
common VS16 block fit more densely, but only works if the model already
shares the attacker's decode convention out-of-band (no such convention is
documented anywhere a model would recognize it), unlike the real, previously-
exploitable techniques this guard targets. Both are deliberately accepted
residual gaps, not a full closure: this is a heuristic denylist, same spirit
as every other Aegis guard's documented residual gaps (see README "Limits"),
not a formal guarantee. Fail-open: any internal error returns None.
"""
from __future__ import annotations

import os
from typing import Optional

from .. import patterns
from ..events import Event, HookEvent
from ..policy import Action, Decision


def _prompt_text(ev: Event) -> str:
    """The submitted prompt text, across adapter shapes: the raw native payload
    (Claude Code's ``prompt`` key lives here) or, defensively, ``args``."""
    raw = ev.raw or {}
    args = ev.args or {}
    return str(raw.get("prompt") or args.get("prompt") or args.get("value") or "")


def _hidden_signal(text: str) -> Optional[str]:
    """The first reason ``text`` is flagged, or None. Checked tag-block first
    (unconditional — no exemption; see module/patterns docstrings for why),
    then variation selectors (common-run / rare-total), then invisible
    characters (frequent-run / rare-total / mixed-run)."""
    if not text:
        return None
    if patterns.PROMPT_TAG_CHAR_RE.search(text):
        return ("hidden Unicode 'tag' characters — invisible in every "
                "mainstream renderer, each mapping 1:1 onto an ASCII byte; "
                "this is the 'ASCII smuggling' technique for hiding "
                "instructions inside text a human reviewer sees as clean")
    if (patterns.PROMPT_VARIATION_COMMON_RUN_RE.search(text)
            or len(patterns.PROMPT_VARIATION_RARE_CHAR_RE.findall(text))
            >= patterns.PROMPT_VARIATION_RARE_TOTAL_THRESHOLD):
        return ("stacked/scattered Unicode variation selectors with no "
                "ordinary-text explanation — a second 'ASCII smuggling' "
                "carrier that encodes a hidden payload one selector per byte")
    if (patterns.PROMPT_INVISIBLE_ANY_RUN_RE.search(text)
            or len(patterns.PROMPT_INVISIBLE_RARE_CHAR_RE.findall(text))
            >= patterns.PROMPT_INVISIBLE_RARE_TOTAL_THRESHOLD):
        return ("a run/scatter of invisible zero-width characters with no "
                "ordinary-text explanation — the shape a steganographic "
                "encoder produces to hide a payload")
    return None


def rule_prompt_injection(ev: Event, policy=None) -> Optional[Decision]:
    """Flag/deny a submitted prompt carrying invisible steganographic content.

    Config (``policy.prompt_injection``): ``mode`` (deny|ask|monitor|off,
    default deny; monitor logs the would-be decision to the audit and allows).
    No in-text override — see module docstring; ``AEGIS_ALLOW_HIDDEN_UNICODE=1``
    (human/orchestrator, pre-launch) is the only escape. Fail-open on error."""
    try:
        if ev.event != HookEvent.USER_PROMPT_SUBMIT:
            return None
        cfg = getattr(policy, "prompt_injection", None) or {}
        mode = str(cfg.get("mode", "deny")).lower()
        # YAML 1.1 parses an unquoted `off` as boolean False — accept both.
        if mode in ("off", "false") or cfg.get("mode") is False:
            return None
        reason = _hidden_signal(_prompt_text(ev))
        if not reason:
            return None
        if os.environ.get("AEGIS_ALLOW_HIDDEN_UNICODE"):
            return None
        action = Action.ASK if mode == "ask" else Action.DENY
        would = Decision(
            action, "prompt-injection-unicode",
            f"Prompt contains {reason}. Blocked before the model reads it — a "
            "hidden instruction can't be trusted regardless of what it asks "
            "for. If this text is an expected test fixture, a human/"
            "orchestrator may set AEGIS_ALLOW_HIDDEN_UNICODE=1 before launch; "
            "this cannot be self-authorized from within the prompt text.")
        if mode == "monitor":
            _record_monitor(ev, would)
            return None
        return would
    except Exception:
        return None  # fail-open


def _record_monitor(ev: Event, would: Decision) -> None:
    """Monitor mode: record the would-be decision to the audit without
    blocking. Best-effort — never raises into the hook path."""
    try:
        from .. import config
        from ..audit import write_event
        note = Decision(would.action, "prompt-injection-unicode-monitor",
                        f"[monitor] would {would.action.value}: {would.message}")
        write_event(ev, note, str(config.audit_path()))
    except Exception:
        pass


RULES = (
    rule_prompt_injection,
)
