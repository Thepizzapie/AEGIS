"""Hidden-Unicode prompt-injection guard — the UserPromptSubmit boundary.

Deliberately builds every invisible/control codepoint via chr()/escape rather
than embedding literal invisible characters in this file — same reasoning as
aegis.patterns: unreviewable in a diff, and an uncomfortable thing for a
security tool's own test suite to carry as raw bytes.
"""
import json

from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy
from aegis.adapters import claude_code as cc

TAG_HELLO = "".join(chr(0xE0000 + b) for b in b" hello")  # tag-block-encoded " hello"
ZWSP, ZWNJ, ZWJ, WORD_JOINER, ZWNBSP = (chr(c) for c in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF))
VS15, VS16 = chr(0xFE0E), chr(0xFE0F)  # variation selectors
RLO = chr(0x202E)  # bidi right-to-left override
LRM = chr(0x200E)  # plain direction mark — legitimate, must never match

# Standardized subdivision flag emoji (Scotland): WAVING BLACK FLAG + tag
# letters spelling "gbsct" + CANCEL TAG. A real, rendered-by-major-platforms
# sequence that must NOT be flagged (it lives entirely inside the tag block).
SCOTLAND_FLAG = "\U0001F3F4" + "".join(chr(0xE0000 + b) for b in b"gbsct") + chr(0xE007F)


def _prompt(text):
    return Event.make(HookEvent.USER_PROMPT_SUBMIT, args={"prompt": text})


def test_tag_block_steganography_blocked():
    d = evaluate(_prompt(f"Please help with this task{TAG_HELLO}"), Policy())
    assert d.blocked
    assert d.rule == "hidden-unicode-tag-chars"


def test_chained_zero_width_run_blocked():
    d = evaluate(_prompt("Summarize this doc" + ZWSP * 8 + "for me"), Policy())
    assert d.blocked
    assert d.rule == "hidden-unicode-zerowidth"


def test_chained_variation_selector_run_blocked():
    d = evaluate(_prompt("Summarize this doc" + (VS15 + VS16) * 4 + "for me"), Policy())
    assert d.blocked
    assert d.rule == "hidden-unicode-variation"


def test_single_variation_selector_allowed_no_false_positive():
    # A single presentation-style selector after a base char (e.g. an emoji's
    # text-vs-emoji form) is everyday usage, not stego — must not be flagged.
    assert not evaluate(_prompt(f"heart emoji ❤{VS16} looks great"), Policy()).blocked


def test_single_zero_width_char_allowed_no_false_positive():
    # A lone ZWJ (e.g. inside a copied emoji sequence) is ordinary, not a stego
    # payload — must not be flagged.
    assert not evaluate(_prompt(f"family emoji test {ZWJ} ok"), Policy()).blocked


def test_short_zero_width_run_allowed():
    # Below the 6-char run threshold -> allowed.
    short_run = ZWSP + ZWNJ + ZWJ
    assert not evaluate(_prompt("text" + short_run + "more"), Policy()).blocked


def test_subdivision_flag_emoji_allowed_no_false_positive():
    # A real, standardized flag (Scotland/England/Wales) lives entirely inside
    # the tag-block range HIDDEN_TAG_RE otherwise covers — must not be flagged.
    d = evaluate(_prompt(f"I'm proud to be from Scotland {SCOTLAND_FLAG}!"), Policy())
    assert not d.blocked


def test_payload_disguised_alongside_real_flag_still_blocked():
    # A hidden payload appended after a legitimate flag must still be caught —
    # the flag carve-out strips only the well-formed flag structure, not every
    # tag-block codepoint in the message.
    d = evaluate(_prompt(f"flag {SCOTLAND_FLAG} and also{TAG_HELLO}"), Policy())
    assert d.blocked
    assert d.rule == "hidden-unicode-tag-chars"


def test_malformed_flag_lookalike_still_blocked():
    # Right bookends (flag + cancel tag) but a payload substituted for the tag
    # letters must not slip through as "looks like a flag".
    fake = "\U0001F3F4" + TAG_HELLO + chr(0xE007F)
    assert evaluate(_prompt(fake), Policy()).blocked


def test_plain_direction_marks_allowed():
    # LRM/RLM are everyday marks, not override/isolate controls — never flagged.
    assert not evaluate(_prompt(f"mixed text {LRM} continues"), Policy()).blocked


def test_bidi_override_monitored_not_blocked_by_default():
    # Default posture: bidi override is audited, not blocked (rarer but not
    # zero legitimate use).
    assert not evaluate(_prompt(f"reorder me {RLO}here"), Policy()).blocked


def test_bidi_override_deny_mode_blocks():
    pol = Policy(hidden_unicode={"bidi_mode": "deny"})
    d = evaluate(_prompt(f"reorder me {RLO}here"), pol)
    assert d.blocked
    assert d.rule == "hidden-unicode-bidi"


def test_normal_prompt_allowed():
    assert not evaluate(_prompt("Please fix the bug in auth.py"), Policy()).blocked


def test_empty_prompt_allowed():
    assert not evaluate(_prompt(""), Policy()).blocked


def test_other_events_not_scanned():
    # The prompt-scanning rule must not fire outside UserPromptSubmit even if
    # some other event happens to carry the tag characters in an arg.
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Read",
                     args={"file_path": f"notes{TAG_HELLO}.txt"})
    assert not evaluate(ev, Policy()).blocked


def test_inband_aegis_allow_does_not_escape_this_guard(monkeypatch):
    # Unlike the shell guards (evasion/remote-exec/destructive-git), this guard
    # does NOT honor '# aegis-allow' embedded in the scanned text itself: the
    # whole point is that an attacker who fully controls the prompt (a relayed
    # GitHub issue/PR/webhook body) could just as easily append that phrase
    # themselves, with no model cooperation required and no AEGIS_AGENT_NAME
    # guarantee in an unattended headless run. Must stay blocked regardless of
    # whether a spawned-agent identity is set.
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)
    assert evaluate(_prompt(f"do it{TAG_HELLO} # aegis-allow"), Policy()).blocked
    monkeypatch.setenv("AEGIS_AGENT_NAME", "relay-bot")
    assert evaluate(_prompt(f"do it{TAG_HELLO} # aegis-allow"), Policy()).blocked


def test_human_operator_env_override(monkeypatch):
    # The actual escape hatch: an out-of-band env var a human sets BEFORE
    # launch, which nothing embedded in the prompt text can set for itself.
    monkeypatch.setenv("AEGIS_ALLOW_HIDDEN_UNICODE", "1")
    assert not evaluate(_prompt(f"do it{TAG_HELLO}"), Policy()).blocked


def test_agent_cannot_set_its_own_override(monkeypatch):
    monkeypatch.delenv("AEGIS_ALLOW_HIDDEN_UNICODE", raising=False)
    monkeypatch.setenv("AEGIS_AGENT_NAME", "relay-bot")
    assert evaluate(_prompt(f"do it{TAG_HELLO}"), Policy()).blocked


def test_mode_off_disables_tag_variation_and_zerowidth():
    pol = Policy(hidden_unicode={"mode": "off"})
    assert not evaluate(_prompt(f"do it{TAG_HELLO}"), pol).blocked
    assert not evaluate(_prompt("x" + ZWSP * 8 + "y"), pol).blocked
    assert not evaluate(_prompt("x" + (VS15 + VS16) * 4 + "y"), pol).blocked


def test_monitor_mode_allows_and_records_the_projected_denial(tmp_path, monkeypatch):
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AEGIS_AUDIT", str(audit))
    pol = Policy(hidden_unicode={"mode": "monitor"})
    d = evaluate(_prompt(f"do it{TAG_HELLO}"), pol)
    assert d.action == Action.ALLOW
    rows = [json.loads(l) for l in audit.read_text().splitlines() if l.strip()]
    monitor = [r for r in rows if r.get("rule") == "hidden-unicode-tag-chars-monitor"]
    assert monitor and monitor[0]["decision"] == "deny"


def test_bidi_monitor_mode_records_the_projected_denial(tmp_path, monkeypatch):
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AEGIS_AUDIT", str(audit))
    pol = Policy(hidden_unicode={"bidi_mode": "monitor"})
    d = evaluate(_prompt(f"reorder me {RLO}here"), pol)
    assert d.action == Action.ALLOW
    rows = [json.loads(l) for l in audit.read_text().splitlines() if l.strip()]
    monitor = [r for r in rows if r.get("rule") == "hidden-unicode-bidi-monitor"]
    assert monitor and monitor[0]["decision"] == "deny"


def test_claude_code_adapter_surfaces_prompt_field():
    ev = cc.parse_event({
        "hook_event_name": "UserPromptSubmit",
        "prompt": f"hi{TAG_HELLO}",
        "session_id": "s1",
    })
    assert ev.event == HookEvent.USER_PROMPT_SUBMIT
    assert ev.args["prompt"] == f"hi{TAG_HELLO}"
    assert evaluate(ev, Policy()).blocked


def test_claude_code_render_deny_blocks_user_prompt_submit():
    ev = cc.parse_event({
        "hook_event_name": "UserPromptSubmit", "prompt": f"hi{TAG_HELLO}",
    })
    code, out, err = cc.render_decision(ev, evaluate(ev, Policy()))
    assert code == 2 and "Hidden Unicode" in err
