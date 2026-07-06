"""Prompt secret-leak guard (aegis.rules.rule_prompt_secret_leak, on
UserPromptSubmit) + its supporting pieces: aegis.patterns.SECRET_PATTERNS /
find_secrets / redact_secrets, and the Claude Code adapter's prompt-text
extraction (adapters.claude_code.parse_event).

The reliability property under test: a submitted prompt carrying a live-looking
secret is blocked BEFORE it reaches the model, the denial never echoes the
matched value, a spawned agent cannot wave it through, and the raw secret is
scrubbed from the event before Aegis's own audit write.
"""
import pytest

from aegis import patterns
from aegis.adapters import claude_code as cc
from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()

AWS_KEY = "AKIAABCDEFGHIJKLMNOP"
GITHUB_TOKEN = "ghp_" + "a" * 36
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----"
SLACK_TOKEN = "xoxb-" + "1" * 12
ANTHROPIC_KEY = "sk-ant-" + "a" * 30
OPENAI_KEY = "sk-" + "a" * 40
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGhpc2lzYXNpZ25hdHVyZQ"


def _prompt(text, session="s1"):
    return Event.make(HookEvent.USER_PROMPT_SUBMIT, args={"prompt": text}, session_id=session)


# ---- pattern layer --------------------------------------------------------------

@pytest.mark.parametrize("label,value", [
    ("aws-access-key", AWS_KEY),
    ("private-key-block", PRIVATE_KEY),
    ("github-token", GITHUB_TOKEN),
    ("gitlab-token", "glpat-" + "a" * 22),
    ("slack-token", SLACK_TOKEN),
    ("slack-webhook", "https://hooks.slack.com/services/T00000000/B00000000/" + "x" * 24),
    ("anthropic-key", ANTHROPIC_KEY),
    ("openai-key", OPENAI_KEY),
    ("google-api-key", "AIza" + "a" * 35),
    ("stripe-key", "sk_live_" + "a" * 20),
    ("jwt", JWT),
    ("generic-assignment", 'api_key = "abcdefghijklmnopqrstuvwx"'),
])
def test_find_secrets_matches_each_shape(label, value):
    assert label in patterns.find_secrets(f"here you go: {value} thanks")


def test_openai_pattern_does_not_shadow_anthropic():
    """sk-ant-... must be labeled anthropic-key, not swallowed by the broader
    sk-... openai pattern (both start with 'sk-')."""
    labels = patterns.find_secrets(ANTHROPIC_KEY)
    assert "anthropic-key" in labels
    assert "openai-key" not in labels


@pytest.mark.parametrize("text", [
    "why is this test failing, here is the stack trace",
    "my password is not going to be embarrassing, promise",
    "sk-8",
    "the api_key field on the settings form is empty",
    "explain how JWT auth works in general",
])
def test_find_secrets_no_false_positive_on_ordinary_text(text):
    assert patterns.find_secrets(text) == []


def test_redact_secrets_replaces_value_not_whole_text():
    redacted, labels = patterns.redact_secrets(f"my key is {AWS_KEY} thanks")
    assert labels == ["aws-access-key"]
    assert AWS_KEY not in redacted
    assert "my key is" in redacted and "thanks" in redacted
    assert "[aegis-redacted:aws-access-key]" in redacted


def test_redact_secrets_noop_on_clean_text():
    text = "nothing sensitive here"
    redacted, labels = patterns.redact_secrets(text)
    assert redacted == text and labels == []


# ---- rule: deny by default -------------------------------------------------------

def test_aws_key_in_prompt_blocked():
    d = evaluate(_prompt(f"my key is {AWS_KEY}, why does auth fail?"), EMPTY)
    assert d.blocked and d.rule == "prompt-secret-leak"


def test_private_key_in_prompt_blocked():
    assert evaluate(_prompt(f"paste: {PRIVATE_KEY}"), EMPTY).blocked


def test_multiple_secret_types_all_named_in_message():
    d = evaluate(_prompt(f"{AWS_KEY} and also {GITHUB_TOKEN}"), EMPTY)
    assert d.blocked
    assert "aws-access-key" in d.message and "github-token" in d.message


def test_denial_message_never_echoes_the_matched_secret():
    d = evaluate(_prompt(f"my key is {AWS_KEY}"), EMPTY)
    assert d.blocked
    assert AWS_KEY not in d.message


def test_ordinary_prompt_allowed():
    assert not evaluate(_prompt("can you help me fix this failing test?"), EMPTY).blocked


def test_empty_or_whitespace_prompt_allowed():
    assert not evaluate(_prompt(""), EMPTY).blocked
    assert not evaluate(_prompt("   "), EMPTY).blocked


def test_other_events_not_affected():
    """The guard only fires on UserPromptSubmit — a tool call whose args happen
    to carry a 'prompt'-shaped value elsewhere must not be caught by this rule."""
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Bash",
                     args={"command": f"echo {AWS_KEY}"})
    d = evaluate(ev, EMPTY)
    assert d.rule != "prompt-secret-leak"


# ---- redaction side-effect on the event (audit-trail hygiene) -------------------

def test_secret_redacted_in_place_on_the_event_after_deny():
    ev = _prompt(f"secret {AWS_KEY} end")
    evaluate(ev, EMPTY)
    assert AWS_KEY not in ev.args["prompt"]
    assert "[aegis-redacted:aws-access-key]" in ev.args["prompt"]


def test_secret_redacted_in_place_even_under_monitor_mode():
    pol = Policy(secrets={"mode": "monitor"})
    ev = _prompt(f"secret {AWS_KEY} end")
    d = evaluate(ev, pol)
    assert not d.blocked
    assert AWS_KEY not in ev.args["prompt"]


# ---- human override vs. spawned-agent enforcement --------------------------------

def test_human_can_override_with_comment():
    assert not evaluate(_prompt(f"{AWS_KEY}  # aegis-allow"), EMPTY).blocked


def test_spawned_agent_cannot_override_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert evaluate(_prompt(f"{AWS_KEY}  # aegis-allow"), EMPTY).blocked


# ---- policy config: mode + allow -------------------------------------------------

def test_monitor_mode_logs_and_allows():
    pol = Policy(secrets={"mode": "monitor"})
    assert not evaluate(_prompt(AWS_KEY), pol).blocked


def test_off_mode_disables_guard():
    pol = Policy(secrets={"mode": "off"})
    assert not evaluate(_prompt(AWS_KEY), pol).blocked


def test_policy_allow_regex_exempts_specific_fixture():
    pol = Policy(secrets={"allow": [r"AKIAABCDEFGHIJKLMNOP"]})
    assert not evaluate(_prompt(f"our test fixture key is {AWS_KEY}"), pol).blocked
    # the exemption is specific to that value; a different real-shaped key
    # elsewhere in the same policy still trips the guard
    assert evaluate(_prompt(GITHUB_TOKEN), pol).blocked


# ---- adapter wiring: UserPromptSubmit must actually carry the prompt text -------

def test_adapter_extracts_prompt_field_for_user_prompt_submit():
    ev = cc.parse_event({
        "hook_event_name": "UserPromptSubmit",
        "prompt": f"here is my key {AWS_KEY}",
        "session_id": "s1",
    })
    assert ev.event == HookEvent.USER_PROMPT_SUBMIT
    assert ev.args["prompt"] == f"here is my key {AWS_KEY}"


def test_adapter_prompt_extraction_does_not_clobber_tool_input():
    """Additive only: a runtime that somehow sent both tool_input and a prompt
    key keeps its tool_input-derived args as the source of truth."""
    ev = cc.parse_event({
        "hook_event_name": "UserPromptSubmit",
        "tool_input": {"prompt": "from-tool-input"},
        "prompt": "from-top-level",
    })
    assert ev.args["prompt"] == "from-tool-input"


def test_end_to_end_adapter_to_render_blocks_and_hides_secret():
    ev = cc.parse_event({
        "hook_event_name": "UserPromptSubmit",
        "prompt": f"my key is {AWS_KEY}",
        "session_id": "s1",
    })
    d = evaluate(ev, EMPTY)
    code, out, err = cc.render_decision(ev, d)
    assert code == 2
    assert AWS_KEY not in err
    assert AWS_KEY not in out
