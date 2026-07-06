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
PRIVATE_KEY_BODY = "MIIEowSuperSecretBase64KeyMaterialGoesHere=="
PRIVATE_KEY = f"-----BEGIN RSA PRIVATE KEY-----\n{PRIVATE_KEY_BODY}\n-----END RSA PRIVATE KEY-----"
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


# ---- QA-review regressions: redaction must remove the WHOLE secret --------------

def test_redact_secrets_removes_entire_private_key_body_not_just_header():
    """Adversarial-review finding: the old private-key-block regex matched only
    the BEGIN header line, leaving the base64 key material to survive
    redaction (and land in Aegis's own audit log) untouched."""
    redacted, labels = patterns.redact_secrets(f"here is the key: {PRIVATE_KEY} thanks")
    assert labels == ["private-key-block"]
    assert PRIVATE_KEY_BODY not in redacted
    assert "-----END RSA PRIVATE KEY-----" not in redacted
    assert "here is the key:" in redacted and "thanks" in redacted


def test_private_key_header_only_still_detected_when_truncated():
    """A truncated paste (header with no END marker) must still trip detection
    even though there's nothing to redact through to."""
    assert "private-key-block" in patterns.find_secrets(
        "oops I pasted -----BEGIN RSA PRIVATE KEY----- and then got scared")


def test_redact_secrets_removes_punctuated_generic_assignment_value():
    """Adversarial-review finding: the old generic-assignment charset
    (alnum/+-/=  only) stopped at the first punctuation character, leaving the
    rest of a real password/secret in the clear after 'redaction'."""
    value = "abc123def456ghijklmnop!SuperSecretTail42"
    redacted, labels = patterns.redact_secrets(f"password = '{value}' is not working")
    assert labels == ["generic-assignment"]
    assert value not in redacted
    assert "SuperSecretTail42" not in redacted


# ---- QA-review regressions: placeholder/example values must not false-positive --

@pytest.mark.parametrize("text", [
    "our docs use AKIAIOSFODNN7EXAMPLE as the sample access key id",  # AWS's own example
    "SECRET_KEY = 'django-insecure-abc123def456ghi789jkl012mno345pqr'",  # Django dev default
    "API_KEY=your_api_key_here_1234567890abcdef",  # .env.example placeholder
    "password = 'changeme1234567890'",  # placeholder discussion
    "api_key: 'test_fake_1234567890abcdef_dummy'",
])
def test_placeholder_and_example_values_not_flagged(text):
    assert patterns.find_secrets(text) == []


def test_case_flipped_secret_still_detected():
    """Adversarial-review finding: only generic-assignment was case-insensitive;
    a lower-cased AWS key sailed through undetected (a zero-cost bypass)."""
    assert "aws-access-key" in patterns.find_secrets(f"key: {AWS_KEY.lower()}")


@pytest.mark.parametrize("text", [
    "password = 'contest9876543210XYZlivevalue'",
    "api_key = 'myProtestSecretValue1234567890'",
    "secret_key: 'fastestLiveTokenValue1234567890'",
    "auth_token = 'attestSignatureValue1234567890XY'",
])
def test_placeholder_word_as_substring_of_real_word_still_flagged(text):
    """Second-round adversarial-review finding: the first placeholder fix did a
    plain unbounded substring search, so a REAL secret that merely contains
    'test'/'fake' as part of an unrelated English word ('contest', 'protest',
    'fastest', 'attest') was wrongly exempted. A leading-word-boundary check
    must still flag these — the placeholder word is glued onto a preceding
    word character with no boundary, unlike a genuine 'test_...'/'...changeme'
    placeholder."""
    assert "generic-assignment" in patterns.find_secrets(text)


def test_redact_secrets_merges_partial_non_nested_overlap_completely():
    """Third-round adversarial-review finding: the drop-on-overlap strategy
    only protected against corruption, not content loss. A gitlab-token match
    (chars 0-26) and a generic-assignment match (chars 18-47) partially
    overlap with NEITHER containing the other; dropping the later-sorted one
    left its uncovered tail (a real secret value) surviving redaction in the
    clear. Overlapping spans must be MERGED (union), never dropped."""
    text = "glpat-aaaaaaaaaaa-password=cccccccccccccccccccc"
    labels = patterns.find_secrets(text)
    assert "gitlab-token" in labels and "generic-assignment" in labels
    redacted, _ = patterns.redact_secrets(text)
    assert "cccccccccccccccccccc" not in redacted
    assert "aaaaaaaaaaa" not in redacted


@pytest.mark.parametrize("value", [
    "ghp_" + "a" * 40 + "example",
    "sk-" + "a" * 40 + "example",
    "glpat-" + "a" * 25 + "example",
])
def test_appending_example_suffix_does_not_launder_a_real_secret(value):
    """Third-round adversarial-review finding: an earlier fix exempted any
    match ending in the literal text 'example' (to catch AWS's own
    AKIAIOSFODNN7EXAMPLE convention), but that suffix check applied uniformly
    to every open-ended pattern — a universal, delimiter-free bypass letting
    anyone exempt a real secret just by appending 'example' to it. Only the
    ONE known exact AWS constant may be exempted this way, never a generic
    suffix rule."""
    assert patterns.find_secrets(f"here: {value}") != []


def test_known_aws_example_constant_still_exempt():
    assert patterns.find_secrets("AKIAIOSFODNN7EXAMPLE") == []


def test_redact_secrets_handles_overlapping_matches_without_corruption():
    """Second-round adversarial-review finding: redact_secrets' back-to-front
    splice assumed non-overlapping spans. generic-assignment's greedy value
    class swallows a whole 'access_token = <jwt>' assignment, nesting the jwt
    pattern's own match inside it; splicing both against the same string at
    their original offsets corrupted the output and destroyed trailing text
    (including an unrelated, later, non-overlapping secret in the same
    string)."""
    text = (f"access_token = {JWT} and my key is {AWS_KEY} thanks")
    redacted, labels = patterns.redact_secrets(text)
    assert "generic-assignment" in labels
    assert "aws-access-key" in labels
    assert JWT not in redacted
    assert AWS_KEY not in redacted
    assert redacted.endswith("thanks")
    assert "and my key is" in redacted


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


def test_incidental_mention_of_override_phrase_does_not_disable_detection():
    """Blocker finding from adversarial QA: the shared OVERRIDE_RE does a bare
    substring search, so a prompt that merely DISCUSSES the escape phrase
    (asking about Aegis's own docs, pasting rules.py for review) used to
    silently allow an unrelated real secret anywhere else in the same prompt.
    The trailing-anchored PROMPT_OVERRIDE_RE must reject this."""
    text = ("I was reading the aegis docs and saw the override syntax "
            "'# aegis-allow' is used to bypass guards. Separately, unrelated: "
            f"can you help me debug why boto3 rejects my key {AWS_KEY}?")
    assert evaluate(_prompt(text), EMPTY).blocked


def test_override_must_be_trailing_not_merely_present():
    assert evaluate(_prompt(f"# aegis-allow, ignore that, real question: {AWS_KEY}"),
                     EMPTY).blocked
    assert not evaluate(_prompt(f"{AWS_KEY}  # aegis-allow"), EMPTY).blocked


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


def test_adapter_top_level_prompt_is_authoritative_over_tool_input():
    """The top-level `prompt` field is the real submitted text per the hook
    contract, so it wins over anything incidentally already in `tool_input`
    (Claude Code never actually populates tool_input for this event, but the
    adapter must not let a stray/incidental value there shadow the field the
    whole guard exists to see)."""
    ev = cc.parse_event({
        "hook_event_name": "UserPromptSubmit",
        "tool_input": {"prompt": "from-tool-input"},
        "prompt": "from-top-level",
    })
    assert ev.args["prompt"] == "from-top-level"


# ---- QA-review: scan is bounded (mirrors normalize.py's shell-scan cap) --------

def test_secret_within_scan_cap_detected_beyond_it_is_a_documented_gap():
    """rule fires on every UserPromptSubmit, so an unbounded scan would add
    unbounded latency to a huge paste (a forwarded log/webhook body) — capped
    like normalize.py's shell-command scan, for the same reason. A secret
    inside the cap is caught; one placed well beyond it is a documented scope
    boundary, not scanned."""
    near = "x " * 50 + AWS_KEY
    assert "aws-access-key" in patterns.find_secrets(near)
    far = "x " * ((patterns._MAX_SCAN // 2) + 1000) + AWS_KEY
    assert "aws-access-key" not in patterns.find_secrets(far)


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


def test_no_agent_skill_hint_on_user_prompt_submit_denial(tmp_path, monkeypatch):
    """A UserPromptSubmit denial's stderr is shown to the HUMAN who typed the
    prompt, before any agent turn is in progress — the agent-facing
    aegis-explain-block hint (meant for a mid-turn tool-call denial) would be
    dead advice here, even when the skill happens to be installed."""
    skill_dir = tmp_path / ".claude" / "skills" / "aegis-explain-block"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("stub", encoding="utf-8")
    ev = cc.parse_event({
        "hook_event_name": "UserPromptSubmit",
        "prompt": AWS_KEY,
        "cwd": str(tmp_path),
    })
    d = evaluate(ev, EMPTY)
    _, _, err = cc.render_decision(ev, d)
    assert "aegis-explain-block" not in err
