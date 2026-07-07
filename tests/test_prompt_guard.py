"""Prompt secret guard (rule_prompt_guard) — the UserPromptSubmit surface.

UserPromptSubmit is one of the original core BLOCKABLE hook points but had no
rule at all before this guard: a live credential typed or smuggled into the raw
prompt had no file path or shell verb for containment/exfil to key off, so it
would silently enter the model's context and (absent redaction) the audit
trail in cleartext. These tests cover: detection across common credential
shapes, non-escapability, policy knobs (mode/allow), the adapter wiring that
surfaces the prompt text at all, and audit-sink redaction as a second layer.
"""
import json

from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Policy
from aegis.rules import rule_prompt_guard
from aegis.adapters import claude_code as cc
from aegis.audit import write_event
from aegis.policy import Decision, Action

EMPTY = Policy()  # default-allow; built-ins still apply


def _prompt(text):
    return Event.make(HookEvent.USER_PROMPT_SUBMIT, args={"prompt": text})


# ---- detection -----------------------------------------------------------------

def test_blocks_aws_access_key():
    assert evaluate(_prompt("here's my key AKIAABCDEFGHIJKLMNOP use it"), EMPTY).blocked


def test_blocks_github_pat():
    assert evaluate(_prompt("token: ghp_" + "a" * 36), EMPTY).blocked
    assert evaluate(_prompt("token: github_pat_" + "b" * 22), EMPTY).blocked


def test_blocks_slack_token():
    assert evaluate(_prompt("xoxb-1234567890-abcdefghij"), EMPTY).blocked


def test_blocks_anthropic_and_openai_style_keys():
    assert evaluate(_prompt("sk-ant-" + "x" * 25), EMPTY).blocked
    assert evaluate(_prompt("sk-" + "y" * 25), EMPTY).blocked


def test_blocks_private_key_block():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----"
    assert evaluate(_prompt(text), EMPTY).blocked


def test_blocks_plain_and_encrypted_pkcs8_key():
    assert evaluate(_prompt("-----BEGIN PRIVATE KEY-----\nMIIB..."), EMPTY).blocked
    assert evaluate(_prompt("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB..."), EMPTY).blocked


def test_blocks_pgp_private_key_block():
    # real OpenPGP ASCII-armor header carries a trailing "BLOCK", unlike PEM
    assert evaluate(_prompt("-----BEGIN PGP PRIVATE KEY BLOCK-----\nxyz"), EMPTY).blocked


def test_blocks_openai_project_and_service_account_keys():
    assert evaluate(_prompt("sk-proj-" + "a" * 25), EMPTY).blocked
    assert evaluate(_prompt("sk-svcacct-" + "b" * 25), EMPTY).blocked


def test_clean_prompt_allowed():
    d = evaluate(_prompt("please refactor this function to be async"), EMPTY)
    assert not d.blocked


def test_empty_prompt_no_opinion():
    assert rule_prompt_guard(_prompt(""), EMPTY) is None
    assert rule_prompt_guard(Event.make(HookEvent.USER_PROMPT_SUBMIT, args={}), EMPTY) is None


def test_only_fires_on_user_prompt_submit():
    # a secret-shaped string in a PreToolUse command is out of this rule's scope
    # (containment/other guards may still have an opinion; not tested here).
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Bash",
                    args={"command": "echo AKIAABCDEFGHIJKLMNOP"})
    assert rule_prompt_guard(ev, EMPTY) is None


# ---- non-escapability ------------------------------------------------------------

def test_not_escapable_with_override_token():
    d = evaluate(_prompt("AKIAABCDEFGHIJKLMNOP  # aegis-allow"), EMPTY)
    assert d.blocked and d.rule == "prompt-secret-guard"


# ---- policy knobs -----------------------------------------------------------------

def test_mode_off_disables():
    p = Policy()
    p.prompt_guard = {"mode": "off"}
    assert not evaluate(_prompt("AKIAABCDEFGHIJKLMNOP"), p).blocked


def test_mode_monitor_records_without_blocking(tmp_path, monkeypatch):
    from aegis import config
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    p = Policy()
    p.prompt_guard = {"mode": "monitor"}
    d = evaluate(_prompt("AKIAABCDEFGHIJKLMNOP"), p)
    assert not d.blocked
    audit_path = config.audit_path()
    assert audit_path.exists()
    rows = [json.loads(x) for x in audit_path.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert any(r.get("rule") == "prompt-secret-guard-monitor" for r in rows)


def test_invalid_mode_value_fails_closed():
    # a typo'd/unknown mode string falls through to the deny branch rather than
    # silently allowing — fail-closed, not fail-open.
    p = Policy()
    p.prompt_guard = {"mode": "not-a-real-mode"}
    assert evaluate(_prompt("AKIAABCDEFGHIJKLMNOP"), p).blocked


def test_allow_list_exempts_matching_prompt():
    p = Policy()
    p.prompt_guard = {"allow": [r"AKIAABCDEFGHIJKLMNOP"]}
    assert not evaluate(_prompt("test fixture: AKIAABCDEFGHIJKLMNOP"), p).blocked
    # a different key not covered by the allow regex is still blocked
    assert evaluate(_prompt("AKIAZZZZZZZZZZZZZZZZ"), p).blocked


# ---- adapter wiring: the prompt must actually reach Event.args ------------------

def test_adapter_surfaces_prompt_text():
    ev = cc.parse_event({"hook_event_name": "UserPromptSubmit",
                         "prompt": "hello", "session_id": "s1"})
    assert ev.event == HookEvent.USER_PROMPT_SUBMIT
    assert ev.args["prompt"] == "hello"


def test_adapter_deny_blocks_user_prompt_submit():
    ev = cc.parse_event({"hook_event_name": "UserPromptSubmit",
                         "prompt": "AKIAABCDEFGHIJKLMNOP"})
    code, out, err = cc.render_decision(ev, evaluate(ev, EMPTY))
    assert code == 2 and "[Aegis]" in err


# ---- audit redaction: never persist a live secret in cleartext -----------------

def test_write_event_redacts_secret_in_args(tmp_path):
    path = tmp_path / "audit.jsonl"
    ev = _prompt("my key is AKIAABCDEFGHIJKLMNOP, please use it")
    write_event(ev, Decision(Action.DENY, "prompt-secret-guard", "blocked"), str(path))
    row = json.loads(path.read_text(encoding="utf-8").strip())
    assert "AKIAABCDEFGHIJKLMNOP" not in json.dumps(row)
    assert "redacted" in row["args"]["prompt"]


def test_write_event_redacts_secret_in_output(tmp_path):
    path = tmp_path / "audit.jsonl"
    ev = Event.make(HookEvent.POST_TOOL_USE, tool="Bash", args={"command": "cat token.txt"},
                    raw={"tool_response": "token=AKIAABCDEFGHIJKLMNOP"})
    write_event(ev, Decision(Action.ALLOW), str(path))
    row = json.loads(path.read_text(encoding="utf-8").strip())
    assert "AKIAABCDEFGHIJKLMNOP" not in json.dumps(row)


def test_write_event_redacts_before_truncating_long_output(tmp_path):
    # Regression: a secret sitting right at the _MAX_OUTPUT_CHARS cut point must
    # be redacted BEFORE truncation, not after — redacting a chopped fragment
    # would drop it below SECRET_RE's length requirement and leak a partial key.
    from aegis import audit as audit_mod
    path = tmp_path / "audit.jsonl"
    secret = "AKIAABCDEFGHIJKLMNOP"
    padding = "x" * (audit_mod._MAX_OUTPUT_CHARS - 5)
    ev = Event.make(HookEvent.POST_TOOL_USE, tool="Bash", args={"command": "cat token.txt"},
                    raw={"tool_response": padding + secret})
    write_event(ev, Decision(Action.ALLOW), str(path))
    row = json.loads(path.read_text(encoding="utf-8").strip())
    assert secret not in json.dumps(row)
