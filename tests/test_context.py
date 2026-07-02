"""Context-injection tests (aegis.context + adapter render_context + CLI wiring).

The reliability property under test: the policy posture is re-injected after the
two points where it can be absent from the model's context — session start and
context compaction — and nowhere else, unless policy opts out.
"""
import json

from aegis import cli, context
from aegis.adapters import claude_code
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy


def _ev(name):
    return Event(event=name)


# ---- should_inject -------------------------------------------------------------

def test_injects_on_session_start_and_post_compact_by_default():
    p = Policy()
    assert context.should_inject(_ev(HookEvent.SESSION_START), p)
    assert context.should_inject(_ev(HookEvent.POST_COMPACT), p)


def test_does_not_inject_on_other_events():
    p = Policy()
    for name in (HookEvent.PRE_TOOL_USE, HookEvent.POST_TOOL_USE,
                 HookEvent.STOP, HookEvent.USER_PROMPT_SUBMIT,
                 HookEvent.PRE_COMPACT, HookEvent.SESSION_END):
        assert not context.should_inject(_ev(name), p), name


def test_inject_mode_off_disables():
    p = Policy()
    p.inject = {"mode": "off"}
    assert not context.should_inject(_ev(HookEvent.SESSION_START), p)
    assert not context.should_inject(_ev(HookEvent.POST_COMPACT), p)


def test_should_inject_fail_safe_on_broken_policy():
    class Boom:
        @property
        def inject(self):
            raise RuntimeError("boom")

    assert context.should_inject(_ev(HookEvent.SESSION_START), Boom()) is False


# ---- compose --------------------------------------------------------------------

def test_compose_states_posture_and_default_action():
    p = Policy(default_action=Action.DENY)
    text = context.compose(p)
    assert "[Aegis]" in text
    assert "default_action=deny" in text
    assert "audit" in text.lower()


def test_compose_reflects_active_optins():
    p = Policy()
    p.team = {"require_verification": True}
    p.completion = {"require_tests": True}
    p.workspace = {"root": "/srv/app"}
    p.egress = {"default": "deny"}
    text = context.compose(p)
    assert "verification" in text
    assert "test run" in text
    assert "/srv/app" in text
    assert "deny-by-default" in text


def test_compose_mentions_failure_loop_unless_off():
    on = context.compose(Policy())
    assert "failed 3x" in on
    p = Policy()
    p.failures = {"mode": "off"}
    assert "failed 3x" not in context.compose(p)


def test_compose_never_raises():
    class Boom:
        def __getattr__(self, name):
            raise RuntimeError("boom")

    assert context.compose(Boom()) == ""


# ---- adapter render_context ------------------------------------------------------

def test_render_context_shape():
    out = claude_code.render_context(_ev(HookEvent.SESSION_START), "the rules")
    data = json.loads(out)
    hso = data["hookSpecificOutput"]
    assert hso["hookEventName"] == "SessionStart"
    assert hso["additionalContext"] == "the rules"


def test_render_context_empty_text_yields_nothing():
    assert claude_code.render_context(_ev(HookEvent.POST_COMPACT), "") == ""


# ---- CLI wiring (end to end through _cmd_hook) -----------------------------------

class _FakeBuffer:
    def __init__(self, data: bytes):
        self._data = data

    def read(self) -> bytes:
        return self._data


class _FakeStdin:
    def __init__(self, data: bytes):
        self.buffer = _FakeBuffer(data)

    def isatty(self) -> bool:
        return False


class _Args:
    def __init__(self, event):
        self.event = event
        self.runtime = None


def _fire(monkeypatch, tmp_path, event, payload=b"{}"):
    monkeypatch.setenv("AEGIS_AUDIT", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("AEGIS_POLICIES", str(tmp_path))  # empty -> defaults
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)
    monkeypatch.setattr("sys.stdin", _FakeStdin(payload))
    return cli._cmd_hook(_Args(event))


def test_cli_injects_on_session_start(monkeypatch, tmp_path, capsys):
    rc = _fire(monkeypatch, tmp_path, "SessionStart")
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert "[Aegis]" in data["hookSpecificOutput"]["additionalContext"]
    assert data["hookSpecificOutput"]["hookEventName"] == "SessionStart"


def test_cli_injects_on_post_compact(monkeypatch, tmp_path, capsys):
    rc = _fire(monkeypatch, tmp_path, "PostCompact")
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["hookSpecificOutput"]["hookEventName"] == "PostCompact"


def test_cli_does_not_inject_on_pre_tool_use(monkeypatch, tmp_path, capsys):
    payload = b'{"tool_name":"Read","tool_input":{"file_path":"README.md"}}'
    rc = _fire(monkeypatch, tmp_path, "PreToolUse", payload)
    assert rc == 0
    assert capsys.readouterr().out == ""


def test_cli_respects_inject_off(monkeypatch, tmp_path, capsys):
    (tmp_path / "policy.yaml").write_text("inject:\n  mode: off\n",
                                          encoding="utf-8")
    rc = _fire(monkeypatch, tmp_path, "SessionStart")
    assert rc == 0
    assert capsys.readouterr().out == ""


def test_loader_roundtrips_inject_knob(tmp_path):
    from aegis.loader import load_policy
    # YAML 1.1 parses unquoted `off` as boolean False — the loader keeps it and
    # should_inject accepts both spellings.
    (tmp_path / "policy.yaml").write_text("inject:\n  mode: off\n",
                                          encoding="utf-8")
    p = load_policy(tmp_path)
    assert p.inject == {"mode": False}
    assert not context.should_inject(_ev(HookEvent.SESSION_START), p)
