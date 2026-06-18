"""AEGI-7: adapter registry + generic JSON adapter."""
import json

import pytest

from aegis import adapters
from aegis.adapters import claude_code, generic
from aegis.events import HookEvent
from aegis.policy import Decision, Action


def test_registry_resolves_known():
    assert adapters.get_adapter(None) is claude_code
    assert adapters.get_adapter("claude-code") is claude_code
    assert adapters.get_adapter("CC") is claude_code
    assert adapters.get_adapter("generic") is generic


def test_registry_unknown_raises():
    with pytest.raises(KeyError):
        adapters.get_adapter("nope")


def test_available_lists_adapters():
    av = adapters.available()
    assert "generic" in av and "claude-code" in av


def test_generic_parse_and_render():
    ev = generic.parse_event({"event": "PreToolUse", "tool": "Bash",
                              "args": {"command": "x"}, "roles": ["dev"], "session_id": "s"})
    assert ev.event == HookEvent.PRE_TOOL_USE and ev.tool == "Bash"
    assert ev.action.value == "shell" and ev.roles == ["dev"]

    code, out, _ = generic.render_decision(ev, Decision(Action.DENY, "r", "blocked"))
    assert code == 2
    assert json.loads(out)["decision"] == "deny"
    assert json.loads(out)["message"] == "blocked"

    code2, out2, _ = generic.render_decision(ev, Decision(Action.ALLOW))
    assert code2 == 0 and json.loads(out2)["decision"] == "allow"


def test_generic_unknown_event_defaults_to_pretool():
    ev = generic.parse_event({"event": "Bogus", "tool": "Read"})
    assert ev.event == HookEvent.PRE_TOOL_USE
