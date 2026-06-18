"""AEGI-2: Claude Code adapter — payload parsing + decision rendering."""
import json

from aegis.events import HookEvent
from aegis.policy import Policy, Rule, Action
from aegis.engine import evaluate
from aegis.adapters import claude_code as cc


def test_parse_event_maps_cc_payload():
    ev = cc.parse_event({
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"}, "session_id": "s1", "cwd": "/repo",
    })
    assert ev.event == HookEvent.PRE_TOOL_USE
    assert ev.tool == "Bash"
    assert ev.args["command"] == "rm -rf /"
    assert ev.session_id == "s1" and ev.cwd == "/repo"
    assert ev.action.value == "shell"


def test_render_deny_blocks_with_exit_2():
    ev = cc.parse_event({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}})
    pol = Policy(rules=[Rule(name="no-shell", action=Action.DENY,
                             actions=["shell"], message="nope")])
    code, out, err = cc.render_decision(ev, evaluate(ev, pol))
    assert code == 2 and "nope" in err and out == ""


def test_render_allow_is_exit_0_silent():
    ev = cc.parse_event({"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {}})
    code, out, err = cc.render_decision(ev, evaluate(ev, Policy()))
    assert code == 0 and out == "" and err == ""


def test_render_ask_emits_permission_json():
    ev = cc.parse_event({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}})
    pol = Policy(rules=[Rule(name="ask-shell", action=Action.ASK,
                             actions=["shell"], message="confirm?")])
    code, out, err = cc.render_decision(ev, evaluate(ev, pol))
    assert code == 0
    data = json.loads(out)
    assert data["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert data["hookSpecificOutput"]["permissionDecisionReason"] == "confirm?"


def test_deny_on_post_tool_use_cannot_block():
    ev = cc.parse_event({"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {}})
    pol = Policy(rules=[Rule(name="d", action=Action.DENY, actions=["shell"])])
    code, out, err = cc.render_decision(ev, evaluate(ev, pol))
    assert code == 0 and "cannot block" in err
