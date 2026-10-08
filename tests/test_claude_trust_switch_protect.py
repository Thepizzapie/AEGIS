"""Claude Code trust-switch guard — blocks enabling ``disableAllHooks`` (turns
off every hook, Aegis's own included), ``enableAllProjectMcpServers`` or a
non-empty ``enabledMcpjsonServers`` in ``.claude/settings.local.json``.
Value-sensitive: ``false``/``[]`` stay allowed."""
import pytest

from aegis import rules
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(claude_trust_switch={"mode": "deny"})
PATH = "/repo/.claude/settings.local.json"
RULE = "claude-trust-switch-protect"


def _write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write",
                      args={"file_path": path, "content": content})


def _edit(path, new):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                      args={"file_path": path, "new_string": new})


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp(args):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__json__set",
                      action=ActionClass.MCP, args=args)


def _hit(ev, pol=EMPTY):
    d = evaluate(ev, pol)
    return d.rule == RULE


def _rule_hit(ev, pol=EMPTY):
    """Call the rule directly: for shell commands against this file the
    non-escapable self-protect rule fires first in the full pipeline, so the
    shell branch is defense-in-depth and is exercised in isolation."""
    d = rules.rule_claude_trust_switch_protect(ev, pol)
    return d is not None and d.rule == RULE


@pytest.mark.parametrize("content", [
    '{"disableAllHooks": true}',
    '{"disableAllHooks":true}',
    '{\n  "disableAllHooks" :\n  true\n}',
    '{"disableAllHooks": "true"}',
    '{"\\u0064isableAllHooks": true}',
    '{"enableAllProjectMcpServers": true}',
    '{"enabledMcpjsonServers": ["evil"]}',
    '{"enabledMcpjsonServers": [ "evil", "x" ]}',
    '{"model": "x", "nested": {"disableAllHooks": true}}',
])
def test_write_blocked(content):
    d = evaluate(_write(PATH, content), EMPTY)
    assert d.rule == RULE and d.action == Action.ASK
    assert evaluate(_write(PATH, content), DENY).action == Action.DENY
    assert _hit(_edit(PATH, content))


@pytest.mark.parametrize("content", [
    '{"disableAllHooks": false}',
    '{"enableAllProjectMcpServers": false}',
    '{"enabledMcpjsonServers": []}',
    '{"model": "opus", "permissions": {"allow": ["Bash(ls)"]}}',
    '{"note": "disableAllHooks is dangerous"}',
])
def test_benign_allowed(content):
    assert not _hit(_write(PATH, content))


def test_other_path_ignored():
    assert not _hit(_write("/repo/other.json", '{"disableAllHooks": true}'))


@pytest.mark.parametrize("cmd", [
    "echo '{\"disableAllHooks\": true}' > .claude/settings.local.json",
    "echo '{\"enableAllProjectMcpServers\": true}' >> .claude/settings.local.json",
    "jq '.disableAllHooks = true' .claude/settings.local.json | sponge .claude/settings.local.json",
    "jq '.enabledMcpjsonServers += [\"x\"]' .claude/settings.local.json > t && mv t .claude/settings.local.json",
    "cd .claude && echo '{\"disableAllHooks\":true}' > settings.local.json",
])
def test_shell_blocked(cmd):
    assert _rule_hit(_shell(cmd)), cmd


def test_shell_benign():
    assert not _rule_hit(_shell("cat .claude/settings.local.json"))
    assert not _rule_hit(_shell("echo '{\"disableAllHooks\": false}' > .claude/settings.local.json"))
    assert not _rule_hit(_shell("echo hi > notes.txt"))


def test_shell_human_override():
    assert not _rule_hit(_shell("echo '{\"disableAllHooks\": true}' > .claude/settings.local.json # aegis-allow"))


def test_mcp_shapes():
    assert _hit(_mcp({"path": PATH, "content": {"disableAllHooks": True}}))
    assert _hit(_mcp({"path": PATH, "key": "disableAllHooks", "value": True}))
    assert _hit(_mcp({"path": PATH, "key": "enabledMcpjsonServers", "value": ["x"]}))
    assert not _hit(_mcp({"path": PATH, "key": "disableAllHooks", "value": False}))


def test_env_toggle(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CLAUDE_TRUST_SWITCH", "1")
    assert not _hit(_write(PATH, '{"disableAllHooks": true}'))


def test_policy_allow_monitor_off():
    assert not _hit(_write(PATH, '{"disableAllHooks": true}'),
                    Policy(claude_trust_switch={"allow": [r"settings\.local\.json"]}))
    assert not _hit(_write(PATH, '{"disableAllHooks": true}'),
                    Policy(claude_trust_switch={"mode": "monitor"}))
    assert not _hit(_write(PATH, '{"disableAllHooks": true}'),
                    Policy(claude_trust_switch={"mode": "off"}))


def test_loader_roundtrip(tmp_path):
    from aegis.loader import load_policy
    (tmp_path / "p.yaml").write_text("claude_trust_switch:\n  mode: deny\n")
    assert load_policy(tmp_path / "p.yaml").claude_trust_switch == {"mode": "deny"}


def test_perf_adversarial():
    import time
    big = '{"a": "' + "x" * 200000 + '"}'
    t = time.time()
    _hit(_write(PATH, big))
    _hit(_shell("jq " + "a" * 100000 + " .claude/settings.local.json"))
    assert time.time() - t < 2.0
