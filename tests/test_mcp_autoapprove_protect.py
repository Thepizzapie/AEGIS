"""Project-MCP auto-approval guard — blocks planting ``enableAllProjectMcpServers:
true`` or a non-empty ``enabledMcpjsonServers`` list in
``.claude/settings.local.json``, which pre-answers Claude Code's one-time
approval prompt for project ``.mcp.json`` servers."""
import json

from aegis import rules
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(mcp_autoapprove={"mode": "deny"})
P = ".claude/settings.local.json"
ALL = '{"enableAllProjectMcpServers": true}'
LST = '{"enabledMcpjsonServers": ["evil"]}'


def _edit(path, s):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit", args={"file_path": path, "new_string": s})


def _write(path, c):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write", args={"file_path": path, "content": c})


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp(path, **kw):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__x", action=ActionClass.MCP,
                      args={"path": path, **kw})


def _rule(d):
    return getattr(d, "rule", None)


def hit(ev, pol=EMPTY):
    # Call the rule directly: shell writes to settings.local.json are also
    # caught earlier (non-escapably) by self-protect, which would mask this guard.
    d = rules.rule_mcp_autoapprove_protect(ev, pol)
    return d is not None and _rule(d) == "mcp-autoapprove-protect"


def test_write_enable_all_asks():
    assert evaluate(_write(P, ALL), EMPTY).action == Action.ASK
    assert hit(_write(P, ALL))


def test_edit_fragment_and_list():
    assert hit(_edit(P, '"enableAllProjectMcpServers": true,'))
    assert hit(_edit(P, '"enabledMcpjsonServers": ["a"]'))
    assert hit(_write("/home/u/proj/.claude/settings.local.json", LST))


def test_deny_mode():
    assert evaluate(_write(P, ALL), DENY).action == Action.DENY


def test_benign_values_pass():
    for c in ('{"enableAllProjectMcpServers": false}', '{"enabledMcpjsonServers": []}',
              '{"permissions": {"allow": ["Bash(ls)"]}}'):
        assert not hit(_write(P, c)), c


def test_other_file_ignored():
    assert not hit(_write("notes/settings.json", ALL))
    assert not hit(_write("package.json", ALL))


def test_unicode_escape_fragment():
    assert hit(_edit(P, '"\\u0065nableAllProjectMcpServers": true'))


def test_empty_string_list_benign():
    assert not hit(_write(P, '{"enabledMcpjsonServers": [""]}'))


def test_string_true_and_whitespace():
    assert hit(_write(P, '{"enableAllProjectMcpServers" :\n "true"}'))


def test_mcp_nested_and_flat():
    assert hit(_mcp(P, content=json.dumps({"enableAllProjectMcpServers": True})))
    assert hit(_mcp(P, data={"enabledMcpjsonServers": ["x"]}))
    assert hit(_mcp(P, key="enableAllProjectMcpServers", value=True))
    assert hit(_mcp(P, key="enabledMcpjsonServers", value=["x"]))
    assert not hit(_mcp(P, key="enableAllProjectMcpServers", value=False))
    assert not hit(_mcp(P, key="enabledMcpjsonServers", value=[]))


def test_shell_redirect_and_jq():
    assert hit(_shell("echo '{\"enableAllProjectMcpServers\": true}' > .claude/settings.local.json"))
    assert hit(_shell("jq '.enableAllProjectMcpServers=true' .claude/settings.local.json | sponge .claude/settings.local.json"))
    assert hit(_shell("jq '.enabledMcpjsonServers += [\"x\"]' .claude/settings.local.json | sponge .claude/settings.local.json"))
    assert hit(_shell("cd .claude && echo '{\"enableAllProjectMcpServers\":true}' > settings.local.json"))


def test_shell_read_only_passes():
    assert not hit(_shell("cat .claude/settings.local.json"))
    assert not hit(_shell("echo enableAllProjectMcpServers"))


def test_escape_hatches(monkeypatch):
    assert not hit(_shell("echo '{\"enableAllProjectMcpServers\": true}' > .claude/settings.local.json # aegis-allow"))
    assert not hit(_write(P, ALL), Policy(mcp_autoapprove={"allow": [r"settings\.local"]}))
    assert not hit(_write(P, ALL), Policy(mcp_autoapprove={"mode": "off"}))
    monkeypatch.setenv("AEGIS_ALLOW_MCP_AUTOAPPROVE", "1")
    assert not hit(_write(P, ALL))


def test_monitor_mode_allows():
    assert not hit(_write(P, ALL), Policy(mcp_autoapprove={"mode": "monitor"}))


def test_loader_wires_knob(tmp_path):
    from aegis.loader import load_policy
    f = tmp_path / "p.yaml"
    f.write_text("mcp_autoapprove:\n  mode: deny\n")
    assert load_policy(f).mcp_autoapprove == {"mode": "deny"}
