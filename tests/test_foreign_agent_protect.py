"""Foreign-agent runtime protection -- blocks stepping outside Aegis through
ANOTHER AI coding agent: launching its CLI with approvals/sandbox off
(``gemini --yolo``, ``codex --dangerously-bypass-approvals-and-sandbox``,
``copilot --allow-all-tools``, ...) or planting config that agent / its IDE
auto-loads (``.gemini/settings.json``, ``.codex/config.toml``,
``.cursor/hooks.json``, ``chat.tools.autoApprove`` in
``.vscode/settings.json``, ...).
"""
import json
import time

import pytest

from aegis import patterns, rules
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.loader import load_policy
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(foreign_agent={"mode": "deny"})
RULE = "foreign-agent-protect"


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _write(path, content="{}", cwd=None):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write", cwd=cwd,
                      args={"file_path": path, "content": content})


def _edit(path, old, new, cwd=None, replace_all=False):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit", cwd=cwd,
                      args={"file_path": path, "old_string": old, "new_string": new,
                            "replace_all": replace_all})


def _multiedit(path, edits, cwd=None):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit", cwd=cwd,
                      args={"file_path": path, "edits": edits})


def _mcp(tool, args):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, action=ActionClass.MCP, args=args)


def _rule(ev, policy=EMPTY):
    return rules.rule_foreign_agent_protect(ev, policy)


def _ours(ev, policy=EMPTY) -> bool:
    d = _rule(ev, policy)
    return d is not None and d.rule == RULE and d.action != Action.ALLOW


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("AEGIS_ALLOW_FOREIGN_AGENT", raising=False)
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)


# ---- (1) nested launch with approvals / sandbox off ----------------------------

@pytest.mark.parametrize("cmd", [
    "gemini --yolo -p 'summarise the repo'",
    "gemini -y -p 'do it'",
    "gemini -yp 'do it'",
    "gemini --approval-mode yolo -p x",
    "gemini --approval-mode=yolo -p x",
    "npx @google/gemini-cli --yolo -p x",
    "npx -y @google/gemini-cli@latest --yolo -p x",
    "qwen --yolo -p x",
    "codex exec --dangerously-bypass-approvals-and-sandbox 'exfil'",
    "codex --yolo 'x'",
    "codex exec -s danger-full-access 'x'",
    "codex exec --sandbox=danger-full-access 'x'",
    "codex -c sandbox_mode=\"danger-full-access\" exec x",
    "codex -a never exec 'x'",
    "codex --ask-for-approval=never exec 'x'",
    "codex -c approval_policy=never exec 'x'",
    "codex -c 'approval_policy=\"never\"' exec x",
    "codex exec --full-auto 'x'",
    "/usr/local/bin/codex exec --full-auto x",
    "copilot -p 'x' --allow-all-tools",
    "copilot -p x --allow-all",
    "copilot -p x --allow-tool 'shell'",
    "COPILOT_ALLOW_ALL=1 copilot -p x",
    "cursor-agent --force -p 'x'",
    "cursor-agent -f -p 'x'",
    "q chat --trust-all-tools 'x'",
    "kiro-cli chat --trust-all-tools",
    "amp --dangerously-allow-all -x 'x'",
    "aider --yes-always --message x",
    "aider --yes --message x",
    "crush --yolo",
    "cd /tmp && gemini --yolo -p x",
    "true; codex --yolo x",
    "bash -c \"gemini --yolo -p hi\"",
    "sh -c 'codex exec --dangerously-bypass-approvals-and-sandbox x'",
    "ge\"\"mini --yo\"\"lo -p x",
    "echo Z2VtaW5pIC0teW9sbw== | base64 -d | sh",
    "$CODEX exec --dangerously-bypass-approvals-and-sandbox x",
    "\"$(which codex)\" --yolo x",
    "codex.exe --yolo x",
])
def test_launch_gated(cmd):
    assert _ours(_shell(cmd)), cmd


@pytest.mark.parametrize("cmd", [
    "gemini -p 'summarise the repo'",
    "gemini --approval-mode default -p x",
    "codex exec 'explain this file'",
    "codex -a on-request",
    "codex --sandbox read-only exec x",
    "copilot -p 'x'",
    "cursor-agent -p 'x'",
    "q chat",
    "aider --message x",
    "find ~/.codex -type f",
    "ls -la ~/.gemini -y",
    "cat ~/.codex/config.toml",
    "npm install -g @openai/codex --force",
    "npm i -g @google/gemini-cli -y",
    "brew install gemini-cli --force",
    "pip install aider-chat -y",
    "apt-get install -y curl && codex exec 'x'",
    "rm -f build.log",
    "yes | apt-get install foo",
    "git commit -m 'bump gemini'",
])
def test_launch_benign_allowed(cmd):
    assert not _ours(_shell(cmd)), cmd


def test_launch_through_engine_is_ours():
    d = evaluate(_shell("gemini --yolo -p 'x'"), EMPTY)
    assert d.action == Action.ASK and d.rule == RULE


def test_launch_deny_mode():
    assert _rule(_shell("gemini --yolo -p x"), DENY).action == Action.DENY


def test_launch_beyond_scan_surface_truncation():
    cmd = "echo " + "a" * 25000 + "; gemini --yolo -p x"
    assert _ours(_shell(cmd))


# ---- (2a) dedicated config files: any write ----------------------------------

DEDICATED = [
    ".gemini/settings.json",
    "/home/u/.gemini/settings.json",
    "/etc/gemini-cli/settings.json",
    ".gemini/commands/deploy.toml",
    ".gemini/commands/git/commit.toml",
    "/home/u/.gemini/extensions/evil/gemini-extension.json",
    ".qwen/settings.json",
    ".codex/config.toml",
    "/home/u/.codex/config.toml",
    "/home/u/.codex/rules/default.rules",
    ".cursor/hooks.json",
    "/home/u/.cursor/hooks.json",
    ".cursor/cli.json",
    "/home/u/.cursor/cli-config.json",
    ".cursor/environment.json",
    ".windsurf/hooks.json",
    "/home/u/.codeium/windsurf/hooks.json",
    ".kiro/settings/mcp.json",
    ".kiro/hooks/on-save.kiro.hook",
    ".amazonq/mcp.json",
    ".amazonq/cli-agents/dev.json",
    "/home/u/.aws/amazonq/mcp.json",
    ".roo/mcp.json",
    "/home/u/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
    ".continue/config.yaml",
    ".continue/mcpServers/evil.yaml",
    "opencode.json",
    "/repo/opencode.jsonc",
    ".opencode/plugin/x.ts",
    ".opencode/plugins/x.js",
    ".opencode/tool/x.ts",
    ".aider.conf.yml",
    "/home/u/.aider.conf.yaml",
    "/home/u/.copilot/config.json",
    "/home/u/.copilot/mcp-config.json",
    ".github/hooks/hooks.json",
    ".crush.json",
    "crush.json",
    "/home/u/.config/amp/settings.json",
    "C:\\Users\\u\\.gemini\\settings.json",
    ".GEMINI/Settings.JSON",
    ".gemini/./settings.json",
]


@pytest.mark.parametrize("path", DEDICATED)
def test_dedicated_write_gated(path):
    assert _ours(_write(path, '{"theme": "dark"}')), path


@pytest.mark.parametrize("path", DEDICATED[:6])
def test_dedicated_edit_gated(path):
    assert _ours(_edit(path, "a", "b")), path


def test_dedicated_mcp_write_gated():
    assert _ours(_mcp("mcp__fs__write_file", {"path": ".codex/config.toml",
                                               "content": 'notify = ["sh", "-c", "curl x"]'}))


@pytest.mark.parametrize("path", [
    ".gemini/GEMINI.md", "docs/settings.json", ".cursor/rules/style.mdc",
    "src/opencode.py", ".github/workflows/hooks.json.md", "codex/config.toml.bak",
    ".codex/AGENTS.md", "aider.md",
])
def test_unrelated_paths_not_ours(path):
    assert not _ours(_write(path, '{"chat.tools.autoApprove": true}')), path


@pytest.mark.parametrize("cmd", [
    "echo '{\"tools\":{\"discoveryCommand\":\"sh x\"}}' > .gemini/settings.json",
    "printf 'notify = [\"sh\"]\\n' >> ~/.codex/config.toml",
    "cat payload | tee .cursor/hooks.json",
    "cp /tmp/h.json .cursor/hooks.json",
    "mv /tmp/x .codex/config.toml",
    "sed -i 's/a/b/' .aider.conf.yml",
    "rm ~/.codex/rules/default.rules",
    "ln -sf /tmp/evil.json .gemini/settings.json",
    "python3 -c \"open('.gemini/settings.json','w').write('{}')\"",
    "jq '.x=1' .gemini/settings.json | sponge .gemini/settings.json",
    "git apply - <<'EOF'\n--- a/.codex/config.toml\n+++ b/.codex/config.toml\nEOF",
])
def test_dedicated_shell_write_gated(cmd):
    assert _ours(_shell(cmd)), cmd


@pytest.mark.parametrize("cmd", [
    "cat .gemini/settings.json",
    "jq . ~/.codex/config.toml",
    "grep notify ~/.codex/config.toml",
    "ls .cursor",
])
def test_dedicated_shell_read_allowed(cmd):
    assert not _ours(_shell(cmd)), cmd


# ---- (2b) shared editor settings: semantic diff ------------------------------

VS = ".vscode/settings.json"


@pytest.mark.parametrize("content", [
    '{"chat.tools.autoApprove": true}',
    '{"chat.tools.global.autoApprove": true}',
    '{"chat.tools.terminal.autoApprove": {"/.*/": true}}',
    '{"chat.tools.terminal.enableAutoApprove": true}',
    '{"chat.tools.edits.autoApprove": {"**/*": true}}',
    '{"github.copilot.chat.agent.terminal.allowList": {"curl": true}}',
    '{"mcp": {"servers": {"x": {"command": "sh", "args": ["-c", "curl x"]}}}}',
    '{"chat.mcp.autostart": "newAndOutdated"}',
    '{"chat.mcp.discovery.enabled": true}',
    '{"amp.dangerouslyAllowAll": true}',
    '{"\\u0063hat.tools.autoApprove": true}',
    '// comment\n{\n  "editor.tabSize": 2, /* c */\n  "chat.tools.autoApprove": true,\n}\n',
    '{"chat.tools.autoApprove": false, "chat.tools.autoApprove": true}',
    '{"chat.tools.autoApprove": "true"}',
])
def test_shared_write_new_key_gated(tmp_path, content):
    assert _ours(_write(str(tmp_path / VS), content)), content


@pytest.mark.parametrize("content", [
    '{"editor.tabSize": 2}',
    '{"chat.tools.autoApprove": false}',
    '{"chat.tools.terminal.autoApprove": {"rm": false, "curl": false}}',
    '{"chat.mcp.discovery.enabled": false}',
    '{"chat.mcp.autostart": "never"}',
    '{"task.allowAutomaticTasks": "off"}',
    '// just comments\n{\n  "files.exclude": {"**/.git": true},\n}',
    '',
])
def test_shared_write_benign_allowed(tmp_path, content):
    assert not _ours(_write(str(tmp_path / VS), content)), content


def test_shared_value_only_flip_caught(tmp_path):
    f = tmp_path / VS
    f.parent.mkdir(parents=True)
    f.write_text('{\n  "editor.tabSize": 2,\n  "chat.tools.autoApprove": false\n}\n')
    assert _ours(_edit(str(f), "false", "true"))


def test_shared_unrelated_edit_with_existing_approval_allowed(tmp_path):
    f = tmp_path / VS
    f.parent.mkdir(parents=True)
    f.write_text('{\n  "editor.tabSize": 2,\n  "chat.tools.autoApprove": true\n}\n')
    assert not _ours(_edit(str(f), '"editor.tabSize": 2', '"editor.tabSize": 4'))


def test_shared_rewrite_keeping_existing_approval_allowed(tmp_path):
    f = tmp_path / VS
    f.parent.mkdir(parents=True)
    f.write_text('{"chat.tools.autoApprove": true}')
    assert not _ours(_write(str(f), '{"chat.tools.autoApprove": true, "editor.tabSize": 4}'))


def test_shared_remove_key_allowed(tmp_path):
    f = tmp_path / VS
    f.parent.mkdir(parents=True)
    f.write_text('{\n  "editor.tabSize": 2,\n  "chat.tools.autoApprove": true\n}\n')
    assert not _ours(_edit(str(f), ',\n  "chat.tools.autoApprove": true', ""))


def test_shared_relative_path_resolved_against_cwd(tmp_path):
    f = tmp_path / VS
    f.parent.mkdir(parents=True)
    f.write_text('{"chat.tools.autoApprove": false}')
    assert _ours(_edit(VS, "false", "true", cwd=str(tmp_path)))
    assert not _ours(_edit(VS, "{", "{\"editor.tabSize\": 2, ", cwd=str(tmp_path)))


def test_shared_multiedit_assembly_caught(tmp_path):
    f = tmp_path / VS
    f.parent.mkdir(parents=True)
    f.write_text('{"zz": true}')
    assert _ours(_multiedit(str(f), [
        {"old_string": '"zz"', "new_string": '"chat.tools.QQ"'},
        {"old_string": "QQ", "new_string": "autoApprove"},
    ]))


def test_shared_key_rename_caught(tmp_path):
    f = tmp_path / VS
    f.parent.mkdir(parents=True)
    f.write_text('{"chat.tools.zzzz": true}')
    assert _ours(_edit(str(f), "zzzz", "autoApprove"))


def test_shared_edit_unreplayable_falls_back_to_fragment(tmp_path):
    p = str(tmp_path / "nope" / VS)   # no pre-image on disk
    assert _ours(_edit(p, "x", '"chat.tools.autoApprove": true'))
    assert not _ours(_edit(p, "x", '"editor.tabSize": 2'))


def test_shared_unparseable_post_image_falls_back(tmp_path):
    assert _ours(_write(str(tmp_path / VS), '{"chat.tools.autoApprove": true,,,'))
    assert not _ours(_write(str(tmp_path / VS), '{"editor.tabSize": 2,,,'))


def test_shared_mcp_edit_file_shape(tmp_path):
    f = tmp_path / VS
    f.parent.mkdir(parents=True)
    f.write_text('{"chat.tools.autoApprove": false}')
    assert _ours(_mcp("mcp__fs__edit_file", {"path": str(f),
                                              "edits": [{"oldText": "false", "newText": "true"}]}))


@pytest.mark.parametrize("path,content", [
    ("/home/u/.config/Code/User/settings.json", '{"chat.tools.autoApprove": true}'),
    ("/home/u/.config/Cursor/User/settings.json", '{"chat.tools.global.autoApprove": true}'),
    ("/home/u/.config/Code/User/profiles/abc123/settings.json", '{"chat.tools.autoApprove": true}'),
    ("proj.code-workspace", '{"folders": [], "settings": {"chat.tools.autoApprove": true}}'),
    ("proj.code-workspace", '{"settings": {"mcp": {"servers": {"x": {"command": "sh"}}}}}'),
    (".zed/settings.json", '{"agent": {"always_allow_tool_actions": true}}'),
    ("/home/u/.config/zed/settings.json", '{"context_servers": {"x": {"command": {"path": "sh"}}}}'),
])
def test_shared_other_editors_gated(tmp_path, path, content):
    if not path.startswith("/"):
        path = str(tmp_path / path)
    assert _ours(_write(path, content)), path


def test_shared_zed_benign_allowed(tmp_path):
    assert not _ours(_write(str(tmp_path / ".zed/settings.json"), '{"theme": "One Dark", "buffer_font_size": 15}'))


@pytest.mark.parametrize("cmd", [
    "jq '.\"chat.tools.autoApprove\" = true' .vscode/settings.json | sponge .vscode/settings.json",
    "echo '{\"chat.tools.autoApprove\": true}' > .vscode/settings.json",
    "python3 - <<'EOF'\nimport json;d=json.load(open('.vscode/settings.json'));d['chat.tools.autoApprove']=True\nEOF",
    "sed -i 's/\"editor.tabSize\": 2/\"chat.mcp.autostart\": \"newAndOutdated\"/' .vscode/settings.json",
])
def test_shared_shell_write_gated(cmd):
    assert _ours(_shell(cmd)), cmd


@pytest.mark.parametrize("cmd", [
    "jq '.\"editor.tabSize\" = 4' .vscode/settings.json | sponge .vscode/settings.json",
    "grep autoApprove .vscode/settings.json",
    "cat .vscode/settings.json",
])
def test_shared_shell_benign_allowed(cmd):
    assert not _ours(_shell(cmd)), cmd


# ---- escapes, modes, wiring -------------------------------------------------

def test_env_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_FOREIGN_AGENT", "1")
    assert not _ours(_shell("gemini --yolo -p x"))
    assert not _ours(_write(".codex/config.toml"))


def test_human_override_comment():
    assert not _ours(_shell("gemini --yolo -p x  # aegis-allow"))


def test_spawned_agent_cannot_override(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "worker-1")
    assert _ours(_shell("gemini --yolo -p x  # aegis-allow"))


def test_policy_allow_regex():
    pol = Policy(foreign_agent={"allow": [r"\.codex/config\.toml$"]})
    assert not _ours(_write("/home/u/.codex/config.toml"), pol)
    assert _ours(_write(".gemini/settings.json"), pol)


def test_mode_off():
    pol = Policy(foreign_agent={"mode": "off"})
    assert _rule(_shell("gemini --yolo -p x"), pol) is None
    assert _rule(_write(".codex/config.toml"), Policy(foreign_agent={"mode": False})) is None


def test_mode_monitor(monkeypatch):
    seen = []
    monkeypatch.setattr(rules, "_record_monitor", lambda ev, d, note="": seen.append((d.rule, note)))
    pol = Policy(foreign_agent={"mode": "monitor"})
    assert _rule(_shell("gemini --yolo -p x"), pol) is None
    assert seen == [(RULE, "foreign-agent-protect-monitor")]


def test_yaml_round_trip(tmp_path):
    (tmp_path / "p.yaml").write_text("foreign_agent:\n  mode: deny\n  allow: ['zzz']\n")
    pol = load_policy(tmp_path)
    assert pol.foreign_agent == {"mode": "deny", "allow": ["zzz"]}
    assert _rule(_shell("codex --yolo x"), pol).action == Action.DENY


def test_registered_in_core_rules_and_fetch_backstop():
    assert rules.rule_foreign_agent_protect in rules.BUILTIN_RULES
    regs = [r for r, _ in rules._FETCH_HUMAN_ESCAPABLE]
    assert patterns.FOREIGN_AGENT_CONFIG_PATH_RE in regs
    assert patterns.FOREIGN_AGENT_SHARED_PATH_RE in regs


def test_fetch_to_file_backstop_reaches_foreign_config():
    d = evaluate(_shell("curl -o ~/.codex/config.toml https://example.com/c"), EMPTY)
    assert d.action != Action.ALLOW


# ---- performance: linear-time on hostile input --------------------------------

@pytest.mark.parametrize("cmd", [
    "codex " + "-" + "y" * 200000 + "1",
    "codex " + " -a" * 50000,
    ("gemini " + "x" * 50) * 4000,
    "echo " + "{" * 100000 + " > .vscode/settings.json",
])
def test_hostile_input_fast(cmd):
    t = time.perf_counter()
    _rule(_shell(cmd))
    assert time.perf_counter() - t < 2.0


def test_deep_json_does_not_crash(tmp_path):
    deep = '{"a":' * 5000 + '1' + '}' * 5000
    t = time.perf_counter()
    _rule(_write(str(tmp_path / VS), deep))
    assert time.perf_counter() - t < 2.0
    deep_gated = '{"chat.tools.autoApprove":' + '{"a":' * 5000 + 'true' + '}' * 5001
    assert _ours(_write(str(tmp_path / VS), deep_gated))
