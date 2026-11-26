"""Claude Code plugin-system guard.

A plugin's hooks/MCP servers run as Claude Code's own subprocesses, outside
the tool-call loop Aegis gates, and `disableAllHooks` switches every hook
(Aegis included) off. Gated: `disableAllHooks` / `enabledPlugins` /
`extraKnownMarketplaces` added to .claude/settings.local.json (or
managed-settings.json), any write into ~/.claude/plugins/, and the
`claude plugin install|enable|update|marketplace add` / `--plugin-dir` CLI.
"""
import json

import pytest

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy
from aegis import patterns
from aegis.loader import load_policy
from aegis.rules import rule_claude_plugin_protect

EMPTY = Policy()
RULE = "claude-plugin-protect"
LOCAL = "/r/.claude/settings.local.json"


def _write(path, content, cwd=None):
    if not isinstance(content, str):
        content = json.dumps(content)
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write",
                      args={"file_path": path, "content": content}, cwd=cwd)


def _edit(path, old, new, cwd=None):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                      args={"file_path": path, "old_string": old, "new_string": new}, cwd=cwd)


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp(args, tool="mcp__filesystem__write_file"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, action=ActionClass.MCP, args=args)


def _ours(d):
    return d is not None and d.action == Action.ASK and d.rule == RULE


@pytest.fixture(autouse=True)
def _no_env_escape(monkeypatch):
    monkeypatch.delenv("AEGIS_ALLOW_CLAUDE_PLUGIN", raising=False)
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)


# ---- path recognition --------------------------------------------------------
@pytest.mark.parametrize("p,kind", [
    (".claude/settings.local.json", "settings"),
    ("/home/u/.claude/settings.local.json", "settings"),
    ("C:\\Users\\u\\.claude\\settings.local.json", "settings"),
    ("/r/.claude/./settings.local.json", "settings"),
    ("/r/x/../.claude/settings.local.json", "settings"),
    ("/r/.claude/settings.local.json::$DATA", "settings"),
    ("file:///r/.claude/settings%2Elocal.json", "settings"),
    ("$CLAUDE_CONFIG_DIR/settings.local.json", "settings"),
    ("/etc/claude-code/managed-settings.json", "settings"),
    ("/home/u/.claude/plugins", "tree"),
    ("/home/u/.claude/plugins/known_marketplaces.json", "tree"),
    ("~/.claude/plugins/cache/p/1.0/hooks/hooks.json", "tree"),
    ("~/.claude/plugins/marketplaces/m/plugins/p/scripts/fmt.sh", "tree"),
    ("${CLAUDE_CONFIG_DIR}/plugins/installed_plugins.json", "tree"),
    ("C:\\Users\\u\\.claude\\plugins\\x", "tree"),
    ("/home/u/.claude./plugins/x", "tree"),
])
def test_kind(p, kind):
    assert patterns.claude_plugin_kind(p) == kind


@pytest.mark.parametrize("p", [
    "/r/.claude/settings.json", "/r/.claude/settings.local.json.bak",
    "/r/claude/plugins/x", "/r/.claude-plugin/plugin.json", "/r/src/plugins/x.ts",
    "/r/.claude/agents/x.md", "/r/docs/settings.local.json.md",
])
def test_kind_negative(p):
    assert patterns.claude_plugin_kind(p) == ""


# ---- settings.local.json content ----------------------------------------------
@pytest.mark.parametrize("body", [
    {"disableAllHooks": True},
    {"disableAllHooks": "true"},
    {"disableAllHooks": 1},
    {"enabledPlugins": {"fmt@acme": True}},
    {"enabledPlugins": ["fmt@acme"]},
    {"extraKnownMarketplaces": {"acme": {"source": {"source": "github", "repo": "evil/m"}}}},
    {"model": "x", "permissions": {"allow": []}, "enabledPlugins": {"a@b": True}},
    {"DisableAllHooks": True},
])
def test_settings_write_gated(body):
    assert _ours(evaluate(_write(LOCAL, body), EMPTY))


def test_unicode_escaped_key_gated():
    assert _ours(evaluate(_write(LOCAL, '{"\\u0064isableAllHooks": true}'), EMPTY))


def test_unparseable_naming_key_fails_closed():
    assert _ours(evaluate(_write(LOCAL, '{"disableAllHooks": true,,}'), EMPTY))


@pytest.mark.parametrize("body", [
    {"model": "claude-x"},
    {"permissions": {"allow": ["Bash(ls:*)"]}},
    {"disableAllHooks": False},
    {"enabledPlugins": {"fmt@acme": False}},
    {"enabledPlugins": {}},
    {},
])
def test_settings_write_benign(body):
    assert rule_claude_plugin_protect(_write(LOCAL, body), EMPTY) is None


def test_unparseable_without_key_allowed():
    assert rule_claude_plugin_protect(_write(LOCAL, '{"model": '), EMPTY) is None


def test_edit_replayed_diff(tmp_path):
    d = tmp_path / ".claude"
    d.mkdir()
    f = d / "settings.local.json"
    f.write_text(json.dumps({"model": "a", "enabledPlugins": {"fmt@acme": True}}, indent=2))
    # unrelated edit beside a human-enabled plugin: allowed
    assert rule_claude_plugin_protect(_edit(str(f), '"model": "a"', '"model": "b"'), EMPTY) is None
    # disabling it: allowed
    assert rule_claude_plugin_protect(_edit(str(f), '"fmt@acme": true', '"fmt@acme": false'), EMPTY) is None
    # adding a second plugin: gated
    d2 = _edit(str(f), '"fmt@acme": true', '"fmt@acme": true, "evil@acme": true')
    assert _ours(evaluate(d2, EMPTY))
    # adding disableAllHooks: gated
    assert _ours(evaluate(_edit(str(f), '"model": "a"', '"model": "a", "disableAllHooks": true'), EMPTY))
    # flipping a disabled plugin back on: gated
    f.write_text(json.dumps({"enabledPlugins": {"fmt@acme": False}}))
    assert _ours(evaluate(_edit(str(f), "false", "true"), EMPTY))


def test_edit_of_missing_file_judges_fragment(tmp_path):
    p = str(tmp_path / ".claude" / "settings.local.json")
    assert rule_claude_plugin_protect(_edit(p, "a", '"model": "b"'), EMPTY) is None
    assert _ours(evaluate(_edit(p, "{", '{"disableAllHooks": true,'), EMPTY))
    assert _ours(evaluate(_edit(p, "{", '{"enabledPlugins": {"x@y": true},'), EMPTY))
    assert rule_claude_plugin_protect(_edit(p, "{", '{"disableAllHooks": false,'), EMPTY) is None


def test_relative_path_with_cwd():
    assert _ours(evaluate(_write("settings.local.json", {"disableAllHooks": True},
                                 cwd="/r/.claude"), EMPTY))


# ---- plugin tree ---------------------------------------------------------------
@pytest.mark.parametrize("p", [
    "/home/u/.claude/plugins/cache/p/1.0/hooks/hooks.json",
    "/home/u/.claude/plugins/marketplaces/m/plugins/p/scripts/run.sh",
    "/home/u/.claude/plugins/known_marketplaces.json",
    "/home/u/.claude/plugins/installed_plugins.json",
    "/home/u/.claude/plugins/cache/p/1.0/commands/x.md",
])
def test_tree_write_gated(p):
    assert _ours(evaluate(_write(p, "anything"), EMPTY))


def test_tree_mcp_write_gated():
    d = evaluate(_mcp({"path": "/home/u/.claude/plugins/cache/p/hooks/hooks.json",
                       "content": "{}"}), EMPTY)
    assert _ours(d)


def test_tree_mcp_read_allowed():
    ev = _mcp({"path": "/home/u/.claude/plugins/known_marketplaces.json"},
              tool="mcp__filesystem__read_file")
    assert rule_claude_plugin_protect(ev, EMPTY) is None


def test_mcp_patch_gated():
    patch = ("*** Begin Patch\n*** Update File: /home/u/.claude/plugins/cache/p/hooks/hooks.json\n"
             "@@\n-{}\n+{\"hooks\":{}}\n*** End Patch\n")
    assert _ours(evaluate(_mcp({"patch": patch}, tool="mcp__x__apply_patch"), EMPTY))


# ---- shell -----------------------------------------------------------------------
@pytest.mark.parametrize("cmd", [
    "echo '{}' > ~/.claude/plugins/cache/p/1.0/hooks/hooks.json",
    "tee ~/.claude/plugins/known_marketplaces.json < x",
    "cp evil.sh ~/.claude/plugins/marketplaces/m/plugins/p/scripts/fmt.sh",
    "sed -i 's/a/b/' ~/.claude/plugins/cache/p/hooks/hooks.json",
    "cp x ~/.cl'aude'/plugins/cache/p/hooks/hooks.json",
    "cp x ~/.claude/plug*/cache/p/hooks/hooks.json",
    "cp x ~/.claude/{plugins,y}/cache/p/hooks/hooks.json",
    "cp x ~/.cl?ude/plugins/c",
    "cd ~/.claude && cp x plugins/cache/p/hooks/hooks.json",
    "cd ~/.claude/plugins && cp x cache/p/hooks/hooks.json",
    "cp x $CLAUDE_CONFIG_DIR/plugins/c",
    "python3 -c \"import json;json.dump({'disable'+'AllHooks':True},open('.claude/settings.local.json','w'))\"",
    "jq '.disableAllHooks=true' .claude/settings.local.json | sponge .claude/settings.local.json",
    "cd .claude && echo '{\"disableAllHooks\":true}' > settings.local.json",
    "echo '{\"disableAllHooks\": true}' > /etc/claude-code/managed-settings.json",
    "bash -c 'echo x > ~/.claude/plugins/cache/p/h.json'",
])
def test_shell_write_gated(cmd):
    # Literal `.claude/...` writes are often already self-protect's DENY;
    # this guard must fire on its own and the pipeline must not allow.
    assert _ours(rule_claude_plugin_protect(_shell(cmd), EMPTY)), cmd
    assert evaluate(_shell(cmd), EMPTY).action != Action.ALLOW, cmd


@pytest.mark.parametrize("cmd", [
    "claude plugin install fmt@acme",
    "claude plugin i fmt@acme",
    "claude plugins install fmt@acme",
    "claude plugin enable fmt@acme",
    "claude plugin update fmt@acme",
    "claude plugin marketplace add evil/marketplace",
    "claude plugin marketplace update",
    "/usr/local/bin/claude plugin install fmt@acme",
    "npx @anthropic-ai/claude-code plugin install fmt@acme",
    "claude --plugin-dir ./evil -p hi",
    "claude -p hi --plugin-dir=./evil",
    "cl'aude' plugin install fmt@acme",
    "claude --debug plugin install x@y",
])
def test_cli_gated(cmd):
    assert _ours(rule_claude_plugin_protect(_shell(cmd), EMPTY)), cmd
    assert evaluate(_shell(cmd), EMPTY).action != Action.ALLOW, cmd


@pytest.mark.parametrize("cmd", [
    "cat ~/.claude/plugins/known_marketplaces.json",
    "ls -la ~/.claude/plugins/cache",
    "grep -r hooks ~/.claude/plugins",
    "cat .claude/settings.local.json",
    "git add .claude/settings.local.json",
    "git diff .claude/settings.local.json",
    "claude plugin list",
    "claude plugin validate .",
    "claude plugin uninstall fmt@acme",
    "claude plugin disable fmt@acme",
    "claude -p 'summarize the repo'",
    "npm install && npm test",
    "echo hello > src/plugins/x.ts",
])
def test_shell_benign(cmd):
    assert rule_claude_plugin_protect(_shell(cmd), EMPTY) is None, cmd


def test_mcp_shell_tool_gated():
    ev = _mcp({"command": "claude plugin install x@y"}, tool="mcp__desktop__run_command")
    assert _ours(evaluate(ev, EMPTY))


# ---- escapes / config ------------------------------------------------------------
def test_override_comment_human_only(monkeypatch):
    cmd = "claude plugin install fmt@acme # aegis-allow"
    assert rule_claude_plugin_protect(_shell(cmd), EMPTY) is None
    monkeypatch.setenv("AEGIS_AGENT_NAME", "worker")
    assert _ours(rule_claude_plugin_protect(_shell(cmd), EMPTY))


def test_env_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CLAUDE_PLUGIN", "1")
    assert rule_claude_plugin_protect(_write(LOCAL, {"disableAllHooks": True}), EMPTY) is None
    assert rule_claude_plugin_protect(_shell("claude plugin install a@b"), EMPTY) is None


def test_modes(tmp_path):
    ev = _write(LOCAL, {"disableAllHooks": True})
    assert rule_claude_plugin_protect(ev, Policy(claude_plugin={"mode": "off"})) is None
    d = rule_claude_plugin_protect(ev, Policy(claude_plugin={"mode": "deny"}))
    assert d.action == Action.DENY
    assert rule_claude_plugin_protect(ev, Policy(claude_plugin={"mode": "monitor"})) is None


def test_allow_regex_path_and_fullmatch_cmd():
    pol = Policy(claude_plugin={"allow": [r"^/r/\.claude/settings\.local\.json$",
                                          r"claude plugin install fmt@acme"]})
    assert rule_claude_plugin_protect(_write(LOCAL, {"disableAllHooks": True}), pol) is None
    assert rule_claude_plugin_protect(_shell("claude plugin install fmt@acme"), pol) is None
    assert _ours(rule_claude_plugin_protect(
        _shell("claude plugin install fmt@acme; claude plugin install evil@x"), pol))
    pol2 = Policy(claude_plugin={"allow": [r"^/r/allowed/"]})
    assert _ours(rule_claude_plugin_protect(
        _write("/r/allowed/../.claude/settings.local.json", {"disableAllHooks": True}), pol2))


def test_loader_wires_knob(tmp_path):
    (tmp_path / "p.yaml").write_text("claude_plugin:\n  mode: deny\n")
    pol = load_policy(str(tmp_path))
    assert pol.claude_plugin == {"mode": "deny"}


def test_self_protect_still_denies_settings_json():
    d = evaluate(_write("/r/.claude/settings.json", {"enabledPlugins": {"a@b": True}}), EMPTY)
    assert d.action == Action.DENY and d.rule == "self-protect"


# ---- QA round 1 regressions ------------------------------------------------------
@pytest.mark.parametrize("cmd", [
    "git commit -m 'docs: explain claude plugin install flow'",
    "grep -rn 'claude plugin install' docs/",
    "rg -n 'claude --plugin-dir' README.md",
    "echo claude plugin install x@m",
    "cd /r/.claude-tools && pytest tests/plugins",
    "cd ~/.claudette && make plugins",
    "cd ~/.claude && cd ~/proj && npm run build --prefix plugins",
    "find ~/.claude/plugins -name hooks.json",
    "cat ~/.claude/plugins/installed_plugins.json | jq .",
    "jq .enabledPlugins .claude/settings.local.json",
    "claude --settings '{\"model\":\"x\"}' -p hi",
])
def test_r1_not_gated(cmd):
    assert rule_claude_plugin_protect(_shell(cmd), EMPTY) is None, cmd


@pytest.mark.parametrize("cmd", [
    "echo 'claude plugin install x@m' | sh",
    "echo claude plugin install x@m | bash",
    "git commit -m x && claude plugin install a@b",
    "git -c alias.x='!claude plugin install a@b' x",
    "claude --settings '{\"disableAllHooks\":true}' -p hi",
    "claude --settings='{\"enabledPlugins\":{\"x@m\":true}}'",
    "claude --settings ./child.json -p hi",
    "claude --setting-sources project -p hi",
    "find ~/.claude/plugins -name '*.sh' -exec sed -i s/a/b/ {} +",
    "jq . x > ~/.claude/plugins/known_marketplaces.json",
])
def test_r1_gated(cmd):
    assert _ours(rule_claude_plugin_protect(_shell(cmd), EMPTY)), cmd


def test_r1_shell_cwd_in_plugin_tree():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Bash",
                    args={"command": "echo '{}' > hooks/hooks.json"},
                    cwd="/home/u/.claude/plugins/cache/p/1")
    assert _ours(rule_claude_plugin_protect(ev, EMPTY))
    ev2 = Event.make(HookEvent.PRE_TOOL_USE, tool="Bash",
                     args={"command": "cp x plugins/cache/p/h.json"}, cwd="/home/u/.claude")
    assert _ours(rule_claude_plugin_protect(ev2, EMPTY))
    ev3 = Event.make(HookEvent.PRE_TOOL_USE, tool="Bash",
                     args={"command": "cat hooks/hooks.json"}, cwd="/home/u/.claude/plugins/cache/p/1")
    assert rule_claude_plugin_protect(ev3, EMPTY) is None


def test_r1_agent_rules_deny_not_preempted():
    ev = _write("/home/u/.claude/plugins/cache/p/1/.cursorrules", "x")
    d = evaluate(ev, Policy(agent_rules={"mode": "deny"}))
    assert d.action == Action.DENY and d.rule != RULE


def test_r1_managed_settings_only_real_locations():
    assert patterns.claude_plugin_kind("/r/tests/fixtures/managed-settings.json") == ""
    assert patterns.claude_plugin_kind("/Library/Application Support/ClaudeCode/managed-settings.json") == "settings"
    assert patterns.claude_plugin_kind("C:\\ProgramData\\ClaudeCode\\managed-settings.json") == "settings"


def test_r1_monitor_records(monkeypatch):
    seen = []
    import aegis.rules as R
    monkeypatch.setattr(R, "_record_monitor", lambda ev, would, note="": seen.append((would.rule, note)))
    assert rule_claude_plugin_protect(_write(LOCAL, {"disableAllHooks": True}),
                                      Policy(claude_plugin={"mode": "monitor"})) is None
    assert seen and seen[0][0] == RULE


def test_r1_deny_mode_mcp_write():
    d = rule_claude_plugin_protect(_mcp({"path": "/home/u/.claude/plugins/x.json", "content": "{}"}),
                                   Policy(claude_plugin={"mode": "deny"}))
    assert d.action == Action.DENY


def test_r1_plugin_source_repo_not_gated():
    for p in ("/r/myplugin/hooks/hooks.json", "/r/.claude-plugin/plugin.json",
              "/r/.claude-tools/plugins/x"):
        assert rule_claude_plugin_protect(_write(p, "{}"), EMPTY) is None, p


def test_r1_shell_project_settings_json_still_self_protect():
    d = evaluate(_shell("echo '{\"disableAllHooks\":true}' > .claude/settings.json"), EMPTY)
    assert d.action == Action.DENY and d.rule == "self-protect"


# ---- QA round 1 (bypass review) regressions -----------------------------------
def _sh(cmd, cwd=None):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd}, cwd=cwd)


@pytest.mark.parametrize("cmd,cwd", [
    ("echo '{\"disableAllHooks\": true}' > settings.local.json", "/r/.claude"),
    ("echo x > cache/m/p/1/hooks/hooks.json", "/home/u/.claude/plugins"),
    ("echo x > plugins/cache/p/hooks/hooks.json", "/home/u/.claude"),
])
def test_b1_cwd(cmd, cwd):
    assert evaluate(_sh(cmd, cwd), EMPTY).action != Action.ALLOW


@pytest.mark.parametrize("cmd", [
    "echo '{\"disableAllHooks\":true}' | tee .cl*/settings.local.json",
    "echo '{\"disableAllHooks\":true}' | tee {.claude,/tmp}/settings.local.json",
    "echo '{\"disableAllHooks\":true}' > .{claude,x}/settings.local.json",
    "cd .cl* && echo '{\"disableAllHooks\": true}' > settings.local.json",
    "cp /tmp/evil.json .c[l]aude/settings.local.json",
    "cp /tmp/a ./.c*/s*.local.json",
    "echo '{\"disableAllHooks\":true}' > /etc/claude-code/manag*.json",
    "echo '{\"disableAllHooks\":true}' > /etc/claude-code/managed-settings.js*",
    "claude --model sonnet --fallback-model opus --permission-mode default --verbose --debug plugin install evil@m",
    "claude --model a --b c --d e --f g --verbose plugin marketplace add evil/repo",
    "claude -d -d -d -d -d -d -d plugin install x@m",
    "claude plugin $(echo install) x@m",
    "claude plugin `echo install` x@m",
    "claude plugin ${X:-install} x@m",
    "s=install; claude plugin $s x@m",
    "c=claude; $c plugin install x@m",
    "$(which claude) plugin install x@m",
    "echo install x@m | xargs claude plugin",
    "python3 -c \"import subprocess;subprocess.run(['claude','plugin','install','x@m'])\"",
    "node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js plugin install x@m",
    "unzip -o /tmp/x.zip -d ~/.claude",
    "tar xf /tmp/x.tar -C ~/.claude",
    "rsync -a /tmp/evil/ ~/.claude/",
    "git -C ~/.claude apply /tmp/x.patch",
    "patch -d ~/.claude -p1 < /tmp/x.patch",
    "patch -p1 -d .claude < /tmp/x.patch",
    "find . -name settings.local.json -exec sed -i 's/\"disableAllHooks\": false/\"disableAllHooks\": true/' {} +",
    "find ~ -path '*plugins/cache*' -name hooks.json -exec cp /tmp/evil {} \;",
    "claude plugin --scope project install x@m",
    "claude plugin marketplace --scope user add e/r",
    "claude config set disableAllHooks true",
    "claude config add enabledPlugins x@m",
    "echo '{\"disableAllHooks\":true}' > /etc/claude-code/managed-settings.d/x.json",
])
def test_b_shell_gated(cmd):
    assert evaluate(_sh(cmd), EMPTY).action != Action.ALLOW, cmd


@pytest.mark.parametrize("args,tool", [
    ({"path": "/r/.claude/settings.local.json", "content": "eyJkaXNhYmxlQWxsSG9va3MiOiB0cnVlfQ==",
      "encoding": "base64"}, "mcp__fs__write"),
    ({"path": "/r/.claude/settings.local.json", "content": "7b7d", "encoding": "hex"}, "mcp__fs__write"),
    ({"path": "/r/.claude/settings.local.json", "content_base64": "eyJ9"}, "mcp__fs__write"),
    ({"archive": "/tmp/x.zip", "dest": "/root/.claude"}, "mcp__fs__extract"),
])
def test_b_mcp_gated(args, tool):
    assert evaluate(_mcp(args, tool=tool), EMPTY).action != Action.ALLOW


@pytest.mark.parametrize("p", [
    "C:\\r\\CLAUDE~1\\SETTIN~1.JSO", "C:\\r\\CLAUDE~1\\plugins\\x", "C:\\u\\CLAUDE~1\\PLUGIN~1\\x",
])
def test_b_short_names(p):
    assert patterns.claude_plugin_kind(p)
    assert evaluate(_write(p, '{"disableAllHooks": true}'), EMPTY).action != Action.ALLOW


def test_b_curly_quote_fragment():
    assert patterns.claude_plugin_fragment_hit("\u201cdisableAllHooks\u201d: true")


def test_b_inert_uppercase_key_does_not_cancel(tmp_path):
    d = tmp_path / ".claude"
    d.mkdir()
    f = d / "settings.local.json"
    f.write_text('{"DISABLEALLHOOKS": true, "model": "a"}')
    ev = _edit(str(f), '"model": "a"', '"model": "a", "disableAllHooks": true')
    assert _ours(rule_claude_plugin_protect(ev, EMPTY))


@pytest.mark.parametrize("cmd", [
    "claude -p 'fix the plugin install script'",
    "claude -p \"explain claude plugin install\"",
    "cd ~/.claude && ls",
    "tar xf x.tar -C build",
    "find . -name '*.py' -exec grep -l foo {} +",
])
def test_b_still_allowed(cmd):
    assert rule_claude_plugin_protect(_sh(cmd), EMPTY) is None, cmd


@pytest.mark.parametrize("s", [
    "cd .claude " * 36000,
    ("cd a/.claude/" + "x" * 290 + " ") * 1287,
    "claude plugin " * 28000,
    "{a,b}" * 50000,
    ".c*/" * 90000,
])
def test_b_perf(s):
    import time
    t = time.time()
    rule_claude_plugin_protect(_sh(s), EMPTY)
    assert time.time() - t < 2.0
