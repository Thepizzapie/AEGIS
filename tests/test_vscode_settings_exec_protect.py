"""VS Code settings.json executable-path hijack guard (git.path, python
interpreter, terminal profiles, language-server paths).

THREAT MODEL: rule_vscode_tasks_protect gates .vscode/settings.json only for
`task.allowAutomaticTasks: "on"`. Pointing `git.path` (or an interpreter /
terminal-profile path) at an attacker script runs it on the next folder
open with no task and no prompt. Default mode ask, human-escapable only.
"""
from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(vscode_settings_exec={"mode": "deny"})
RULE = "vscode-settings-exec-protect"
S = ".vscode/settings.json"


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write", args={"file_path": path, "content": content})


def _edit(path, s):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit", args={"file_path": path, "new_string": s})


def _mcp(path, **kw):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write_file", args={"path": path, **kw})


def _hit(ev, pol=EMPTY):
    d = evaluate(ev, pol)
    return d.rule == RULE


HOSTILE = [
    '{"git.path": "./.vscode/evil.sh"}',
    '{ "python.defaultInterpreterPath" : "/tmp/py" }',
    '{"terminal.integrated.automationProfile.linux": {"path": "/tmp/x"}}',
    '{"terminal.integrated.profiles.linux": {"b": {"path": "/tmp/x"}}}',
    '{"terminal.integrated.shell.linux": "/tmp/x"}',
    '{"php.validate.executablePath": "/tmp/php"}',
    '{"typescript.tsdk": "./evil/lib"}',
    '{"eslint.nodePath": "./evil"}',
    '{"rust-analyzer.server.path": "/tmp/ra"}',
    '{"GIT.PATH": "x"}',
]


def test_write_hostile_asks():
    for c in HOSTILE:
        d = evaluate(_write(S, c), EMPTY)
        assert d.rule == RULE and d.action == Action.ASK, c


def test_edit_and_nested_and_windows_paths():
    assert _hit(_edit("/repo/.vscode/settings.json", '"git.path": "x"'))
    assert _hit(_write("C:\\repo\\.vscode\\settings.json", HOSTILE[0]))
    assert _hit(_write("/repo/sub/.vscode/settings.json", HOSTILE[0]))


def test_mcp_forms():
    assert _hit(_mcp(S, content=HOSTILE[0]))
    assert _hit(_mcp(S, key="git.path", value="/tmp/x"))


def test_deny_mode():
    assert evaluate(_write(S, HOSTILE[0]), DENY).action == Action.DENY


def test_benign_settings_not_flagged():
    for c in ['{"editor.tabSize": 2}', '{"files.autoSave": "on"}',
              '{"python.analysis.typeCheckingMode": "basic"}',
              '{"terminal.integrated.fontSize": 14}',
              '{"typescript.preferences.quoteStyle": "single"}']:
        assert not _hit(_write(S, c)), c


def test_other_files_not_flagged():
    assert not _hit(_write("README.md", HOSTILE[0]))
    assert not _hit(_write("src/settings.json", HOSTILE[0]))
    assert not _hit(_write(".vscode-old/settings.json", HOSTILE[0]))


def test_shell_writes():
    for cmd in [
        'echo \'{"git.path":"./x.sh"}\' > .vscode/settings.json',
        "cat > .vscode/settings.json <<'E'\n{\"git.path\": \"x\"}\nE",
        "jq '.[\"git.path\"]=\"./x.sh\"' .vscode/settings.json | sponge .vscode/settings.json",
        "jq '.[\"python.defaultInterpreterPath\"] |= \"/tmp/p\"' .vscode/settings.json > /tmp/o && mv /tmp/o .vscode/settings.json",
        "jq -i '.\"git.path\" = \"x\"' .vscode/settings.json",
        "cd .vscode && echo '{\"git.path\":\"x\"}' > settings.json",
        "sed -i 's/\"editor.tabSize\"/\"git.path\": \"x\", &/' .vscode/settings.json",
        "echo '\"terminal.integrated.automationProfile.linux\": {}' | tee .vscode/settings.json",
    ]:
        assert _hit(_shell(cmd)), cmd


def test_shell_reads_and_benign_not_flagged():
    for cmd in [
        "cat .vscode/settings.json",
        "grep git.path .vscode/settings.json",
        "jq '.[\"git.path\"]' .vscode/settings.json",
        "echo '{\"editor.tabSize\":2}' > .vscode/settings.json",
        "git status",
        "cd .vscode-old && echo '{\"git.path\":\"x\"}' > settings.json",
    ]:
        assert not _hit(_shell(cmd)), cmd


def test_human_escape_shell_only():
    assert not _hit(_shell('echo \'{"git.path":"x"}\' > .vscode/settings.json # aegis-allow'))


def test_env_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_VSCODE_SETTINGS_EXEC", "1")
    assert not _hit(_write(S, HOSTILE[0]))


def test_policy_allow_and_off_and_monitor():
    assert not _hit(_write(S, HOSTILE[0]), Policy(vscode_settings_exec={"allow": [r"\.vscode/settings"]}))
    assert not _hit(_write(S, HOSTILE[0]), Policy(vscode_settings_exec={"mode": "off"}))
    assert not _hit(_write(S, HOSTILE[0]), Policy(vscode_settings_exec={"mode": "monitor"}))


def test_loader_roundtrip(tmp_path):
    from aegis.loader import load_policy
    f = tmp_path / "p.yaml"
    f.write_text("vscode_settings_exec:\n  mode: deny\n")
    assert load_policy(str(f)).vscode_settings_exec == {"mode": "deny"}


def test_redos_linear():
    import time
    big = '"terminal.integrated.profiles' + ".a" * 20000
    t = time.time()
    _hit(_write(S, big))
    _hit(_shell("echo " + big + " > .vscode/settings.json"))
    assert time.time() - t < 3
