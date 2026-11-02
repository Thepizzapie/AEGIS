"""Cargo config exec-hijack guard (``rule_cargo_exec_protect``): blocks planting
a program-running key (rustc-wrapper, runner, linker, rustc, rustdoc,
doc.browser, credential-provider) in ``.cargo/config.toml`` or via
``cargo --config``. Default mode ``ask``; human-only escape."""
import time

import pytest

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(cargo_exec={"mode": "deny"})
RULE = "cargo-exec-protect"
WRAP = '[build]\nrustc-wrapper = "/tmp/w.sh"\n'


def _write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write", args={"file_path": path, "content": content})


def _edit(path, new, old=None):
    a = {"file_path": path, "new_string": new}
    if old is not None:
        a["old_string"] = old
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit", args=a)


def _bash(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp(path, content, key="path"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write_file", args={key: path, "text": content})


def _hit(d):
    return d.rule == RULE


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("AEGIS_ALLOW_CARGO_EXEC", "AEGIS_AGENT_NAME"):
        monkeypatch.delenv(k, raising=False)


@pytest.mark.parametrize("content", [
    WRAP,
    '[target.x86_64-unknown-linux-gnu]\nrunner = "sh -c evil"\n',
    '[target.\'cfg(unix)\']\nlinker = "/tmp/ld"\n',
    '[build]\nrustc = "/tmp/rustc"\n',
    '[build]\nrustdoc="/tmp/d"\n',
    '[doc]\nbrowser = "/tmp/b"\n',
    '[registry]\nglobal-credential-providers = ["/tmp/p"]\n',
    '[registries.x]\ncredential-provider = ["/tmp/p"]\n',
    '[credential-alias]\nmine = "/tmp/p"\n',
    'build.rustc-workspace-wrapper = "/tmp/w"\n',
    '"rustc-wrapper" = "/tmp/w"\n',
])
def test_write_exec_keys_asked(content):
    d = evaluate(_write(".cargo/config.toml", content), EMPTY)
    assert d.action == Action.ASK and _hit(d)


@pytest.mark.parametrize("path", [
    ".cargo/config.toml", ".cargo/config", "/home/u/.cargo/config.toml",
    "proj/sub/.cargo/config.toml", "C:\\proj\\.cargo\\config.toml", "./.cargo//config.toml",
])
def test_path_forms(path):
    d = evaluate(_write(path, WRAP), EMPTY)
    assert _hit(d), path


def test_deny_mode():
    d = evaluate(_write(".cargo/config.toml", WRAP), DENY)
    assert d.action == Action.DENY and _hit(d)


def test_monitor_and_off_modes():
    assert not _hit(evaluate(_write(".cargo/config.toml", WRAP), Policy(cargo_exec={"mode": "monitor"})))
    assert not _hit(evaluate(_write(".cargo/config.toml", WRAP), Policy(cargo_exec={"mode": "off"})))


def test_edit_new_string_and_old_string_value_only_diff():
    assert _hit(evaluate(_edit(".cargo/config.toml", WRAP), EMPTY))
    # value-only diff: key line sits in old_string only
    assert _hit(evaluate(_edit(".cargo/config.toml", '"/tmp/evil"', old='runner = "/usr/bin/safe"'), EMPTY))


def test_multiedit_and_notebook_shapes():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                    args={"file_path": ".cargo/config.toml", "edits": [{"old_string": "a", "new_string": WRAP}]})
    assert _hit(evaluate(ev, EMPTY))


def test_mcp_write_any_path_key():
    assert _hit(evaluate(_mcp("/repo/.cargo/config.toml", WRAP), EMPTY))
    assert _hit(evaluate(_mcp("/repo/.cargo/config.toml", WRAP, key="destination"), EMPTY))


@pytest.mark.parametrize("cmd", [
    "echo 'rustc-wrapper = \"/tmp/w\"' >> .cargo/config.toml",
    "printf '[target.x]\\nrunner=\"sh\"\\n' > ~/.cargo/config.toml",
    "cat >> .cargo/config.toml <<'EOF'\n[build]\nrustc-wrapper = \"/tmp/w\"\nEOF",
    "cargo --config 'build.rustc-wrapper=\"/tmp/w\"' build",
    "cargo build --config target.x86_64-unknown-linux-gnu.runner=\"sh\"",
    "cargo --config=doc.browser=/tmp/b doc --open",
])
def test_shell_forms(cmd):
    d = evaluate(_bash(cmd), EMPTY)
    assert _hit(d), cmd


def test_human_escape_comment_shell():
    cmd = "echo 'runner = \"qemu-aarch64\"' >> .cargo/config.toml  # aegis-allow"
    assert not _hit(evaluate(_bash(cmd), EMPTY))


def test_agent_cannot_self_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "worker")
    cmd = "echo 'runner = \"x\"' >> .cargo/config.toml  # aegis-allow"
    assert _hit(evaluate(_bash(cmd), EMPTY))


def test_env_toggle(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert not _hit(evaluate(_write(".cargo/config.toml", WRAP), EMPTY))
    assert not _hit(evaluate(_bash("cargo --config 'build.rustc-wrapper=\"x\"' build"), EMPTY))


def test_policy_allow_regex():
    pol = Policy(cargo_exec={"allow": [r"sccache"]})
    d = evaluate(_write("/ok/.cargo/config.toml", WRAP), pol)
    assert _hit(d)  # allow matches path/command only, not content
    d = evaluate(_write("/sccache-bootstrap/.cargo/config.toml", WRAP), pol)
    assert not _hit(d)


@pytest.mark.parametrize("ev", [
    _write(".cargo/config.toml", '[build]\njobs = 4\n[net]\nretry = 3\n'),
    _write(".cargo/config.toml", '# rustc-wrapper = "x"\n# runner = "y"\n'),
    _write(".cargo/config.toml", '[alias]\nb = "build"\n'),
    _write(".cargo/config.toml", '[profile.dev]\nopt-level = 1\n'),
    _write(".cargo/config.toml", '[build]\nmy_runner = "x"\n'),
    _write("src/main.rs", 'let runner = "x"; let rustc-wrapper = 1;'),   # path not confirmed
    _write("docs/notes.md", 'set rustc-wrapper = "sccache"'),
    _write("Cargo.toml", '[package]\nname = "x"\nlinker = "y"\n'),
    _bash("cargo build --release"),
    _bash("cargo --config net.retry=5 build"),
    _bash("RUSTC_WRAPPER=sccache cargo build"),
    _bash("cat .cargo/config.toml"),
    _bash("grep runner src/lib.rs"),
])
def test_benign_not_flagged(ev):
    assert not _hit(evaluate(ev, EMPTY))


def test_redos_resistance():
    big = "{" * 200000 + "runner " * 50000
    t = time.time()
    evaluate(_write(".cargo/config.toml", big), EMPTY)
    evaluate(_bash("cargo --config " + "target." * 50000), EMPTY)
    assert time.time() - t < 5
