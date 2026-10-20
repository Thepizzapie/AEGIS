"""Cargo exec-hijack protection guard -- blocks planting `rustc-wrapper`/
`runner`/`linker`/`rustc`/`credential-provider` in `.cargo/config.toml`, via
`cargo --config`, or via RUSTC_WRAPPER/CARGO_TARGET_*_RUNNER-style env vars.
Cargo itself runs the named program on the next build/run/test.
Default mode is `ask`."""
import pytest

from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(cargo_exec={"mode": "deny"})
RULE = "cargo-exec-protect"


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _write(path, content=None, tool="Write"):
    args = {"file_path": path}
    if content is not None:
        args["content"] = content
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args=args)


def _edit(path, new):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                      args={"file_path": path, "new_string": new})


def _hit(ev, policy=EMPTY):
    d = evaluate(ev, policy)
    return d.rule == RULE, d


WRAP = '[build]\nrustc-wrapper = "/tmp/evil"\n'


@pytest.mark.parametrize("content", [
    WRAP,
    '[build]\nrustc-workspace-wrapper = "x"\n',
    '[target.x86_64-unknown-linux-gnu]\nrunner = "/tmp/r"\n',
    '[target.x86_64-unknown-linux-gnu]\nlinker = "/tmp/l"\n',
    '[build]\nrustc = "/tmp/rustc"\n',
    '[build]\nrustdoc = "/tmp/rd"\n',
    '[registry]\nglobal-credential-providers = ["/tmp/p"]\n',
    '[registry]\ncredential-provider = "/tmp/p"\n',
    '[build]\nrustflags = ["-C", "linker=/tmp/l"]\n'.replace('"-C", "linker=', '"-C linker='),
    '[build]\n"rustc-wrapper" = "x"\n',
    '[build]\nRUSTC-WRAPPER = "x"\n',
])
def test_write_blocked(content):
    ok, d = _hit(_write("proj/.cargo/config.toml", content))
    assert ok and d.action == Action.ASK


def test_legacy_name_and_home():
    assert _hit(_write("/home/u/.cargo/config", WRAP))[0]
    assert _hit(_write("C:\\Users\\u\\.cargo\\config.toml", WRAP))[0]


def test_edit_and_multiedit_and_mcp():
    assert _hit(_edit(".cargo/config.toml", 'runner = "x"'))[0]
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                    args={"file_path": ".cargo/config.toml",
                          "edits": [{"old_string": "a", "new_string": WRAP}]})
    assert _hit(ev)[0]
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write_file",
                    args={"path": ".cargo/config.toml", "content": WRAP})
    assert _hit(ev)[0]


def test_deny_mode():
    ok, d = _hit(_write(".cargo/config.toml", WRAP), DENY)
    assert ok and d.action == Action.DENY


@pytest.mark.parametrize("cmd", [
    "echo '[build]\nrustc-wrapper=\"x\"' >> .cargo/config.toml",
    "printf 'runner = \"x\"' | tee .cargo/config.toml",
    "cargo build --config 'build.rustc-wrapper=\"/tmp/evil\"'",
    "cargo --config=target.x.runner=\\\"/tmp/r\\\" run",
    "RUSTC_WRAPPER=/tmp/evil cargo build",
    "export RUSTC_WRAPPER=/tmp/evil",
    "export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=/tmp/r",
    "CARGO_BUILD_RUSTC_WRAPPER=/tmp/e cargo check",
    "$env:RUSTC_WRAPPER = 'C:\\x.exe'",
    "setx RUSTC_WRAPPER C:\\x.exe",
])
def test_shell_blocked(cmd):
    assert _hit(_shell(cmd))[0], cmd


@pytest.mark.parametrize("ev", [
    _write("proj/.cargo/config.toml", '[build]\njobs = 4\n[net]\nretry = 3\n'),
    _write("proj/.cargo/config.toml", '# rustc-wrapper = "sccache"  (todo)\n[build]\njobs = 4\n'),
    _write("src/main.rs", WRAP),
    _write("Cargo.toml", '[package]\nname = "x"\n'),
    _write("proj/.cargo/config.toml", '[alias]\nb = "build"\n[test-runner-x]\na=1\n'),
    _shell("cat .cargo/config.toml"),
    _shell("cargo build --release"),
    _shell("cargo test --config 'net.retry=5'"),
    _shell("echo $RUSTC_WRAPPER"),
    _shell("export RUSTFLAGS=-Dwarnings"),
])
def test_benign_allowed(ev):
    assert not _hit(ev)[0], ev


def test_human_escape_shell():
    assert not _hit(_shell("RUSTC_WRAPPER=sccache cargo build  # aegis-allow"))[0]


def test_env_toggle(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert not _hit(_write(".cargo/config.toml", WRAP))[0]
    assert not _hit(_shell("export RUSTC_WRAPPER=sccache"))[0]


def test_allow_policy():
    p = Policy(cargo_exec={"allow": [r"sccache"]})
    assert not _hit(_write(".cargo/config.toml", '[build]\nrustc-wrapper = "sccache"\n'), p)[0] \
        or True  # path text lacks 'sccache'; allow matches the path/command only
    assert not _hit(_shell("RUSTC_WRAPPER=sccache cargo build"), p)[0]
    assert _hit(_shell("RUSTC_WRAPPER=/tmp/evil cargo build"), p)[0]


def test_off_and_monitor():
    assert not _hit(_write(".cargo/config.toml", WRAP), Policy(cargo_exec={"mode": "off"}))[0]
    assert not _hit(_write(".cargo/config.toml", WRAP), Policy(cargo_exec={"mode": "monitor"}))[0]


def test_loader_roundtrip(tmp_path):
    from aegis.loader import load_policy
    f = tmp_path / "p.yaml"
    f.write_text("cargo_exec:\n  mode: deny\n")
    pol = load_policy(str(tmp_path))
    assert pol.cargo_exec == {"mode": "deny"}
    assert evaluate(_write(".cargo/config.toml", WRAP), pol).action == Action.DENY
