"""Cargo exec-hijack guard: program-naming keys in .cargo/config(.toml), via
`cargo --config`, or CARGO_*/RUSTC_* env vars. Default mode: ask."""
import pytest

from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(cargo_exec={"mode": "deny"})
RULE = "cargo-exec-protect"


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write",
                      args={"file_path": path, "content": content})


def _edit(path, new):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                      args={"file_path": path, "new_string": new})


def _mcp(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write_file",
                      args={"path": path, "content": content})


def _hit(ev, pol=EMPTY):
    d = evaluate(ev, pol)
    return d.rule == RULE, d


@pytest.mark.parametrize("content", [
    '[build]\nrustc-wrapper = "/tmp/evil"\n',
    '[build]\nrustc-workspace-wrapper = "./w.sh"\n',
    '[build]\nrustc = "/tmp/rustc"\n',
    '[target.x86_64-unknown-linux-gnu]\nlinker = "/tmp/ld"\n',
    '[target.x86_64-unknown-linux-gnu]\nrunner = "sh -c evil"\n',
    '[registry]\ncredential-provider = ["/tmp/p"]\n',
    '[registry]\ncredential-process = "/tmp/p"\n',
    'build.rustc-wrapper = "/tmp/evil"\n',
    '[build]\n"rustc-wrapper" = "sccache-evil"\n',
    '[build]\nrustc-wrapper = "/usr/bin/sccache"\n',   # path-qualified: not exempt
])
@pytest.mark.parametrize("path", [".cargo/config.toml", ".cargo/config",
                                  "/repo/sub/.cargo/config.toml", ".cargo\\config.toml"])
def test_file_write_asks(path, content):
    for ev in (_write(path, content), _edit(path, content), _mcp(path, content)):
        ok, d = _hit(ev)
        assert ok and d.action == Action.ASK


def test_deny_mode():
    ok, d = _hit(_write(".cargo/config.toml", '[build]\nrustc-wrapper="/x"\n'), DENY)
    assert ok and d.action == Action.DENY


@pytest.mark.parametrize("content", [
    '[build]\nrustc-wrapper = "sccache"\n',
    '[build]\nrustc-wrapper = "ccache" # cache\n',
    '[build]\njobs = 4\n',
    '[alias]\nb = "build"\n',
    '# rustc-wrapper = "/tmp/evil"\n[build]\njobs = 2\n',
    '[net]\nretry = 3\n',
])
def test_benign_config_allowed(content):
    assert not _hit(_write(".cargo/config.toml", content))[0]


def test_other_file_ignored():
    assert not _hit(_write("notes.toml", '[build]\nrustc-wrapper="/x"\n'))[0]


@pytest.mark.parametrize("cmd", [
    "echo '[build]\nrustc-wrapper=\"/tmp/e\"' >> .cargo/config.toml",
    "printf 'runner = \"sh x\"' > ~/.cargo/config",
    "cargo build --config 'build.rustc-wrapper=\"/tmp/e\"'",
    "cargo test --config=target.x86_64-unknown-linux-gnu.runner='/tmp/e'",
    "RUSTC_WRAPPER=/tmp/evil cargo build",
    "export RUSTC_WRAPPER=/tmp/evil",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=/tmp/e cargo test",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/tmp/e cargo build",
    "CARGO_REGISTRIES_FOO_CREDENTIAL_PROVIDER=/tmp/p cargo publish",
    "RUSTC_WORKSPACE_WRAPPER=./w cargo check",
])
def test_shell_asks(cmd):
    ok, d = _hit(_shell(cmd))
    assert ok and d.action == Action.ASK


@pytest.mark.parametrize("cmd", [
    "cargo build",
    "RUSTC_WRAPPER=sccache cargo build",
    "export RUSTC_WRAPPER=sccache",
    "cargo build --config 'build.jobs=4'",
    "cat .cargo/config.toml",
    "echo jobs=4 >> .cargo/config.toml",
])
def test_shell_benign_allowed(cmd):
    assert not _hit(_shell(cmd))[0]


def test_human_override_shell():
    assert not _hit(_shell("RUSTC_WRAPPER=/tmp/e cargo build  # aegis-allow"))[0]


def test_env_toggle(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert not _hit(_write(".cargo/config.toml", '[build]\nrustc-wrapper="/x"\n'))[0]
    assert not _hit(_shell("RUSTC_WRAPPER=/tmp/e cargo build"))[0]


def test_policy_allow_and_off_and_monitor():
    w = _write("vendor/.cargo/config.toml", '[build]\nrustc-wrapper="/x"\n')
    assert not _hit(w, Policy(cargo_exec={"allow": [r"vendor/"]}))[0]
    assert not _hit(w, Policy(cargo_exec={"mode": "off"}))[0]
    assert not _hit(w, Policy(cargo_exec={"mode": "monitor"}))[0]


def test_yaml_policy_round_trip(tmp_path):
    from aegis.loader import load_policy
    w = _write("sub/.cargo/config.toml", '[build]\nrustc-wrapper="/x"\n')
    f = tmp_path / "p.yaml"
    f.write_text("cargo_exec:\n  mode: deny\n")
    d = evaluate(w, load_policy(str(f)))
    assert d.rule == RULE and d.action == Action.DENY
    f.write_text("cargo_exec:\n  allow: ['sub/\\.cargo']\n")
    assert evaluate(w, load_policy(str(f))).rule != RULE
    f.write_text("cargo_exec:\n  mode: off\n")
    assert evaluate(w, load_policy(str(f))).rule != RULE


def test_no_redos():
    big = '[build]\n' + 'rustc-wrapper' * 20000
    import time
    t = time.time()
    _hit(_write(".cargo/config.toml", big))
    _hit(_shell("RUSTC_WRAPPER " * 20000))
    assert time.time() - t < 3


@pytest.mark.parametrize("cmd", [
    "RUSTC=/tmp/e cargo build", "export RUSTC=/tmp/e", "RUSTDOC=/tmp/e cargo doc",
    "RUSTC_WRAPPER='sccache /tmp/e' cargo build",
    'export RUSTC_WRAPPER="sccache /tmp/e"',
    "CARGO_BUILD_RUSTC_WRAPPER='ccache /tmp/e' cargo b",
    "cargo build --config 'build.rustc-wrapper=\"sccache /tmp/e\"'",
    "CARGO_REGISTRY_GLOBAL_CREDENTIAL_PROVIDERS=/tmp/e cargo publish",
    "CARGO_REGISTRY_CREDENTIAL_PROCESS=/tmp/e cargo publish",
    "CARGO_HOST_LINKER=/tmp/e cargo build",
    "cargo build --config 'registry.global-credential-providers=[\"/tmp/e\"]'",
    "cargo build --config 'target.\"cfg(unix)\".linker=\"/tmp/e\"'",
    "cargo build --config 'build={rustc-wrapper=\"/tmp/e\"}'",
    "cargo build --config 'target={x={linker=\"/tmp/e\"}}'",
    "cargo doc --config 'doc.browser=\"/tmp/e\"'",
    'printf "[build]\\nrustc-wrapper=\\"/tmp/e\\"\\n" > .cargo/config.toml',
    "echo -e '[build]\\nrustc-wrapper=\"/tmp/e\"' >> .cargo/config.toml",
    "echo 'build.rustc-wrapper=\"/tmp/e\"' > $CARGO_HOME/config.toml",
    'echo \'runner="x"\' > "${CARGO_HOME:-$HOME/.cargo}/config.toml"',
    "cp /tmp/x.toml .cargo/config.toml",
    "sed -i 's#sccache#/tmp/e#' .cargo/config.toml",
])
def test_qa_round1_shell_bypasses_closed(cmd):
    ok, d = _hit(_shell(cmd))
    assert ok and d.action == Action.ASK


@pytest.mark.parametrize("content", [
    "[build]\nrustc-wrapper = '''sccache\nevil'''\n",
    '[build]\nrustc-wrapper = """sccache\nevil"""\n',
    '[build]\nrustc-wrapper = "sccache # x"\n',
    '[build]\nrustc-wrapper = ["sccache", "evil"]\n',
    '[registry]\nglobal-credential-providers = ["/tmp/e"]\n',
    '[doc]\nbrowser = "/tmp/e"\n',
    '[build]\nrustc-wrapper = "SCCACHE"\n',
])
def test_qa_round1_file_bypasses_closed(content):
    assert _hit(_write(".cargo/config.toml", content))[0]


@pytest.mark.parametrize("path", ["/opt/cargo/config.toml"])
def test_cargo_dir_without_dot(path):
    assert _hit(_write(path, '[build]\nrustc-wrapper="/x"\n'))[0]


def test_value_only_edit_asks():
    assert _hit(_edit(".cargo/config.toml", "/tmp/evil"))[0]
    assert _hit(_edit(".cargo/config.toml", '"/tmp/evil"'))[0]
    assert not _hit(_edit(".cargo/config.toml", "[build]\njobs = 4\n"))[0]


@pytest.mark.parametrize("cmd", [
    "export RUSTC_WRAPPER=sccache; cargo build",
    "RUSTC_WRAPPER=sccache&& cargo build",
    "unset RUSTC_WRAPPER", "echo $RUSTC_WRAPPER", "env -u RUSTC_WRAPPER cargo build",
    "grep -rn RUSTC_WRAPPER .", "RUSTC_WRAPPER= cargo build",
    'RUSTC_WRAPPER="" cargo build',
    "cargo build --config 'build.rustc-wrapper=\"\"'",
    "cargo build --config 'build.rustc-wrapper=\"sccache\"'",
])
def test_qa_round1_false_asks_closed(cmd):
    assert not _hit(_shell(cmd))[0]


@pytest.mark.parametrize("content", [
    '[build]\nrustc-wrapper = ""\n',
    'build = { rustc-wrapper = "sccache" }\n',
    'build = { jobs = 2, rustc-wrapper = "sccache" }\n',
    '[build]\nrustc-wrapper = ["sccache"]\n',
])
def test_qa_round1_benign_file_forms(content):
    assert not _hit(_write(".cargo/config.toml", content))[0]
