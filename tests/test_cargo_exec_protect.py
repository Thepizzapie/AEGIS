"""Cargo config exec-hijack protection guard — blocks planting a key in
``.cargo/config.toml`` (or legacy ``.cargo/config``) that names a program Cargo
itself executes on every future build/run/test under that directory:
``rustc-wrapper``/``rustc-workspace-wrapper``/``rustc``/``rustdoc``, a
``[target.*]`` ``linker``/``runner``, registry ``credential-process``/
``credential-provider``.

Default mode is ``ask`` (sccache/mold/clang linkers are routine). Escapable only
by a human (``# aegis-allow`` / ``AEGIS_ALLOW_CARGO_EXEC=1``).
"""
import time

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(cargo_exec={"mode": "deny"})
RULE = "cargo-exec-protect"
CFG = ".cargo/config.toml"


def _ev(tool, **args):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args=args)


def _write(path, content):
    return _ev("Write", file_path=path, content=content)


def _edit(path, new):
    return _ev("Edit", file_path=path, new_string=new)


def _shell(cmd):
    return _ev("Bash", command=cmd)


def _mcp(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                      action=ActionClass.MCP, args={"path": path, "content": content})


def _gated(d):
    return d.action != Action.ALLOW and d.rule == RULE


# ---- positives -----------------------------------------------------------------

def test_rustc_wrapper_write_gated():
    assert _gated(evaluate(_write(CFG, '[build]\nrustc-wrapper = "/tmp/x"\n'), EMPTY))


def test_rustc_workspace_wrapper_gated():
    assert _gated(evaluate(_edit(CFG, 'rustc-workspace-wrapper = "/tmp/x"'), EMPTY))


def test_target_runner_and_linker_gated():
    for body in ('[target.x86_64-unknown-linux-gnu]\nrunner = "/tmp/x"\n',
                 '[target.x86_64-unknown-linux-gnu]\nlinker = "/tmp/x"\n',
                 '[target.\'cfg(unix)\']\nrunner = ["sh", "-c"]\n'):
        assert _gated(evaluate(_write(CFG, body), EMPTY)), body


def test_rustc_and_rustdoc_replacement_gated():
    assert _gated(evaluate(_edit(CFG, 'rustc = "/tmp/evil"'), EMPTY))
    assert _gated(evaluate(_edit(CFG, 'rustdoc = "/tmp/evil"'), EMPTY))


def test_credential_process_and_provider_gated():
    assert _gated(evaluate(_edit(CFG, 'credential-process = "/tmp/x"'), EMPTY))
    assert _gated(evaluate(_write(
        CFG, '[registry]\ncredential-provider = ["/tmp/x"]\n'), EMPTY))


def test_dotted_and_inline_table_forms_gated():
    assert _gated(evaluate(_edit(CFG, 'build.rustc-wrapper = "/tmp/x"'), EMPTY))
    assert _gated(evaluate(_edit(CFG, 'target.x.linker = "/tmp/x"'), EMPTY))
    assert _gated(evaluate(_edit(CFG, 'build = { rustc-wrapper = "/tmp/x" }'), EMPTY))


def test_quoted_key_gated():
    assert _gated(evaluate(_edit(CFG, '"rustc-wrapper" = "/tmp/x"'), EMPTY))


def test_rustflags_linker_gated_when_path_confirmed():
    assert _gated(evaluate(_edit(CFG, 'rustflags = ["-Clinker=/tmp/x"]'), EMPTY))


def test_legacy_config_filename_and_variants_gated():
    for path in (".cargo/config", "/home/u/proj/.cargo/config.toml", "sub/.CARGO/Config.TOML",
                 ".cargo\\config.toml", "/home/u/.cargo/config.toml"):
        assert _gated(evaluate(_edit(path, 'rustc-wrapper = "/tmp/x"'), EMPTY)), path


def test_staged_elsewhere_strong_gated():
    assert _gated(evaluate(_write("/tmp/staged.toml",
                                  '[build]\nrustc-wrapper = "/tmp/x"\n'), EMPTY))
    assert _gated(evaluate(_write("/tmp/staged.toml",
                                  '[target.aarch64-apple-darwin]\nrunner = "/tmp/x"\n'), EMPTY))


def test_multiedit_nested_gated():
    ev = _ev("MultiEdit", file_path=CFG,
             edits=[{"old_string": "a", "new_string": 'rustc-wrapper = "/tmp/x"'}])
    assert _gated(evaluate(ev, EMPTY))


def test_mcp_write_gated():
    assert _gated(evaluate(_mcp("/home/u/proj/.cargo/config.toml",
                                '[build]\nrustc-wrapper = "/tmp/x"'), EMPTY))
    assert _gated(evaluate(_mcp(CFG, 'linker = "/tmp/x"'), EMPTY))


def test_mcp_unknown_path_key_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__x__put", action=ActionClass.MCP,
                    args={"target": CFG, "body": 'runner = "/tmp/x"'})
    assert _gated(evaluate(ev, EMPTY))


def test_shell_redirect_gated():
    assert _gated(evaluate(_shell(
        "printf '[build]\\nrustc-wrapper=\"/tmp/x\"\\n' > .cargo/config.toml"), EMPTY))
    assert _gated(evaluate(_shell(
        "echo 'linker = \"/tmp/x\"' >> ~/.cargo/config.toml"), EMPTY))


def test_shell_heredoc_gated():
    assert _gated(evaluate(_shell(
        "cat > .cargo/config.toml <<EOF\n[target.x]\nrunner = \"/tmp/x\"\nEOF"), EMPTY))


def test_shell_sed_inplace_gated():
    assert _gated(evaluate(_shell(
        "sed -i 's|^\\[build\\]|[build]\\nrustc-wrapper = \"/tmp/x\"|' .cargo/config.toml"), EMPTY))


def test_shell_tee_to_staged_strong_gated():
    assert _gated(evaluate(_shell(
        "printf '[build]\\nrustc-wrapper=\"/x\"\\n' > /tmp/a && mv /tmp/a .cargo/config.toml"), EMPTY))


def test_deny_mode_blocks():
    d = evaluate(_write(CFG, 'rustc-wrapper = "/tmp/x"'), DENY)
    assert d.blocked and d.rule == RULE


# ---- negatives -----------------------------------------------------------------

def test_unrelated_cargo_config_allowed():
    for body in ('[build]\njobs = 4\n', '[net]\nretry = 3\n',
                 '[alias]\nb = "build"\n', '[term]\ncolor = "always"\n'):
        assert not _gated(evaluate(_write(CFG, body), EMPTY)), body


def test_exec_words_in_unrelated_file_allowed():
    assert not _gated(evaluate(_write("notes.md", "set a runner = x and linker = y"), EMPTY))
    assert not _gated(evaluate(_write("setup.cfg", "[tool]\nrunner = pytest\nlinker = ld\n"), EMPTY))
    # ...but a Cargo `[target.*]` header + runner is the strong, path-independent form
    assert _gated(evaluate(_write("ci.toml", "[target.x]\nrunner = \"a\"\n"), EMPTY))


def test_ambiguous_keys_without_cargo_section_allowed_elsewhere():
    # `runner`/`linker` need a Cargo section header OR the cargo path.
    assert not _gated(evaluate(_write("conf.toml", 'runner = "x"\nlinker = "y"\n'), EMPTY))


def test_comment_only_mention_allowed():
    assert not _gated(evaluate(_write(CFG, '# set rustc-wrapper = "sccache" here\n[build]\njobs = 2\n'), EMPTY))
    assert not _gated(evaluate(_write(CFG, '[build]\n# linker = "x"\njobs = 2\n'), EMPTY))


def test_shell_read_or_grep_allowed():
    assert not _gated(evaluate(_shell("cat .cargo/config.toml"), EMPTY))
    assert not _gated(evaluate(_shell("grep -n rustc-wrapper .cargo/config.toml"), EMPTY))
    assert not _gated(evaluate(_shell("cargo build"), EMPTY))


def test_no_cross_section_false_strong():
    body = '[target.x]\nfoo = 1\n[profile.release]\nlinker = "irrelevant-not-cargo"\n'
    assert not _gated(evaluate(_write("/tmp/other.toml", body), EMPTY))


def test_prose_cargo_path_without_key_allowed():
    assert not _gated(evaluate(_write(CFG, "[build]\njobs = 8\n"), EMPTY))


# ---- escapes -------------------------------------------------------------------

def test_shell_aegis_allow_escape():
    d = evaluate(_shell("echo 'rustc-wrapper=\"sccache\"' >> .cargo/config.toml # aegis-allow"), EMPTY)
    assert not _gated(d)


def test_env_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert not _gated(evaluate(_write(CFG, 'rustc-wrapper = "sccache"'), EMPTY))


def test_policy_allow_regex():
    pol = Policy(cargo_exec={"allow": [r"sccache|vendored/\.cargo"]})
    assert not _gated(evaluate(_write("vendored/.cargo/config.toml", 'rustc-wrapper = "x"'), pol))
    assert _gated(evaluate(_write(CFG, 'rustc-wrapper = "x"'), pol))


def test_monitor_mode_allows():
    pol = Policy(cargo_exec={"mode": "monitor"})
    assert evaluate(_write(CFG, 'rustc-wrapper = "x"'), pol).action == Action.ALLOW


def test_off_mode_allows():
    assert evaluate(_write(CFG, 'rustc-wrapper = "x"'),
                    Policy(cargo_exec={"mode": "off"})).action == Action.ALLOW


def test_shell_deny_mode_blocks():
    d = evaluate(_shell("echo 'linker=\"/x\"' >> .cargo/config.toml"), DENY)
    assert d.blocked and d.rule == RULE


def test_shell_env_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert not _gated(evaluate(_shell("echo 'linker=\"/x\"' >> .cargo/config.toml"), EMPTY))


def test_sed_slash_form_gated():
    assert _gated(evaluate(_shell("sed -i 's/a/linker = \"x\"/' .cargo/config.toml"), EMPTY))


def test_registries_header_credential_provider_gated():
    assert _gated(evaluate(_write("/tmp/s.toml",
                                  '[registries.foo]\ncredential-provider = ["/x"]\n'), EMPTY))


def test_yaml_policy_roundtrip(tmp_path):
    from aegis.loader import load_policy
    f = tmp_path / "p.yaml"
    f.write_text("cargo_exec:\n  mode: deny\n")
    pol = load_policy(str(tmp_path))
    assert pol.cargo_exec == {"mode": "deny"}


def test_agent_cannot_self_escape_via_content():
    d = evaluate(_write(CFG, 'rustc-wrapper = "x" # aegis-allow'), EMPTY)
    assert _gated(d)


# ---- fetch-to-file backstop + perf ---------------------------------------------

def test_fetch_to_file_into_cargo_config_gated():
    d = evaluate(_shell("curl -o .cargo/config.toml https://example.com/c.toml"), EMPTY)
    assert d.action != Action.ALLOW and d.rule == "fetch-to-file-protect"


def test_large_input_is_fast():
    body = "[target.x]\n" + ("# filler line\n" * 4000) + "\n".join(["[a]"] * 2000)
    t = time.time()
    evaluate(_write("/tmp/big.toml", body), EMPTY)
    assert time.time() - t < 3
    body = "{" * 20000 + "[" * 20000
    t = time.time()
    evaluate(_write("/tmp/big2.toml", body), EMPTY)
    assert time.time() - t < 3
