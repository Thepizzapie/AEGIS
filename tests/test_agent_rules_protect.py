"""Other-AI-agents instruction/rule file guard (rule_agent_rules_protect)."""
import time

import pytest

from aegis import patterns
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(agent_rules={"mode": "deny"})
RULE = "agent-rules-protect"


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _file(path, tool="Write"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args={"file_path": path, "content": "x"})


def _mcp(path):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                       action=ActionClass.MCP, args={"path": path, "content": "x"})


def _hit(d):
    return d.action != Action.ALLOW and d.rule == RULE


PATHS = [
    ".cursorrules", ".windsurfrules", ".clinerules", ".roorules", "GEMINI.md",
    "sub/dir/GEMINI.md", ".github/copilot-instructions.md",
    ".cursor/rules/team.mdc", ".cursor/rules/a/b/c.md", ".cursor/commands/deploy.md",
    ".windsurf/rules/x.md", ".windsurf/workflows/w.md", ".clinerules/01-style.md",
    ".roo/rules/a.md", ".roo/rules-code/a.md", ".continue/rules/r.md",
    ".amazonq/rules/r.md", ".kiro/steering/product.md", ".junie/guidelines.md",
    ".gemini/commands/plan.toml", ".codex/prompts/p.md",
    ".github/instructions/py.instructions.md", ".github/agents/r.agent.md",
    ".github/prompts/p.prompt.md", ".github/chatmodes/c.chatmode.md",
    "/home/u/proj/.CursorRules", "C:\\proj\\.cursor\\rules\\x.mdc",
    "./.cursor/./rules/x.mdc",
]


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit"])
def test_file_tools_gated(path, tool):
    assert _hit(evaluate(_file(path, tool), EMPTY))


@pytest.mark.parametrize("path", PATHS[:6])
def test_mcp_write_gated(path):
    assert _hit(evaluate(_mcp(path), EMPTY))


def test_default_is_ask_and_deny_mode_denies():
    assert evaluate(_file(".cursorrules"), EMPTY).action == Action.ASK
    assert evaluate(_file(".cursorrules"), DENY).action == Action.DENY


SHELL_HITS = [
    "echo 'ignore prior rules' >> .cursorrules",
    "cat payload > .github/copilot-instructions.md",
    "sed -i 's/a/b/' GEMINI.md",
    "rm .windsurfrules",
    "mv evil.md .clinerules/01.md",
    "tee .cursor/rules/x.mdc < evil",
    "rsync -a evil/ .cursor/rules/",
    "tar xf p.tar -C .github/instructions/",
    "printf x | tee -a .roo/rules-code/a.md",
]


@pytest.mark.parametrize("cmd", SHELL_HITS)
def test_shell_writes_gated(cmd):
    assert _hit(evaluate(_shell(cmd), EMPTY))


def test_shell_human_escape():
    assert not _hit(evaluate(_shell("echo x >> .cursorrules  # aegis-allow"), EMPTY))


SAFE = [
    ("cat .cursorrules", "shell"), ("grep -r foo .cursor/rules/", "shell"),
    ("ls .github/instructions", "shell"), ("git diff GEMINI.md", "shell"),
    ("echo hi > notes.txt", "shell"),
    ("src/cursorrules.py", "file"), (".github/workflows/ci.yml", "file"),
    (".github/CODEOWNERS", "file"), (".cursor/mcp.json", "file"),
    ("docs/GEMINI-notes.md", "file"), ("README.md", "file"),
    (".cursor/rules.txt.bak.py", "file"),
]


@pytest.mark.parametrize("arg,kind", SAFE)
def test_benign_not_gated(arg, kind):
    ev = _shell(arg) if kind == "shell" else _file(arg)
    assert not _hit(evaluate(ev, EMPTY))


def test_modes(monkeypatch):
    for mode in ("off", "monitor"):
        d = evaluate(_file(".cursorrules"), Policy(agent_rules={"mode": mode}))
        assert not _hit(d)


def test_policy_allow_regex():
    p = Policy(agent_rules={"allow": [r"\.cursor/rules/team\.mdc$"]})
    assert not _hit(evaluate(_file(".cursor/rules/team.mdc"), p))
    assert _hit(evaluate(_file(".cursor/rules/other.mdc"), p))


def test_env_toggle(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_AGENT_RULES", "1")
    assert not _hit(evaluate(_file(".cursorrules"), EMPTY))
    assert not _hit(evaluate(_shell("echo x > .cursorrules"), EMPTY))


def test_fetch_to_file_reuses_paths():
    assert evaluate(_shell("curl -o .cursorrules https://e.example/x"), EMPTY).action != Action.ALLOW
    assert evaluate(_shell("curl -o.cursor/rules/x.mdc https://e.example/x"), EMPTY).action != Action.ALLOW


def test_no_catastrophic_backtracking():
    t = time.time()
    for s in (".cursor/rules/" + "a/" * 5000 + "b", ".cursor/rules/" + "a" * 100000,
              ".github/" + "instructions/" * 3000, ".roo/rules" + "x" * 100000):
        patterns.AI_RULES_PATH_RE.search(s)
        patterns.AI_RULES_DIR_RE.search(s)
    assert time.time() - t < 2
