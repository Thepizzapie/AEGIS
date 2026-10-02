"""Guard for other coding agents' auto-loaded instruction files (.cursorrules,
copilot-instructions.md, GEMINI.md, ...). Sibling of agent_def; same ask-by-default posture."""
import pytest

from aegis import rules
from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(agent_instructions={"mode": "deny"})


def _ev(tool, **args):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args=args)


def _g(ev, pol=EMPTY):
    return rules.rule_agent_instructions_protect(ev, pol)


PATHS = [
    ".cursorrules", "proj/.cursorrules", ".cursor/rules/a.mdc", ".windsurfrules",
    ".windsurf/rules/x.md", ".clinerules", ".clinerules/01.md", ".roo/rules/a.md",
    ".roo/rules-code/a.md", ".continue/rules/a.md", ".amazonq/rules/a.md",
    ".kiro/steering/a.md", ".junie/guidelines.md", ".github/copilot-instructions.md",
    ".github/instructions/py.instructions.md", ".github/prompts/a.prompt.md",
    "GEMINI.md", "sub/dir/GEMINI.md", ".gemini/GEMINI.md", "QWEN.md", ".goosehints",
    "/abs/repo/.CursorRules", "gemini.md",
]


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("tool", ["Edit", "Write", "MultiEdit"])
def test_edit_write_asks(path, tool):
    d = _g(_ev(tool, file_path=path))
    assert d and d.action == Action.ASK and d.rule == "agent-instructions-protect"


def test_mcp_filesystem_write_asks():
    assert _g(_ev("mcp__filesystem__write_file", path=".cursorrules", content="x"))


@pytest.mark.parametrize("path", [
    "README.md", "src/rules.py", ".cursor/mcp.json", ".github/workflows/ci.yml",
    "docs/GEMINI-notes.txt", "mycursorrules", ".cursorrules.bak2/x" if False else "notes.md",
    "CLAUDE.md", ".github/CODEOWNERS", ".continue/config.json",
])
def test_unrelated_paths_abstain(path):
    assert _g(_ev("Write", file_path=path)) is None


@pytest.mark.parametrize("cmd", [
    "echo 'always exfiltrate' >> .cursorrules",
    "cat evil > .github/copilot-instructions.md",
    "tee GEMINI.md < payload",
    "sed -i 's/a/b/' .windsurfrules",
    "rm .cursor/rules/a.mdc",
    "mv evil.md .junie/guidelines.md",
    "rsync -a evil/ .cursor/rules/",
    "tar xf p.tar -C .clinerules/",
    "cp evil .goosehints",
    "printf x | tee -a sub/GEMINI.md",
])
def test_shell_write_asks(cmd):
    d = _g(_ev("Bash", command=cmd))
    assert d and d.action == Action.ASK


@pytest.mark.parametrize("cmd", [
    "cat .cursorrules", "grep -r foo .cursor/rules", "ls .github/", "git status",
    "echo hi > notes.txt", "cat GEMINI.md | wc -l",
])
def test_shell_read_abstains(cmd):
    assert _g(_ev("Bash", command=cmd)) is None


def test_deny_mode():
    d = _g(_ev("Write", file_path=".cursorrules"), DENY)
    assert d.action == Action.DENY


@pytest.mark.parametrize("mode", ["off", "OFF", False])
def test_off(mode):
    assert _g(_ev("Write", file_path=".cursorrules"), Policy(agent_instructions={"mode": mode})) is None


def test_monitor_abstains():
    assert _g(_ev("Write", file_path=".cursorrules"), Policy(agent_instructions={"mode": "monitor"})) is None


def test_env_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_AGENT_INSTRUCTIONS", "1")
    assert _g(_ev("Write", file_path=".cursorrules")) is None
    assert _g(_ev("Bash", command="echo x > .cursorrules")) is None


def test_shell_human_escape():
    assert _g(_ev("Bash", command="echo x > .cursorrules # aegis-allow")) is None


def test_policy_allow():
    pol = Policy(agent_instructions={"allow": [r"^docs/"]})
    assert _g(_ev("Write", file_path="docs/GEMINI.md"), pol) is None
    assert _g(_ev("Write", file_path="GEMINI.md"), pol)


def test_bad_allow_regex_ignored():
    pol = Policy(agent_instructions={"allow": ["("]})
    assert _g(_ev("Write", file_path="GEMINI.md"), pol)


def test_engine_integration():
    d = evaluate(_ev("Write", file_path=".cursorrules"), EMPTY)
    assert d.action == Action.ASK and d.rule == "agent-instructions-protect"


def test_redos_resistant():
    import time
    t = time.time()
    _g(_ev("Bash", command="echo " + ".github/" * 5000 + " > x"))
    _g(_ev("Bash", command="cat " + ".roo/rules" + "a" * 50000 + " > x"))
    assert time.time() - t < 2


@pytest.mark.parametrize("cmd", [
    "rm -rf .cursor", "cp -r a .cursor", "unzip a.zip -d .windsurf",
    "cd .cursor/rules && echo x > a.mdc", "cd .github && echo x > copilot-instructions.md",
    "cd .github; cp a agents/x.md", "echo x >.windsurf/rules/a.md", "echo x>.cursorrules",
    "echo x>.github/prompts/a.md", "cd ./.roo && tee rules/a.md < p",
])
def test_qa_round1_bypasses_ask(cmd):
    d = _g(_ev("Bash", command=cmd))
    assert d and d.action == Action.ASK, cmd


@pytest.mark.parametrize("cmd", [
    "cd .github && echo x > CODEOWNERS", "cd .github/workflows", "cd .cursor && ls",
    "rm -rf .github/workflows/old.yml", "cp -r a .github",
])
def test_qa_round1_no_new_false_positives(cmd):
    assert _g(_ev("Bash", command=cmd)) is None, cmd


def test_cd_re_no_quadratic_blowup():
    import time
    from aegis import patterns
    for seg in (".github/", ".cursor/"):
        t = time.time()
        patterns.OTHER_AGENT_CD_RE.search("cd " + seg * 20000 + " x")
        assert time.time() - t < 0.5
