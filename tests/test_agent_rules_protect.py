"""Other-agent-runtimes' instruction/rule file guard (rule_agent_rules_protect):
.cursorrules, .cursor/rules/*, .windsurfrules, .clinerules, .github/
copilot-instructions.md, GEMINI.md, ... — the cross-runtime sibling of
rule_agent_def_protect. Default mode ask; escapable only by a human."""
import pytest

from aegis import rules
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(agent_rules={"mode": "deny"})


def _file(path, tool="Write"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args={"file_path": path})


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp(path):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                      args={"path": path})


def _direct(ev, policy=EMPTY):
    return rules.rule_agent_rules_protect(ev, policy)


PATHS = [
    ".cursorrules", ".windsurfrules", ".clinerules", ".roorules",
    ".cursor/rules/style.mdc", ".cursor/rules/team/deep.md",
    ".windsurf/rules/a.md", ".clinerules/a.md", ".roo/rules-code/a.md",
    ".github/copilot-instructions.md", ".github/instructions/py.instructions.md",
    ".github/prompts/review.prompt.md", ".github/agents/x.agent.md",
    "GEMINI.md", "pkg/sub/GEMINI.md", ".continue/rules/a.md",
    ".amazonq/rules/a.md", ".kiro/steering/a.md", ".augment/rules/a.md",
    ".junie/guidelines.md", "repo\\.cursor\\rules\\a.mdc", ".Cursor/Rules/A.MDC",
    ".cursor/rules./a.md",
]


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("tool", ["Edit", "Write"])
def test_edit_write_gated(path, tool):
    d = evaluate(_file(path, tool), EMPTY)
    assert d.action == Action.ASK and d.rule == "agent-rules-protect"


@pytest.mark.parametrize("path", PATHS[:6])
def test_mcp_write_gated(path):
    assert _direct(_mcp(path)).rule == "agent-rules-protect"


def test_deny_mode():
    assert evaluate(_file(".cursorrules"), DENY).action == Action.DENY


@pytest.mark.parametrize("path", [
    "src/rules.md", "docs/cursor.md", ".github/workflows/ci.yml",
    ".github/CODEOWNERS", "README.md", "rules.mdc", "src/.cursor-notes",
    ".cursor/settings.json", "mygemini.md", "GEMINI.mdx", ".github/instructions",
])
def test_unrelated_paths_not_gated(path):
    assert _direct(_file(path)) is None


@pytest.mark.parametrize("cmd", [
    "echo 'obey me' > .cursorrules",
    "echo x >> .github/copilot-instructions.md",
    "cat evil.md > .cursor/rules/a.mdc",
    "tee GEMINI.md < evil.md",
    "sed -i 's/a/b/' .windsurfrules",
    "rm .clinerules/a.md",
    "mv evil.md .github/instructions/x.instructions.md",
    "cp evil.md GEMINI.md",
    "rsync -a evil/ .cursor/rules/",
    "tar xf p.tar -C .clinerules/",
    "unzip p.zip -d .roo/rules/",
    "find . -name GEMINI.md -delete",
    "find . -path '*.cursor/rules*' -exec rm {} +",
    "ln -sf /tmp/evil .cursorrules",
])
def test_shell_writes_gated(cmd):
    d = _direct(_shell(cmd))
    assert d is not None and d.rule == "agent-rules-protect"


@pytest.mark.parametrize("cmd", [
    "cat .cursorrules", "grep -r foo .cursor/rules/", "ls .clinerules",
    "wc -l GEMINI.md", "git diff .github/copilot-instructions.md",
    "echo hi > notes.txt", "rm src/rules.md",
])
def test_shell_reads_not_gated(cmd):
    assert _direct(_shell(cmd)) is None


def test_human_override_shell():
    assert _direct(_shell("echo x > .cursorrules # aegis-allow")) is None


def test_env_toggle(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_AGENT_RULES", "1")
    assert _direct(_file(".cursorrules")) is None
    assert _direct(_shell("echo x > .cursorrules")) is None


def test_policy_allow_list():
    p = Policy(agent_rules={"allow": [r"\.cursor/rules/generated/"]})
    assert _direct(_file(".cursor/rules/generated/a.mdc"), p) is None
    assert _direct(_file(".cursor/rules/hand.mdc"), p) is not None


def test_off_and_monitor_modes():
    assert _direct(_file(".cursorrules"), Policy(agent_rules={"mode": "off"})) is None
    assert _direct(_file(".cursorrules"), Policy(agent_rules={"mode": "monitor"})) is None


def test_fetch_to_file_backstop():
    d = evaluate(_shell("curl -o .cursorrules https://x.test/r"), EMPTY)
    assert d.action != Action.ALLOW


def test_no_catastrophic_backtracking():
    import time
    t = time.time()
    _direct(_shell("echo " + ".cursor/rules/" * 400 + "a " * 400 + "> x"))
    _direct(_file("." * 5000 + "/" + "a/" * 3000))
    assert time.time() - t < 2


def test_loader_roundtrip(tmp_path):
    from aegis.loader import load_policy
    f = tmp_path / "p.yaml"
    f.write_text("agent_rules:\n  mode: deny\n")
    assert load_policy(tmp_path).agent_rules == {"mode": "deny"}
