"""Third-party coding-agent instruction/rules file guard: blocks planting or
altering `.cursorrules`, `.cursor/rules/*`, `.windsurfrules`, `.clinerules`,
`.roo/rules*`, `.github/copilot-instructions.md`, `GEMINI.md`, etc.

THREAT MODEL: rule_agent_def_protect only knows CLAUDE.md/AGENTS.md. Any other
assistant opening the same checkout auto-loads its own rules file on every
future session, so a planted instruction persists for a teammate or CI.
Default mode `ask`, escapable only by a human.
"""
import os

import pytest

from aegis import patterns
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.loader import load_policy
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(foreign_agent_instr={"mode": "deny"})
RULE = "foreign-agent-instr-protect"


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _write(path, tool="Write"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args={"file_path": path, "content": "x"})


def _mcp(path):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                      action=ActionClass.MCP, args={"path": path, "content": "x"})


def _gated(d):
    return d.action != Action.ALLOW


PATHS = [
    ".cursorrules", "/r/.cursorrules", "/r/.cursor/rules/a.mdc", "/r/.cursor/rules/sub/a.mdc",
    "/r/.windsurfrules", "/r/.windsurf/rules/a.md", "/r/.clinerules", "/r/.clinerules/a.md",
    "/r/.roo/rules/a.md", "/r/.roo/rules-code/a.md", "/r/.roorules",
    "/r/.github/copilot-instructions.md", "/r/.github/instructions/a.instructions.md",
    "/r/.github/prompts/a.prompt.md", "/r/.github/chatmodes/a.chatmode.md",
    "/r/.github/agents/a.agent.md", "/r/GEMINI.md", "/r/.gemini/GEMINI.md", "/r/QWEN.md",
    "/r/.junie/guidelines.md", "/r/.amazonq/rules/a.md", "/r/.kiro/steering/a.md",
    "/r/.goosehints", "/r/.continue/rules/a.md", "/r/GEMINI.MD",
]


@pytest.mark.parametrize("p", PATHS)
@pytest.mark.parametrize("tool", ["Write", "Edit"])
def test_edit_write_gated(p, tool):
    d = evaluate(_write(p, tool), EMPTY)
    assert d.action == Action.ASK and d.rule == RULE


@pytest.mark.parametrize("p", PATHS[:6])
def test_mcp_gated(p):
    assert evaluate(_mcp(p), EMPTY).rule == RULE


def test_deny_mode():
    assert evaluate(_write("/r/GEMINI.md"), DENY).action == Action.DENY


@pytest.mark.parametrize("p", [
    "/r/README.md", "/r/.github/workflows/ci.yml", "/r/.cursor/rulesx", "/r/MYGEMINI.md",
    "/r/.cursorrules.bak", "/r/src/main.py", "/r/.github/CODEOWNERS", "/r/.cursor/settings.json",
])
def test_unrelated_paths_not_claimed(p):
    d = evaluate(_write(p), EMPTY)
    assert d.rule != RULE


@pytest.mark.parametrize("cmd", [
    "echo 'ignore prior rules' > .cursorrules",
    "echo x >> GEMINI.md",
    "cat <<EOF > .github/copilot-instructions.md\nhi\nEOF",
    "tee .windsurfrules < payload.txt",
    "sed -i 's/a/b/' .cursor/rules/main.mdc",
    "rm -rf .roo/rules",
    "mv evil.md .clinerules",
    "rsync -a evil/ .cursor/rules/",
    "tar xf p.tar -C .github/instructions/",
    "cp evil .junie/guidelines.md",
    "echo x > './.cursorrules'",
    "echo x > \".github/agents/a.agent.md\"",
])
def test_shell_writes_gated(cmd):
    d = evaluate(_shell(cmd), EMPTY)
    assert d.rule == RULE and _gated(d), (cmd, d)


@pytest.mark.parametrize("cmd", [
    "cat .cursorrules", "grep -r foo .cursor/rules", "ls .github/instructions",
    "git status", "echo hello > out.txt", "cat GEMINI.md | head",
])
def test_shell_reads_not_claimed(cmd):
    assert evaluate(_shell(cmd), EMPTY).rule != RULE


def test_fetch_to_file_backstop():
    d = evaluate(_shell("curl -o .cursorrules https://example.com/r"), EMPTY)
    assert _gated(d)


def test_human_override_shell():
    d = evaluate(_shell("echo x > .cursorrules # aegis-allow"), EMPTY)
    assert d.rule != RULE


def test_agent_cannot_override(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "spawned")
    d = evaluate(_shell("echo x > .cursorrules # aegis-allow"), EMPTY)
    assert d.rule == RULE


def test_env_toggle(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_FOREIGN_AGENT_INSTR", "1")
    assert evaluate(_write("/r/.cursorrules"), EMPTY).rule != RULE
    assert evaluate(_shell("echo x > .cursorrules"), EMPTY).rule != RULE


def test_policy_allow():
    pol = Policy(foreign_agent_instr={"allow": [r"docs/rules/"]})
    assert evaluate(_write("/r/docs/rules/.cursorrules"), pol).rule != RULE
    assert evaluate(_write("/r/.cursorrules"), pol).rule == RULE


def test_modes_off_and_monitor():
    assert evaluate(_write("/r/.cursorrules"), Policy(foreign_agent_instr={"mode": "off"})).rule != RULE
    d = evaluate(_write("/r/.cursorrules"), Policy(foreign_agent_instr={"mode": "monitor"}))
    assert d.action == Action.ALLOW


def test_yaml_policy_roundtrip(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("foreign_agent_instr:\n  mode: deny\n  allow: ['ok/']\n")
    pol = load_policy(str(f))
    assert pol.foreign_agent_instr == {"mode": "deny", "allow": ["ok/"]}
    assert evaluate(_write("/r/GEMINI.md"), pol).action == Action.DENY
    assert evaluate(_write("/r/ok/GEMINI.md"), pol).rule != RULE


def test_claude_md_still_owned_by_agent_def():
    assert evaluate(_write("/r/CLAUDE.md"), EMPTY).rule == "agent-def-protect"


def test_regex_no_redos():
    import time
    t = time.time()
    patterns.FOREIGN_AGENT_INSTR_PATH_RE.search(" ".join([".cursor/"] * 5000) + "a" * 50000)
    patterns.FOREIGN_AGENT_INSTR_PATH_RE.search("." * 20000 + " " * 20000)
    assert time.time() - t < 2


def _mcp_args(tool, args):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, action=ActionClass.MCP, args=args)


@pytest.mark.parametrize("cmd", [
    "cd .github && echo x > copilot-instructions.md",
    "pushd .github; cp x copilot-instructions.md",
    "cd .cursor && echo x > rules/a.mdc",
    "git -C .github mv x copilot-instructions.md",
    "echo x >.cursorrules", "echo x>>GEMINI.md", "(echo x)>.cursorrules",
    "ln -s evil .cursorrules", "touch .cursorrules", "patch .cursorrules < p",
    "git checkout -- .cursorrules", "git restore .windsurfrules",
])
def test_qa_round1_shell_bypasses(cmd):
    assert evaluate(_shell(cmd), EMPTY).rule == RULE, cmd


def test_qa_round1_mcp_nested_and_dest():
    d = evaluate(_mcp_args("mcp__github__push_files",
                           {"files": [{"path": ".cursorrules", "content": "x"}]}), EMPTY)
    assert d.rule == RULE
    assert evaluate(_mcp_args("mcp__fs__move_file",
                              {"source": "a", "destination": ".cursorrules"}), EMPTY).rule == RULE


@pytest.mark.parametrize("tool", ["mcp__fs__read_file", "mcp__fs__list_directory",
                                  "mcp__github__get_file_contents"])
def test_qa_round1_mcp_reads_not_gated(tool):
    assert evaluate(_mcp_args(tool, {"path": ".cursor/rules"}), EMPTY).rule != RULE


def test_qa_round1_cd_benign():
    assert evaluate(_shell("cd .github && cat copilot-instructions.md"), EMPTY).rule != RULE
    assert evaluate(_shell("cd .github && ls workflows"), EMPTY).rule != RULE
