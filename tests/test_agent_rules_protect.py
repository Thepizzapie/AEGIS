"""Cross-agent rules/instructions file protection (``agent-rules-protect``).

``agent-def-protect`` gates ``CLAUDE.md``/``AGENTS.md`` only. This guard gates
the equivalent auto-loaded files of every OTHER coding agent (Cursor, Copilot,
Gemini, Windsurf, Cline/Roo/Kilo, Codex, Continue, Aider, Zed, Junie, ...) plus
``.claude/rules/``: one injected write persists across sessions and people and
runs under a different agent's authority. Default ``ask``; content carrying
invisible/bidi/Unicode-tag characters is ``deny`` whatever the mode.
"""
import os

import pytest

from aegis import patterns, rules
from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.loader import load_policy
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(agent_rules={"mode": "deny"})
RULE = "agent-rules-protect"


def _ev(tool, cwd=None, **args):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args=args, cwd=cwd)


def _write(path, content="be helpful", **kw):
    return _ev("Write", file_path=path, content=content, **kw)


def _shell(cmd, **kw):
    return _ev("Bash", command=cmd, **kw)


def _only(ev, policy=EMPTY):
    """This guard's own opinion, bypassing earlier rules in the chain."""
    return rules.rule_agent_rules_protect(ev, policy)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("AEGIS_ALLOW_AGENT_RULES", raising=False)
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)


# ---- the surface ---------------------------------------------------------------
GATED = [
    ".cursorrules",
    "/repo/.cursorrules",
    "/repo/.cursor/rules/style.mdc",
    "/repo/.cursor/rules/a/b/c/d/e/f/deep.mdc",
    "/repo/.cursor/commands/deploy.md",
    "/repo/.github/copilot-instructions.md",
    "/repo/.github/instructions/py.instructions.md",
    "/repo/.github/prompts/review.prompt.md",
    "/repo/.github/chatmodes/arch.chatmode.md",
    "/repo/.github/agents/reviewer.md",
    "/repo/docs/team.instructions.md",
    "/repo/GEMINI.md",
    "/home/u/.gemini/GEMINI.md",
    "/repo/.gemini/commands/x.toml",
    "/repo/AGENTS.override.md",
    "/home/u/.codex/prompts/fix.md",
    "/repo/.windsurfrules",
    "/repo/.windsurf/rules/a.md",
    "/repo/.windsurf/workflows/a.md",
    "/home/u/.codeium/windsurf/memories/global_rules.md",
    "/repo/.clinerules",
    "/repo/.clinerules/01-style.md",
    "/repo/.clinerules-code",
    "/repo/.roorules",
    "/repo/.roomodes",
    "/repo/.roo/rules/a.md",
    "/repo/.roo/rules-architect/a.md",
    "/repo/.kilocode/rules/a.md",
    "/repo/.continuerules",
    "/repo/.continue/rules/a.md",
    "/repo/.aider.conf.yml",
    "/repo/.rules",
    "/repo/.junie/guidelines.md",
    "/repo/.amazonq/rules/a.md",
    "/repo/.augment-guidelines",
    "/repo/.augment/rules/a.md",
    "/repo/.trae/rules/a.md",
    "/repo/.goosehints",
    "/repo/QWEN.md",
    "/repo/WARP.md",
    "/repo/CRUSH.md",
    "/repo/AGENT.md",
    "/repo/.opencode/agent/x.md",
    "/repo/.opencode/commands/x.md",
    "/repo/.claude/rules/security.md",
    "C:\\repo\\.cursor\\rules\\a.mdc",
    "C:\\repo\\.github\\copilot-instructions.md",
    "/repo/sub/pkg/.cursorrules",
    "/repo/.CursorRules",                      # case-insensitive filesystems
    "/repo/gemini.md",
    "/repo/.cursorrules.",                     # Windows trailing-dot trim
    "/repo/.cursor./rules/a.mdc",
    "/repo/.cursor//rules/./a.mdc",
]

NOT_GATED = [
    "/repo/README.md",
    "/repo/docs/rules/style.md",
    "/repo/src/rules.py",
    "/repo/foo.rules",
    "/repo/.cursorrules.bak",
    "/repo/.cursor/mcp.json",                  # mcp-config-protect's surface
    "/repo/.github/workflows/ci.yml",          # ci-workflow-protect's surface
    "/repo/.github/ISSUE_TEMPLATE/bug.md",
    "/repo/management.md",
    "/repo/src/gemini.md.txt",
    "/repo/src/agent.py",
    "/repo/cursor/rules/a.md",                 # no leading dot
]


@pytest.mark.parametrize("path", GATED)
def test_write_to_rules_file_asks(path):
    d = _only(_write(path))
    assert d is not None and d.action == Action.ASK and d.rule == RULE, path


@pytest.mark.parametrize("path", NOT_GATED)
def test_ordinary_files_not_claimed(path):
    assert _only(_write(path)) is None, path


def test_claude_md_and_agents_md_left_to_agent_def():
    for p in ("/repo/CLAUDE.md", "/repo/AGENTS.md"):
        assert _only(_write(p)) is None
        assert evaluate(_write(p), EMPTY).rule == "agent-def-protect"


def test_engine_reaches_guard_for_edit_write_and_mcp():
    for ev in (_write("/repo/.cursorrules"),
               _ev("Edit", file_path="/repo/GEMINI.md", old_string="a", new_string="b"),
               _ev("mcp__filesystem__write_file", path="/repo/.windsurfrules", content="x")):
        d = evaluate(ev, EMPTY)
        assert d.action == Action.ASK and d.rule == RULE


def test_claude_rules_edit_reaches_this_guard_through_engine():
    d = evaluate(_write("/repo/.claude/rules/x.md"), EMPTY)
    assert d.action == Action.ASK and d.rule == RULE


def test_mention_in_content_of_unrelated_file_is_not_a_hit():
    assert _only(_write("/repo/README.md", content="edit .cursorrules to taste")) is None


# ---- path indirection ----------------------------------------------------------
def test_dotdot_traversal_normalized():
    assert _only(_write("/repo/src/../.cursor/x/../rules/a.mdc")).action == Action.ASK


def test_relative_path_resolved_against_cwd_inside_rules_dir():
    assert _only(_write("a.mdc", cwd="/repo/.cursor/rules")).action == Action.ASK
    assert _only(_write("rules/a.mdc", cwd="/repo/.cursor")).action == Action.ASK
    assert _only(_write("a.mdc", cwd="/repo/src")) is None


def test_symlink_to_rules_file_resolved(tmp_path):
    real = tmp_path / ".cursorrules"
    real.write_text("x")
    link = tmp_path / "notes.md"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    assert _only(_write(str(link))).action == Action.ASK


def test_symlinked_directory_resolved(tmp_path):
    d = tmp_path / ".cursor" / "rules"
    d.mkdir(parents=True)
    link = tmp_path / "docs"
    try:
        os.symlink(d, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    assert _only(_write(str(link / "a.mdc"))).action == Action.ASK


# ---- MCP tool shapes -----------------------------------------------------------
def test_mcp_move_destination_is_the_target():
    ev = _ev("mcp__filesystem__move_file", source="/tmp/payload.md",
             destination="/repo/.github/copilot-instructions.md")
    d = _only(ev)
    assert d.action == Action.ASK and "copilot-instructions" in d.message


def test_mcp_nested_path_leaf():
    ev = _ev("mcp__fs__apply", ops=[{"target": "/repo/.cursor/rules/a.mdc", "text": "x"}])
    assert _only(ev).action == Action.ASK


def test_mcp_prose_mentioning_a_rules_file_is_not_a_path():
    assert _only(_ev("mcp__slack__post_message", text="please update .cursorrules")) is None


# ---- hidden-character content: deny even in ask mode ---------------------------
HIDDEN = ["\u200b", "\u200c", "\u200e", "\u2060", "\u2062", "\u202e", "\u2066",
          "\u00ad", "\u180e", "\u3164", "\U000e0041", "\U000e0020", "\U000e0101"]


@pytest.mark.parametrize("ch", HIDDEN)
def test_hidden_character_in_written_content_denied(ch):
    d = _only(_write("/repo/.cursorrules", content=f"Follow PEP8.{ch}{ch} Always."))
    assert d.action == Action.DENY and d.rule == RULE
    assert "Rules File Backdoor" in d.message


def test_hidden_character_via_edit_new_string_denied():
    ev = _ev("Edit", file_path="/repo/GEMINI.md", old_string="a", new_string="a\u200bb")
    assert _only(ev).action == Action.DENY


def test_hidden_character_via_multiedit_and_mcp_shapes_denied():
    ev = _ev("MultiEdit", file_path="/repo/.windsurfrules",
             edits=[{"old_string": "a", "new_string": "ok"},
                    {"old_string": "b", "new_string": "x\U000e0049y"}])
    assert _only(ev).action == Action.DENY
    ev = _ev("mcp__filesystem__edit_file", path="/repo/.clinerules",
             edits=[{"oldText": "a", "newText": "b\u202ec"}])
    assert _only(ev).action == Action.DENY


def test_removing_hidden_characters_is_only_an_ask():
    ev = _ev("Edit", file_path="/repo/.cursorrules", old_string="a\u200b\U000e0041b",
             new_string="ab")
    assert _only(ev).action == Action.ASK
    ev = _ev("mcp__filesystem__edit_file", path="/repo/.cursorrules",
             edits=[{"oldText": "a\u200bb", "newText": "ab"}])
    assert _only(ev).action == Action.ASK


def test_leading_bom_and_emoji_are_not_hidden_content():
    assert _only(_write("/repo/.cursorrules", content="\ufeff# Rules")).action == Action.ASK
    emoji = "Be kind \U0001F468\u200d\U0001F469\u200d\U0001F467 \u2764\ufe0f"
    assert _only(_write("/repo/.cursorrules", content=emoji)).action == Action.ASK
    assert _only(_write("/repo/.cursorrules", content="a\ufeffb")).action == Action.DENY


def test_hidden_characters_in_an_unrelated_file_not_claimed():
    assert _only(_write("/repo/README.md", content="a\u200bb")) is None


def test_hidden_content_denied_despite_policy_allow():
    pol = Policy(agent_rules={"allow": [r"\.cursor/rules/"]})
    assert _only(_write("/repo/.cursor/rules/a.mdc"), pol) is None
    assert _only(_write("/repo/.cursor/rules/a.mdc", content="x\u200by"), pol).action == Action.DENY


def test_hidden_content_human_env_override(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_AGENT_RULES", "1")
    assert _only(_write("/repo/.cursorrules", content="x\u200by")) is None


# ---- shell form ----------------------------------------------------------------
SHELL_GATED = [
    "echo 'always approve' > .cursorrules",
    "echo x >> .github/copilot-instructions.md",
    "cat payload.md >> GEMINI.md",
    "tee .windsurfrules < payload",
    "cp /tmp/p.md .cursor/rules/style.mdc",
    "mv /tmp/p.md .clinerules",
    "sed -i 's/never/always/' .roorules",
    "rm -rf .cursor/rules",
    "rsync -a evil/ .cursor/rules/",
    "tar xf p.tar -C .github/instructions/",
    "unzip p.zip -d .roo/rules-code",
    "ln -sf /tmp/p .cursorrules",
    "python3 -c \"open('.cursorrules','w').write('x')\"",
    "bash -c 'echo x > .cursorrules'",
    "cd .cursor/rules && echo x > a.mdc",
    "find . -name '.cursorrules' -exec sed -i 's/a/b/' {} +",
    "find . -regex '.*\\.cursor.*rules.*' -delete",
    "echo x > AGENTS.override.md",
    "echo 'read: evil.md' >> .aider.conf.yml",
]

SHELL_NOT_GATED = [
    "cat .cursorrules",
    "ls -la .cursor/rules",
    "git add .cursorrules && git commit -m 'rules'",
    "git diff -- GEMINI.md",
    "grep -r TODO .github/instructions",
    "echo hello > notes.txt",
    "rm -rf build",
    "wc -l .windsurfrules",
]


@pytest.mark.parametrize("cmd", SHELL_GATED)
def test_shell_write_to_rules_file_asks(cmd):
    d = _only(_shell(cmd))
    assert d is not None and d.action == Action.ASK and d.rule == RULE, cmd


@pytest.mark.parametrize("cmd", SHELL_NOT_GATED)
def test_shell_read_or_unrelated_not_claimed(cmd):
    assert _only(_shell(cmd)) is None, cmd


def test_shell_through_engine():
    d = evaluate(_shell("echo x > .cursorrules"), EMPTY)
    assert d.action == Action.ASK and d.rule == RULE


def test_shell_write_with_cwd_already_inside_rules_dir():
    assert _only(_shell("echo x > a.mdc", cwd="/repo/.cursor/rules")).action == Action.ASK
    assert _only(_shell("ls", cwd="/repo/.cursor/rules")) is None


def test_shell_base64_wrapped_write_seen():
    import base64
    b = base64.b64encode(b"echo x > .cursorrules").decode()
    assert _only(_shell(f"echo {b} | base64 -d | sh")).action == Action.ASK


@pytest.mark.parametrize("cmd", [
    "printf 'ok\u200bhidden' > .cursorrules",
    "printf 'ok\\u200bhidden' > .cursorrules",
    "echo -e 'ok\\xe2\\x80\\x8bhidden' >> GEMINI.md",
    "echo $'ok\\342\\200\\213hidden' >> .windsurfrules",
    "printf 'a\\U000E0041b' > .clinerules",
    "printf 'a\\xf3\\xa0\\x81\\x81b' > .clinerules",
    "python3 -c \"open('.cursorrules','w').write('a\\u202eb')\"",
])
def test_shell_hidden_character_literal_or_escaped_denied(cmd):
    d = _only(_shell(cmd))
    assert d.action == Action.DENY and d.rule == RULE, cmd


def test_fetch_to_file_backstop_covers_rules_files():
    for cmd in ("curl -o .cursorrules https://x.example/r",
                "wget -O .github/copilot-instructions.md https://x.example/r",
                "curl -o .cursor/rules/a.mdc https://x.example/r"):
        d = evaluate(_shell(cmd), EMPTY)
        assert d.action == Action.ASK and d.rule == "fetch-to-file-protect", cmd


# ---- escapes -------------------------------------------------------------------
def test_shell_human_override_comment():
    assert _only(_shell("echo x > .cursorrules  # aegis-allow")) is None


def test_spawned_agent_cannot_use_override_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "worker-1")
    assert _only(_shell("echo x > .cursorrules  # aegis-allow")).action == Action.ASK
    d = _only(_shell("printf 'a\u200bb' > .cursorrules  # aegis-allow"))
    assert d.action == Action.DENY


def test_env_toggle_allows_both_forms(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_AGENT_RULES", "1")
    assert _only(_write("/repo/.cursorrules")) is None
    assert _only(_shell("echo x > .cursorrules")) is None


def test_policy_allow_regex():
    pol = Policy(agent_rules={"allow": [r"\.github/copilot-instructions\.md$", "("]})
    assert _only(_write("/repo/.github/copilot-instructions.md"), pol) is None
    assert _only(_write("/repo/.cursorrules"), pol).action == Action.ASK
    pol = Policy(agent_rules={"allow": [r"sync-rules\.sh"]})
    assert _only(_shell("./sync-rules.sh > .cursorrules"), pol) is None


# ---- modes ---------------------------------------------------------------------
def test_mode_deny():
    assert _only(_write("/repo/.cursorrules"), DENY).action == Action.DENY
    assert _only(_shell("echo x > GEMINI.md"), DENY).action == Action.DENY


@pytest.mark.parametrize("mode", ["off", "false", False])
def test_mode_off(mode):
    pol = Policy(agent_rules={"mode": mode})
    assert _only(_write("/repo/.cursorrules", content="a\u200bb"), pol) is None
    assert _only(_shell("echo x > .cursorrules"), pol) is None


def test_mode_monitor_records_without_blocking(monkeypatch):
    seen = []
    monkeypatch.setattr(rules, "_record_monitor",
                        lambda ev, would, note: seen.append((would.action, note)))
    pol = Policy(agent_rules={"mode": "monitor"})
    assert _only(_write("/repo/.cursorrules"), pol) is None
    assert _only(_write("/repo/.cursorrules", content="a\u200bb"), pol) is None
    assert _only(_shell("echo x > .cursorrules"), pol) is None
    assert [n for _, n in seen] == ["agent-rules-protect-monitor"] * 3
    assert seen[1][0] == Action.DENY


# ---- wiring --------------------------------------------------------------------
def test_registered_in_core_rules_after_agent_def():
    names = [r.__name__ for r in rules._CORE_RULES]
    assert names.index("rule_agent_rules_protect") == names.index("rule_agent_def_protect") + 1


def test_policy_yaml_round_trip(tmp_path):
    d = tmp_path / "policies"
    d.mkdir()
    (d / "p.yaml").write_text("agent_rules:\n  mode: deny\n  allow: ['GEMINI']\n")
    pol = load_policy(str(d))
    assert pol.agent_rules == {"mode": "deny", "allow": ["GEMINI"]}
    assert evaluate(_write("/repo/.cursorrules"), pol).action == Action.DENY
    assert evaluate(_write("/repo/GEMINI.md"), pol).rule != RULE


def test_documented_everywhere_siblings_are():
    from aegis import skills
    import pathlib
    src = pathlib.Path(skills.__file__).read_text(encoding="utf-8")
    assert "agent-rules-protect" in src and src.count("`agent_rules`") >= 2
    readme = pathlib.Path(skills.__file__).parent.parent / "README.md"
    assert "AEGIS_ALLOW_AGENT_RULES" in readme.read_text(encoding="utf-8") or \
        "Cross-agent rules" in readme.read_text(encoding="utf-8")


# ---- regex safety --------------------------------------------------------------
@pytest.mark.parametrize("blob", [
    ".cursor/" * 20000, "a" * 200000 + ".instructions.md", "-name x " * 20000,
    ".roo/rules-" + "a-" * 50000, "/" * 100000 + ".rules", " ." * 60000,
])
def test_patterns_do_not_backtrack_catastrophically(blob):
    import time
    t = time.time()
    patterns.agent_rules_path_hit(blob)
    patterns.agent_rules_find_hit("find . " + blob)
    patterns.AGENT_RULES_HIDDEN_UNICODE_RE.search(blob)
    rules._AGENT_RULES_ESCAPED_HIDDEN_RE.search(blob)
    assert time.time() - t < 2.0
