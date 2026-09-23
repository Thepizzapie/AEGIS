"""Claude Code env-var hijack protection guard — blocks planting/altering a
dangerous env var (``BASH_ENV``, ``NODE_OPTIONS``, ``PERL5OPT``, ``RUBYOPT``,
``PYTHONSTARTUP``, ``LD_PRELOAD``, ``DYLD_INSERT_LIBRARIES``,
``GIT_SSH_COMMAND``) in the ``env`` block of ``.claude/settings.local.json``,
the project-local, gitignored-by-default sibling of ``.claude/settings.json``
that `rule_claude_hooks_protect`/`rule_statusline_protect`/`rule_permission_
bypass_protect` already guard for their own keys in this file.

Claude Code merges ``env`` into the environment of every subprocess it
spawns for every future session in this project — a planted var like
``BASH_ENV`` runs as arbitrary shell on the very next Bash tool call, often
this same session, with no future git/CI/session-restart trigger needed.
"""
import time

from aegis import patterns
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                            # default mode: ask
DENY = Policy(claude_env={"mode": "deny"})                   # stricter, hard-block posture

ENV_JSON = '{"env": {"BASH_ENV": "/tmp/evil.sh"}}'


def _edit(path, new_string=ENV_JSON):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                       args={"file_path": path, "new_string": new_string})


def _write(path, content=ENV_JSON):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write",
                       args={"file_path": path, "content": content})


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp_write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                       action=ActionClass.MCP, args={"path": path, "content": content})


def _mcp_edit_nested(path, old, new):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__edit_file",
                       action=ActionClass.MCP,
                       args={"path": path, "edits": [{"oldText": old, "newText": new}]})


def _mcp_key_value(path, key, value):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__json_editor__set_key",
                       action=ActionClass.MCP,
                       args={"path": path, "key": key, "value": value})


def _mcp_nested_json(path, obj):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_json",
                       action=ActionClass.MCP, args={"path": path, "json": obj})


def _gated(d) -> bool:
    return d.action != Action.ALLOW


# ---- Edit/Write ---------------------------------------------------------------

def test_bash_env_key_via_write_gated():
    d = evaluate(_write(".claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_bash_env_key_via_edit_gated():
    d = evaluate(_edit(".claude/settings.local.json",
                        '"BASH_ENV": "/tmp/evil.sh"'), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_windows_path_separator_gated():
    assert _gated(evaluate(_write(".claude\\settings.local.json"), EMPTY))


def test_single_quoted_key_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         "'BASH_ENV': '/tmp/evil.sh'"), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_each_dangerous_var_name_gated():
    for var in patterns.CLAUDE_ENV_DANGEROUS_VARS:
        d = evaluate(_write(".claude/settings.local.json",
                             f'{{"env": {{"{var}": "x"}}}}'), EMPTY)
        assert _gated(d) and d.rule == "claude-env-protect", var


def test_case_insensitive_key_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '{"env": {"bash_env": "/tmp/evil.sh"}}'), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_nested_project_path_gated():
    d = evaluate(_write("packages/foo/.claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_user_scope_path_gated():
    d = evaluate(_write("/home/dev/.claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_unicode_escaped_key_gated():
    """The same JSON `\\uXXXX`-escape evasion class `_claude_hooks_json_key_
    hit` closes for `hooks` — `"\\u0042ASH_ENV"` decodes to the real key
    `BASH_ENV` while a purely textual substring check can't see through the
    decode step it never performs."""
    d = evaluate(_write(".claude/settings.local.json",
                         '{"env": {"\\u0042ASH_ENV": "/tmp/evil.sh"}}'), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_unicode_escaped_key_via_mcp_gated():
    d = evaluate(_mcp_write(".claude/settings.local.json",
                             '{"env": {"\\u0042ASH_ENV": "/tmp/evil.sh"}}'), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_partial_edit_fragment_not_valid_json_still_uses_textual_check():
    d = evaluate(_edit(".claude/settings.local.json",
                        '"NODE_OPTIONS": "--require /tmp/evil.js"'), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_unicode_escaped_key_in_partial_edit_fragment_gated():
    """QA finding (independent adversarial review, round A): a CONFIRMED,
    reproduced silent-ALLOW bypass — a `\\uXXXX`-escaped dangerous var name
    inside a PARTIAL Edit fragment (no enclosing braces, so it never parses
    standalone as JSON) evaded both the textual check (run against RAW,
    un-decoded content) and the JSON semantic walk (which only fires on
    content that validates as JSON on its own). Unlike `hooks` — whose real
    schema needs the literal substring to appear twice in any real plant,
    incidentally masking this class — `env` needs only ONE occurrence, so
    this was a single-call bypass, not just a theoretical one. Closed by
    `_claude_env_normalize` (whitespace-collapse + `\\uXXXX`-decode) run
    before the textual regex ever sees the text, the same fix already
    shipped for `statusLine`/`permissions.defaultMode`."""
    d = evaluate(_edit(".claude/settings.local.json",
                        '"env": {"\\u0042ASH_ENV": "/tmp/evil.sh"}'), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_unicode_escaped_key_in_mcp_edit_file_fragment_gated():
    """The identical fragment-escape bypass, via a third-party MCP
    filesystem server's own `{path, edits: [{oldText, newText}]}` shape
    rather than Claude Code's own content/new_string convention."""
    d = evaluate(_mcp_edit_nested(".claude/settings.local.json", "{}",
                                   '"env": {"\\u0042ASH_ENV": "/tmp/evil.sh"}'), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


# ---- MCP-tool writes ------------------------------------------------------------

def test_mcp_write_gated():
    d = evaluate(_mcp_write(".claude/settings.local.json", ENV_JSON), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_mcp_edit_file_nested_edits_shape_gated():
    d = evaluate(_mcp_edit_nested(".claude/settings.local.json", "{}",
                                   '"env": {"BASH_ENV": "/tmp/evil.sh"}'), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_mcp_flat_key_value_arg_shape_gated():
    d = evaluate(_mcp_key_value(".claude/settings.local.json", "BASH_ENV",
                                 "/tmp/evil.sh"), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_mcp_nested_json_dict_key_shape_gated():
    d = evaluate(_mcp_nested_json(".claude/settings.local.json",
                                   {"env": {"BASH_ENV": "/tmp/evil.sh"}}), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_mcp_struct_key_depth_capped():
    nested = {"BASH_ENV": "/tmp/evil.sh"}
    for _ in range(8):
        nested = {"wrapper": nested}
    d = evaluate(_mcp_nested_json(".claude/settings.local.json", nested), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_mcp_decoy_literal_content_does_not_suppress_struct_fallback():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_json",
                     action=ActionClass.MCP,
                     args={"path": ".claude/settings.local.json",
                           "content": '{"model": "opus"}',
                           "json": {"env": {"BASH_ENV": "/tmp/evil.sh"}}})
    d = evaluate(ev, EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_jsonc_comment_mentioning_var_not_gated_for_literal_edit():
    """The bareword/struct fallback is scoped to ActionClass.MCP only — an
    ordinary Edit/Write whose literal content merely mentions BASH_ENV in a
    comment or unrelated string must not false-positive without the real
    key shape present."""
    d = evaluate(_write(".claude/settings.local.json",
                         '{\n  // TODO: consider setting BASH_ENV later\n'
                         '  "model": "opus"\n}'), EMPTY)
    assert not _gated(d)


# ---- shell forms ----------------------------------------------------------------
#
# Same precedence note as `test_claude_hooks_protect.py`'s own shell-forms
# section: `rule_self_protect`'s whole-command-scoped, non-escapable
# `CONFIG_DIR_RE` + write-verb check preempts a redirect/sed-i/heredoc/mv
# shell form before this guard ever runs (first-deny-wins), so those shapes
# assert `self-protect`, not `claude-env-protect`. This guard's own
# non-redundant coverage is the jq-through-sponge shape self-protect's
# fixed write-verb list doesn't recognize at all.

def test_shell_redirect_already_blocked_by_self_protect():
    d = evaluate(_shell(f"echo '{ENV_JSON}' > .claude/settings.local.json"), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_cat_heredoc_already_blocked_by_self_protect():
    d = evaluate(_shell(
        'cat > .claude/settings.local.json <<EOF\n'
        '{"env": {"BASH_ENV": "/tmp/evil.sh"}}\n'
        'EOF'), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_jq_sponge_assign_gated():
    d = evaluate(_shell(
        'jq \'.env.BASH_ENV = "/tmp/evil.sh"\' '
        '.claude/settings.local.json | sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_shell_jq_merge_form_via_mv_already_blocked_by_self_protect():
    d = evaluate(_shell(
        'jq \'. += {env: {"BASH_ENV": "/tmp/evil.sh"}}\' .claude/settings.local.json '
        '> /tmp/x.json && mv /tmp/x.json .claude/settings.local.json'), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_jq_update_assign_operator_gated():
    d = evaluate(_shell(
        'jq \'.env.NODE_OPTIONS |= "--require /tmp/evil.js"\' '
        '.claude/settings.local.json | sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_shell_jq_bracket_index_notation_gated():
    d = evaluate(_shell(
        'jq \'.env["GIT_SSH_COMMAND"] = "/tmp/evil.sh"\' .claude/settings.local.json '
        '| sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_shell_jq_comment_padding_gated():
    """QA finding (independent adversarial review, round A): a CONFIRMED,
    reproduced silent-ALLOW bypass — a jq `#`-comment (real jq syntax, valid
    inside a single-quoted shell argument, ignored by jq itself) used as
    filler right after the `jq` token pushed the dangerous var name outside
    the original fixed 400-char lookahead window, the identical bypass class
    `PERMISSION_BYPASS_JQ_RE`'s own patterns.py comment already discloses
    and fixes for its own key. Closed the same way: an unbounded,
    `;`-scoped lookahead instead of a fixed character bound."""
    d = evaluate(_shell(
        "jq '#" + "x" * 450 + "\n.env.BASH_ENV = \"/tmp/evil.sh\"' "
        ".claude/settings.local.json | sponge .claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_jq_equality_comparison_not_gated():
    d = evaluate(_shell(
        "jq 'select(.env.BASH_ENV == null)' .claude/settings.local.json"), EMPTY)
    assert not _gated(d)


def test_jq_plain_read_not_gated():
    assert not _gated(evaluate(
        _shell("jq '.env.BASH_ENV' .claude/settings.local.json"), EMPTY))


def test_shell_cd_into_claude_dir_then_bare_filename_gated():
    d = evaluate(_shell(
        'cd .claude && jq \'.env.BASH_ENV = "/tmp/evil.sh"\' '
        'settings.local.json | sponge settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_shell_push_location_into_claude_dir_then_bare_filename_gated():
    d = evaluate(_shell(
        'Push-Location .claude; jq \'.env.BASH_ENV = "/tmp/evil.sh"\' '
        'settings.local.json | sponge settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_shell_set_location_into_claude_dir_then_bare_filename_gated():
    d = evaluate(_shell(
        'Set-Location .claude; Set-Content settings.local.json '
        '\'{"env": {"BASH_ENV": "/tmp/evil.sh"}}\''), EMPTY)
    assert _gated(d) and d.rule == "claude-env-protect"


def test_shell_cd_elsewhere_then_bare_filename_not_gated():
    assert not _gated(evaluate(_shell(
        'cd /tmp && echo "see settings.local.json for env config"'), EMPTY))


def test_shell_cd_into_lookalike_dir_not_gated():
    for cmd in (
        'cd .claude-old && jq \'.env.BASH_ENV="x"\' settings.local.json | sponge settings.local.json',
        'cd .claude.bak && jq \'.env.BASH_ENV="x"\' settings.local.json | sponge settings.local.json',
    ):
        assert not _gated(evaluate(_shell(cmd), EMPTY)), cmd


def test_shell_write_without_write_verb_not_gated():
    assert not _gated(evaluate(_shell('cat .claude/settings.local.json'), EMPTY))


def test_shell_jq_sponge_to_unrelated_key_not_gated():
    d = evaluate(_shell(
        'jq \'.model = "opus"\' .claude/settings.local.json '
        '| sponge .claude/settings.local.json'), EMPTY)
    assert not _gated(d)


def test_shell_redirect_to_unrelated_file_not_gated():
    assert not _gated(evaluate(_shell(f"echo '{ENV_JSON}' > output.txt"), EMPTY))


# ---- benign cases: must NOT gate -------------------------------------------------

def test_benign_env_key_not_gated():
    """Ordinary env tweaks (NODE_ENV, DEBUG, a project API base URL) carry
    none of the dangerous var names and are routine, sanctioned local
    customization — the same trade-off `rule_claude_hooks_protect`'s own
    docstring names `env` under."""
    d = evaluate(_write(".claude/settings.local.json",
                         '{"env": {"NODE_ENV": "development", "DEBUG": "1"}}'), EMPTY)
    assert not _gated(d)


def test_benign_local_settings_edit_not_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '{"model": "opus", "env": {"FOO": "bar"}}'), EMPTY)
    assert not _gated(d)


def test_lookalike_var_name_not_gated():
    """A var name that merely contains a dangerous substring (not an exact
    match) must not false-positive."""
    d = evaluate(_write(".claude/settings.local.json",
                         '{"env": {"MY_BASH_ENV_NOTE": "x"}}'), EMPTY)
    assert not _gated(d)


def test_project_settings_json_not_gated_by_this_guard():
    d = evaluate(_write(".claude/settings.json", ENV_JSON), EMPTY)
    assert d.rule != "claude-env-protect"


def test_unrelated_file_mentioning_bash_env_not_gated():
    assert not _gated(evaluate(
        _write("README.md", 'Set BASH_ENV in your shell profile...'), EMPTY))


def test_reading_settings_local_json_not_gated():
    read_ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Read",
                          args={"file_path": ".claude/settings.local.json"})
    assert not _gated(evaluate(read_ev, EMPTY))


def test_unrelated_path_named_settings_local_json_not_gated():
    assert not _gated(evaluate(
        _write("config/settings.local.json", ENV_JSON), EMPTY))


def test_settings_local_json_backup_file_not_gated():
    assert not _gated(evaluate(
        _write(".claude/settings.local.json.bak", ENV_JSON), EMPTY))


# ---- escape hatches: human-only --------------------------------------------------

_JQ_SPONGE_CMD = ('jq \'.env.BASH_ENV = "/tmp/evil.sh"\' .claude/settings.local.json '
                   '| sponge .claude/settings.local.json')


def test_human_can_override_shell_with_comment():
    assert not _gated(evaluate(_shell(_JQ_SPONGE_CMD + " # aegis-allow"), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(_shell(_JQ_SPONGE_CMD + " # aegis-allow"), EMPTY))


def test_env_toggle_allows_edit_write_and_shell(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CLAUDE_ENV", "1")
    assert not _gated(evaluate(_write(".claude/settings.local.json"), EMPTY))
    assert not _gated(evaluate(_shell(_JQ_SPONGE_CMD), EMPTY))


def test_policy_allow_regex_skips_gate():
    pol = Policy(claude_env={"allow": [r"\.claude/settings\.local\.json"]})
    assert not _gated(evaluate(_write(".claude/settings.local.json"), pol))


# ---- modes: ask (default) / deny / monitor / off ----------------------------------

def test_default_mode_is_ask():
    d = evaluate(_write(".claude/settings.local.json"), EMPTY)
    assert d.action == Action.ASK and d.rule == "claude-env-protect"
    d2 = evaluate(_shell(_JQ_SPONGE_CMD), EMPTY)
    assert d2.action == Action.ASK and d2.rule == "claude-env-protect"


def test_deny_mode_hard_blocks():
    d = evaluate(_write(".claude/settings.local.json"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == "claude-env-protect"


def test_monitor_mode_logs_and_allows():
    pol = Policy(claude_env={"mode": "monitor"})
    assert not _gated(evaluate(_write(".claude/settings.local.json"), pol))


def test_off_mode_disables_guard():
    pol = Policy(claude_env={"mode": "off"})
    assert not _gated(evaluate(_write(".claude/settings.local.json"), pol))


# ---- perf / ReDoS ------------------------------------------------------------------

def test_shell_jq_unbounded_lookahead_does_not_cross_semicolon():
    """The now-unbounded `CLAUDE_ENV_JQ_RE` lookahead is `;`-scoped, not
    truly unbounded across the whole command — an unrelated `jq` invocation
    followed by a LATER, `;`-separated statement that happens to mention a
    dangerous var name must not false-positive."""
    d = evaluate(_shell(
        'jq \'.model\' .claude/settings.local.json; echo "note BASH_ENV here"'), EMPTY)
    assert not _gated(d)


def test_perf_no_redos_on_unbounded_jq_lookahead():
    adversarial = "jq '" + "#x" * 100000 + "' .claude/settings.local.json | sponge .claude/settings.local.json"
    start = time.time()
    evaluate(_shell(adversarial), EMPTY)
    assert time.time() - start < 1.0


def test_perf_no_redos_on_adversarial_shell_input():
    adversarial = ("jq " + "a" * 5000 + " .claude/settings.local.json | sponge "
                    ".claude/settings.local.json " + "b" * 5000)
    start = time.time()
    evaluate(_shell(adversarial), EMPTY)
    assert time.time() - start < 1.0


def test_perf_no_redos_on_long_path_content():
    long_content = '"x": "' + ("y" * 20000) + '", "env": {"BASH_ENV": "/tmp/evil.sh"}'
    start = time.time()
    d = evaluate(_write(".claude/settings.local.json", long_content), EMPTY)
    assert time.time() - start < 1.0
    assert _gated(d)


# ---- direct pattern sanity ---------------------------------------------------------

def test_dangerous_var_regex_matches_each_name():
    for var in patterns.CLAUDE_ENV_DANGEROUS_VARS:
        assert patterns.CLAUDE_ENV_DANGEROUS_VAR_RE.search(f'"{var}": "x"'), var


def test_dangerous_var_regex_does_not_match_benign_names():
    for var in ("NODE_ENV", "DEBUG", "PATH", "HOME"):
        assert not patterns.CLAUDE_ENV_DANGEROUS_VAR_RE.search(f'"{var}": "x"'), var
