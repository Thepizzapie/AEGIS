"""Claude Code permission-bypass protection guard — blocks planting/altering
a ``permissions.defaultMode: "bypassPermissions"`` entry in
``.claude/settings.local.json``, the same project-local, gitignored-by-default
sibling of ``.claude/settings.json`` `rule_claude_hooks_protect`/`rule_
statusline_protect` already guard for their own keys, and the equivalent,
file-free ``claude --dangerously-skip-permissions``/``--permission-mode
bypassPermissions`` CLI invocation.

Unlike ``hooks``/``statusLine``, this doesn't plant one auto-run command — it
silences Claude Code's own confirmation prompt for EVERY future tool call.
"""
import time

from aegis import patterns
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                              # default mode: ask
DENY = Policy(permission_bypass={"mode": "deny"})              # stricter, hard-block posture

BYPASS_JSON = '{"permissions": {"defaultMode": "bypassPermissions"}}'


def _edit(path, new_string=BYPASS_JSON):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                       args={"file_path": path, "new_string": new_string})


def _write(path, content=BYPASS_JSON):
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

def test_bypass_mode_via_write_gated():
    d = evaluate(_write(".claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_bypass_mode_via_edit_gated():
    d = evaluate(_edit(".claude/settings.local.json",
                        '"permissions": {"defaultMode": "bypassPermissions"}'), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_windows_path_separator_gated():
    d = evaluate(_write(".claude\\settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_single_quoted_form_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         "'defaultMode': 'bypassPermissions'"), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_other_default_mode_values_not_gated():
    """The everyday-safe shape this guard is deliberately narrower than a
    bare-key gate: `acceptEdits`/`plan`/`default` are legitimate, common
    values of the very same key."""
    for value in ("acceptEdits", "plan", "default"):
        d = evaluate(_write(".claude/settings.local.json",
                             f'"permissions": {{"defaultMode": "{value}"}}'), EMPTY)
        assert not _gated(d), value


def test_bare_default_mode_key_alone_not_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '"defaultMode"'), EMPTY)
    assert not _gated(d)


def test_bare_bypass_permissions_value_alone_not_gated():
    """`bypassPermissions` alone (no `defaultMode` key) must not
    false-positive — e.g. an unrelated string value elsewhere."""
    d = evaluate(_write(".claude/settings.local.json",
                         '{"note": "bypassPermissions is dangerous"}'), EMPTY)
    assert d.rule != "permission-bypass-protect"


def test_additional_directories_not_gated():
    """`permissions.additionalDirectories`/`allow`/`deny` are ordinary,
    routine settings.local.json content this guard is deliberately narrower
    than — only the `defaultMode: "bypassPermissions"` shape is gated."""
    d = evaluate(_write(".claude/settings.local.json",
                         '{"permissions": {"additionalDirectories": ["../docs"], '
                         '"allow": ["Bash(git diff:*)"]}}'), EMPTY)
    assert not _gated(d)


def test_extra_whitespace_between_key_and_value_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '"defaultMode"    :\n\n   "bypassPermissions"'), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_unicode_escaped_key_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '{"\\u0064efaultMode": "bypassPermissions"}'), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_unicode_escaped_value_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '{"defaultMode": "\\u0062ypassPermissions"}'), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_unicode_escaped_key_via_mcp_gated():
    d = evaluate(_mcp_write(".claude/settings.local.json",
                             '{"\\u0064efaultMode": "bypassPermissions"}'), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_partial_edit_fragment_not_valid_json_still_uses_textual_check():
    d = evaluate(_edit(".claude/settings.local.json",
                        '"model": "opus", "defaultMode": "bypassPermissions",'),
                 EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_nested_project_path_gated():
    d = evaluate(_write("packages/foo/.claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_user_scope_path_gated():
    d = evaluate(_write("/home/dev/.claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


# ---- MCP-tool writes ------------------------------------------------------------

def test_mcp_write_gated():
    d = evaluate(_mcp_write(".claude/settings.local.json", BYPASS_JSON), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_mcp_edit_file_nested_edits_shape_gated():
    d = evaluate(_mcp_edit_nested(".claude/settings.local.json", "{}",
                                   '"defaultMode": "bypassPermissions"'),
                 EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_mcp_flat_key_value_arg_shape_gated():
    d = evaluate(_mcp_key_value(".claude/settings.local.json", "defaultMode",
                                 "bypassPermissions"), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_mcp_nested_json_dict_key_shape_gated():
    d = evaluate(_mcp_nested_json(".claude/settings.local.json",
                                   {"permissions": {"defaultMode": "bypassPermissions"}}),
                 EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_mcp_nested_json_other_value_not_gated():
    d = evaluate(_mcp_nested_json(".claude/settings.local.json",
                                   {"permissions": {"defaultMode": "acceptEdits"}}), EMPTY)
    assert not _gated(d)


def test_mcp_struct_key_depth_capped():
    nested = {"permissions": {"defaultMode": "bypassPermissions"}}
    for _ in range(8):
        nested = {"wrapper": nested}
    d = evaluate(_mcp_nested_json(".claude/settings.local.json", nested), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_mcp_decoy_literal_content_does_not_suppress_struct_fallback():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_json",
                     action=ActionClass.MCP,
                     args={"path": ".claude/settings.local.json",
                           "content": '{"model": "opus"}',
                           "json": {"permissions": {"defaultMode": "bypassPermissions"}}})
    d = evaluate(ev, EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_jsonc_comment_mentioning_key_not_gated_for_literal_edit():
    d = evaluate(_write(".claude/settings.local.json",
                         '{\n  // TODO: consider bypassPermissions for CI later\n'
                         '  "model": "opus"\n}'), EMPTY)
    assert not _gated(d)


# ---- shell forms: file-write ----------------------------------------------------
# Same self-protect-precedence interaction `test_statusline_protect.py` documents:
# self-protect's own shell branch (write-verb + `.claude` mention, non-escapable)
# preempts this guard for any redirect/sed-i/heredoc/mv form. This guard's own real
# coverage is the write-verb-less jq/sponge shape self-protect never sees.

def test_shell_redirect_already_blocked_by_self_protect():
    d = evaluate(_shell(f"echo '{BYPASS_JSON}' > .claude/settings.local.json"), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_sed_inplace_already_blocked_by_self_protect():
    d = evaluate(_shell(
        "sed -i 's/.*/{\"permissions\":{\"defaultMode\":\"bypassPermissions\"}}/' "
        ".claude/settings.local.json"), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_jq_sponge_assign_gated():
    d = evaluate(_shell(
        'jq \'.permissions.defaultMode = "bypassPermissions"\' '
        '.claude/settings.local.json | sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_shell_jq_update_assign_operator_gated():
    d = evaluate(_shell(
        'jq \'.permissions.defaultMode |= "bypassPermissions"\' .claude/settings.local.json '
        '| sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_shell_jq_bracket_index_notation_gated():
    d = evaluate(_shell(
        'jq \'.["permissions"]["defaultMode"] = "bypassPermissions"\' '
        '.claude/settings.local.json | sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_jq_equality_comparison_not_gated():
    d = evaluate(_shell(
        "jq 'select(.permissions.defaultMode == \"bypassPermissions\")' "
        ".claude/settings.local.json"), EMPTY)
    assert not _gated(d)


def test_jq_plain_read_not_gated():
    assert not _gated(evaluate(
        _shell("jq '.permissions.defaultMode' .claude/settings.local.json"), EMPTY))


def test_jq_default_mode_other_value_not_gated():
    d = evaluate(_shell(
        'jq \'.permissions.defaultMode = "acceptEdits"\' .claude/settings.local.json '
        '| sponge .claude/settings.local.json'), EMPTY)
    assert not _gated(d)


def test_shell_sponge_without_jq_gated():
    """The one shell shape that skips every write-verb self-protect checks
    for — same closed gap `test_statusline_protect.py`'s own round-A QA
    finding documents for `sponge`."""
    d = evaluate(_shell(
        f"echo '{BYPASS_JSON}' | sponge .claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_shell_printf_pipe_sponge_gated():
    d = evaluate(_shell(
        f"printf '%s' '{BYPASS_JSON}' | sponge .claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_shell_whitespace_padding_does_not_defeat_window_gated():
    padded = ('jq \'.permissions.defaultMode =' + (" " * 500)
              + '"bypassPermissions"\' .claude/settings.local.json '
                '| sponge .claude/settings.local.json')
    d = evaluate(_shell(padded), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_shell_jq_multiline_program_gated():
    cmd = ('jq \'.permissions.defaultMode =\n  "bypassPermissions"\' '
           '.claude/settings.local.json | sponge .claude/settings.local.json')
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_shell_jq_ampersand_in_quoted_value_gated():
    cmd = ('jq \'.permissions = {"note": "a&b", "defaultMode":"bypassPermissions"}\' '
           '.claude/settings.local.json | sponge .claude/settings.local.json')
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_shell_gojq_drop_in_gated():
    d = evaluate(_shell(
        'gojq \'.permissions.defaultMode = "bypassPermissions"\' '
        '.claude/settings.local.json | sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_shell_jaq_drop_in_gated():
    d = evaluate(_shell(
        'jaq \'.permissions.defaultMode = "bypassPermissions"\' '
        '.claude/settings.local.json | sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_shell_cd_into_claude_dir_then_bare_filename_gated():
    d = evaluate(_shell(
        'cd .claude && jq \'.permissions.defaultMode = "bypassPermissions"\' '
        'settings.local.json | sponge settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_shell_push_location_into_claude_dir_then_bare_filename_gated():
    d = evaluate(_shell(
        'Push-Location .claude; jq \'.permissions.defaultMode = "bypassPermissions"\' '
        'settings.local.json | sponge settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_shell_cd_into_lookalike_dir_not_gated():
    for cmd in (
        'cd .claude-old && jq \'.permissions.defaultMode="bypassPermissions"\' '
        'settings.local.json | sponge settings.local.json',
        'cd .claude.bak && jq \'.permissions.defaultMode="bypassPermissions"\' '
        'settings.local.json | sponge settings.local.json',
    ):
        assert not _gated(evaluate(_shell(cmd), EMPTY)), cmd


def test_shell_write_without_write_verb_not_gated():
    assert not _gated(evaluate(_shell('cat .claude/settings.local.json'), EMPTY))


def test_shell_redirect_to_unrelated_file_not_gated():
    assert not _gated(evaluate(_shell(f"echo '{BYPASS_JSON}' > output.txt"), EMPTY))


# ---- shell forms: CLI flag -------------------------------------------------------

def test_cli_dangerously_skip_permissions_gated():
    d = evaluate(_shell('claude -p "do the thing" --dangerously-skip-permissions'), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_cli_permission_mode_bypass_space_form_gated():
    d = evaluate(_shell('claude --permission-mode bypassPermissions -p "go"'), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_cli_permission_mode_bypass_equals_form_gated():
    d = evaluate(_shell('claude --permission-mode=bypassPermissions -p "go"'), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_cli_permission_mode_bypass_quoted_form_gated():
    d = evaluate(_shell('claude --permission-mode "bypassPermissions" -p "go"'), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_cli_dangerously_skip_permissions_no_settings_file_still_gated():
    """No `.claude/settings.local.json` mention at all — this is the
    file-free bypass path, independent of the path checks above."""
    d = evaluate(_shell('claude --dangerously-skip-permissions'), EMPTY)
    assert _gated(d) and d.rule == "permission-bypass-protect"


def test_cli_permission_mode_other_value_not_gated():
    for mode in ("acceptEdits", "plan", "default"):
        d = evaluate(_shell(f'claude --permission-mode {mode} -p "go"'), EMPTY)
        assert not _gated(d), mode


def test_cli_flag_without_claude_binary_not_gated():
    """The flag string alone, with no `claude` invocation in the same
    command, is a narrow accepted gap — matches this guard's own documented
    scope (anchored to the literal binary name)."""
    d = evaluate(_shell('echo "never run with --dangerously-skip-permissions"'), EMPTY)
    assert not _gated(d)


def test_cli_bare_dangerously_skip_permissions_mention_not_claude_command_not_gated():
    d = evaluate(_shell('cat notes.txt  # remember: no --dangerously-skip-permissions'), EMPTY)
    assert not _gated(d)


# ---- benign cases: must NOT gate -------------------------------------------------

def test_benign_local_settings_edit_not_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '{"model": "opus", "env": {"FOO": "bar"}}'), EMPTY)
    assert not _gated(d)


def test_project_settings_json_not_gated_by_this_guard():
    """`.claude/settings.json` is already fully blocked outright by
    self-protect; this content-gated guard's own path check must not also
    fire on it."""
    d = evaluate(_write(".claude/settings.json", BYPASS_JSON), EMPTY)
    assert d.rule != "permission-bypass-protect"


def test_unrelated_file_mentioning_bypass_not_gated():
    assert not _gated(evaluate(
        _write("README.md", 'Setting defaultMode to bypassPermissions is dangerous...'),
        EMPTY))


def test_reading_settings_local_json_not_gated():
    read_ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Read",
                          args={"file_path": ".claude/settings.local.json"})
    assert not _gated(evaluate(read_ev, EMPTY))


def test_unrelated_path_named_settings_local_json_not_gated():
    assert not _gated(evaluate(
        _write("config/settings.local.json", BYPASS_JSON), EMPTY))


def test_settings_local_json_backup_file_not_gated():
    assert not _gated(evaluate(
        _write(".claude/settings.local.json.bak", BYPASS_JSON), EMPTY))


# ---- escape hatches: human-only --------------------------------------------------

_JQ_SPONGE_CMD = ('jq \'.permissions.defaultMode = "bypassPermissions"\' '
                   '.claude/settings.local.json | sponge .claude/settings.local.json')
_CLI_CMD = 'claude --dangerously-skip-permissions -p "go"'


def test_human_can_override_shell_jq_with_comment():
    assert not _gated(evaluate(_shell(_JQ_SPONGE_CMD + " # aegis-allow"), EMPTY))


def test_human_can_override_cli_form_with_comment():
    assert not _gated(evaluate(_shell(_CLI_CMD + " # aegis-allow"), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(_shell(_JQ_SPONGE_CMD + " # aegis-allow"), EMPTY))
    assert _gated(evaluate(_shell(_CLI_CMD + " # aegis-allow"), EMPTY))


def test_env_toggle_allows_edit_write_shell_and_cli(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_PERMISSION_BYPASS", "1")
    assert not _gated(evaluate(_write(".claude/settings.local.json"), EMPTY))
    assert not _gated(evaluate(_shell(_JQ_SPONGE_CMD), EMPTY))
    assert not _gated(evaluate(_shell(_CLI_CMD), EMPTY))


def test_policy_allow_regex_skips_gate():
    pol = Policy(permission_bypass={"allow": [r"\.claude/settings\.local\.json"]})
    assert not _gated(evaluate(_write(".claude/settings.local.json"), pol))


def test_policy_allow_regex_skips_cli_gate():
    pol = Policy(permission_bypass={"allow": [r"--dangerously-skip-permissions"]})
    assert not _gated(evaluate(_shell(_CLI_CMD), pol))


# ---- modes: ask (default) / deny / monitor / off ----------------------------------

def test_default_mode_is_ask():
    d = evaluate(_write(".claude/settings.local.json"), EMPTY)
    assert d.action == Action.ASK and d.rule == "permission-bypass-protect"
    d2 = evaluate(_shell(_JQ_SPONGE_CMD), EMPTY)
    assert d2.action == Action.ASK and d2.rule == "permission-bypass-protect"
    d3 = evaluate(_shell(_CLI_CMD), EMPTY)
    assert d3.action == Action.ASK and d3.rule == "permission-bypass-protect"


def test_deny_mode_hard_blocks():
    d = evaluate(_write(".claude/settings.local.json"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == "permission-bypass-protect"
    d2 = evaluate(_shell(_CLI_CMD), DENY)
    assert d2.blocked and d2.action == Action.DENY and d2.rule == "permission-bypass-protect"


def test_monitor_mode_logs_and_allows():
    pol = Policy(permission_bypass={"mode": "monitor"})
    assert not _gated(evaluate(_write(".claude/settings.local.json"), pol))
    assert not _gated(evaluate(_shell(_CLI_CMD), pol))


def test_off_mode_disables_guard():
    pol = Policy(permission_bypass={"mode": "off"})
    assert not _gated(evaluate(_write(".claude/settings.local.json"), pol))
    assert not _gated(evaluate(_shell(_CLI_CMD), pol))


# ---- perf / ReDoS ------------------------------------------------------------------

def test_perf_no_redos_on_adversarial_shell_input():
    adversarial = ("jq " + "a" * 5000 + " .claude/settings.local.json | sponge "
                    ".claude/settings.local.json " + "b" * 5000)
    start = time.time()
    evaluate(_shell(adversarial), EMPTY)
    assert time.time() - start < 1.0


def test_perf_no_redos_on_long_cli_input():
    """Filler kept under `normalize.scan_surface`'s shared 20,000-char cap
    (every guard's shell branch inherits that truncation boundary) so the
    flag itself isn't truncated away — this pins timing, not the cap."""
    adversarial = "claude " + ("x" * 5000) + " --dangerously-skip-permissions"
    start = time.time()
    d = evaluate(_shell(adversarial), EMPTY)
    assert time.time() - start < 1.0
    assert _gated(d)


def test_perf_no_redos_on_long_path_content():
    long_content = ('"x": "' + ("y" * 20000)
                     + '", "defaultMode": "bypassPermissions"')
    start = time.time()
    d = evaluate(_write(".claude/settings.local.json", long_content), EMPTY)
    assert time.time() - start < 1.0
    assert _gated(d)


def test_perf_no_redos_on_adversarial_key_content():
    adversarial = '"permissions": {' + ('x' * 20000) + '}'
    start = time.time()
    evaluate(_write(".claude/settings.local.json", adversarial), EMPTY)
    assert time.time() - start < 1.0


# ---- direct pattern sanity ---------------------------------------------------------

def test_mode_key_regex_matches_expected_forms():
    for content in (
        '"defaultMode": "bypassPermissions"',
        "'defaultMode': 'bypassPermissions'",
    ):
        assert patterns.PERMISSION_BYPASS_MODE_KEY_RE.search(content), content


def test_mode_key_regex_does_not_match_other_values():
    assert not patterns.PERMISSION_BYPASS_MODE_KEY_RE.search(
        '"defaultMode": "acceptEdits"')


def test_cli_regex_matches_expected_forms():
    for cmd in (
        'claude --dangerously-skip-permissions',
        'claude --permission-mode bypassPermissions',
        'claude --permission-mode=bypassPermissions',
    ):
        assert patterns.PERMISSION_BYPASS_CLI_RE.search(cmd), cmd


def test_cli_regex_does_not_match_other_modes():
    assert not patterns.PERMISSION_BYPASS_CLI_RE.search(
        'claude --permission-mode acceptEdits')
