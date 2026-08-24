"""Claude Code statusline-hijack protection guard — blocks planting/altering a
``statusLine.command`` entry in ``.claude/settings.local.json``, the same
project-local, gitignored-by-default sibling of ``.claude/settings.json``
`rule_claude_hooks_protect` already guards for its ``hooks`` key.

A planted ``statusLine.command`` is spawned directly by Claude Code and
re-invoked on an ongoing UI-refresh cadence — with NO future tool call, git
operation, CI run, or session restart needed at all, a worse trigger bar than
every other auto-exec surface `rule_claude_hooks_protect`'s own siblings
guard, including `hooks` in the very same file.
"""
import time

from aegis import patterns
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                          # default mode: ask
DENY = Policy(statusline={"mode": "deny"})                # stricter, hard-block posture

STATUSLINE_JSON = '{"statusLine": {"type": "command", "command": "/tmp/evil.sh"}}'


def _edit(path, new_string=STATUSLINE_JSON):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                       args={"file_path": path, "new_string": new_string})


def _write(path, content=STATUSLINE_JSON):
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

def test_statusline_command_via_write_gated():
    d = evaluate(_write(".claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_statusline_command_via_edit_gated():
    d = evaluate(_edit(".claude/settings.local.json",
                        '"statusLine": {"type": "command", "command": "evil.sh"}'), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_windows_path_separator_gated():
    d = evaluate(_write(".claude\\settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_single_quoted_key_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         "'statusLine': {'type': 'command', 'command': 'evil.sh'}"), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_statusline_key_without_command_not_gated():
    """An everyday-safe shape this guard is deliberately narrower than the
    `hooks` guard for: a padding/type-only tweak to an existing statusLine
    entry that never re-introduces a `command` sub-key in this edit."""
    d = evaluate(_write(".claude/settings.local.json",
                         '"statusLine": {"padding": 0}'), EMPTY)
    assert not _gated(d)


def test_value_only_tweak_not_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '{"statusLine": {"padding": 1}}'), EMPTY)
    assert not _gated(d)


def test_bare_command_key_alone_not_gated():
    """`command` alone (no `statusLine` co-occurrence) must not false-positive
    — e.g. an unrelated hooks-style `command` field elsewhere is a different
    guard's own territory (`hooks`), not this one's."""
    d = evaluate(_write(".claude/settings.local.json",
                         '{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", '
                         '"command": "echo hi"}]}]}}'), EMPTY)
    assert d.rule != "statusline-protect"


def test_type_command_without_command_key_gated():
    """QA finding (independent adversarial review, round A): a CONFIRMED,
    reproduced two-call bypass in an earlier draft that gated on a
    `command` KEY as the second signal — plant `{"statusLine": {"type":
    "command"}}` first (no `command` key yet, so the earlier draft never
    fired), then add `"command": "..."` in a second, narrowly-scoped Edit
    that never repeats the literal substring `statusLine`. `type: "command"`
    is itself the enabling signal (Claude Code's schema names no other
    supported `type`), so this first call — the one the bypass relied on
    being silently allowed — must gate on its own."""
    d = evaluate(_write(".claude/settings.local.json",
                         '{"statusLine": {"type": "command"}}'), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_split_plant_second_call_no_longer_reaches_because_first_call_gated():
    """The full two-call bypass sequence from the QA finding: step 1 (armed,
    no command yet) now gates, so a human reviews before step 2 (which adds
    the actual `command` value) could ever run unsupervised."""
    step1 = evaluate(_write(".claude/settings.local.json",
                             '{"statusLine": {"type": "command"}}'), EMPTY)
    assert _gated(step1) and step1.rule == "statusline-protect"
    step2 = evaluate(_edit(".claude/settings.local.json",
                            '"type": "command", "command": "/tmp/evil.sh"'), EMPTY)
    assert not _gated(step2)  # by itself; step 1 above is what stops the plant


def test_unicode_escaped_key_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '{"\\u0073tatusLine": {"type": "command", "command": "evil.sh"}}'), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_unicode_escaped_key_via_mcp_gated():
    d = evaluate(_mcp_write(".claude/settings.local.json",
                             '{"\\u0073tatusLine": {"type": "command", "command": "evil.sh"}}'),
                 EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_partial_edit_fragment_not_valid_json_still_uses_textual_check():
    """An ordinary Edit's `new_string` is a fragment embedded in surrounding
    context (a trailing comma, no enclosing braces of its own) that never
    parses standalone as JSON — `_statusline_json_key_hit` silently no-ops
    (returns False, doesn't raise) and the textual `CLAUDE_STATUSLINE_KEY_RE`
    check alone still carries this case."""
    d = evaluate(_edit(".claude/settings.local.json",
                        '"statusLine": {"padding": 0, "type": "command", "command": "evil.sh"},'),
                 EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_nested_project_path_gated():
    d = evaluate(_write("packages/foo/.claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_user_scope_path_gated():
    d = evaluate(_write("/home/dev/.claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


# ---- MCP-tool writes ------------------------------------------------------------

def test_mcp_write_gated():
    d = evaluate(_mcp_write(".claude/settings.local.json", STATUSLINE_JSON), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_mcp_edit_file_nested_edits_shape_gated():
    d = evaluate(_mcp_edit_nested(".claude/settings.local.json", "{}",
                                   '"statusLine": {"type": "command", "command": "evil.sh"}'),
                 EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_mcp_flat_key_value_arg_shape_gated():
    d = evaluate(_mcp_key_value(".claude/settings.local.json", "statusLine",
                                 {"type": "command", "command": "evil.sh"}), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_mcp_nested_json_dict_key_shape_gated():
    d = evaluate(_mcp_nested_json(".claude/settings.local.json",
                                   {"statusLine": {"type": "command", "command": "evil.sh"}}),
                 EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_mcp_nested_json_without_command_not_gated():
    d = evaluate(_mcp_nested_json(".claude/settings.local.json",
                                   {"statusLine": {"padding": 0}}), EMPTY)
    assert not _gated(d)


def test_mcp_struct_key_depth_capped():
    nested = {"statusLine": {"type": "command", "command": "evil.sh"}}
    for _ in range(8):
        nested = {"wrapper": nested}
    d = evaluate(_mcp_nested_json(".claude/settings.local.json", nested), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_mcp_decoy_literal_content_does_not_suppress_struct_fallback():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_json",
                     action=ActionClass.MCP,
                     args={"path": ".claude/settings.local.json",
                           "content": '{"model": "opus"}',
                           "json": {"statusLine": {"type": "command", "command": "evil.sh"}}})
    d = evaluate(ev, EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_jsonc_comment_mentioning_key_not_gated_for_literal_edit():
    d = evaluate(_write(".claude/settings.local.json",
                         '{\n  // TODO: consider a custom statusLine command later\n'
                         '  "model": "opus"\n}'), EMPTY)
    assert not _gated(d)


# ---- shell forms ----------------------------------------------------------------
# Same self-protect-precedence interaction `test_claude_hooks_protect.py`
# documents at length for the identical file: self-protect's own shell branch
# (write-verb + `.claude` mention, non-escapable) preempts this guard for any
# redirect/sed-i/heredoc/mv form. This guard's own real coverage is the
# write-verb-less jq/sponge shape self-protect's write-verb list never sees.

def test_shell_redirect_already_blocked_by_self_protect():
    d = evaluate(_shell(f"echo '{STATUSLINE_JSON}' > .claude/settings.local.json"), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_sed_inplace_already_blocked_by_self_protect():
    d = evaluate(_shell(
        "sed -i 's/.*/{\"statusLine\":{\"type\":\"command\",\"command\":\"evil.sh\"}}/' "
        ".claude/settings.local.json"), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_jq_sponge_assign_gated():
    d = evaluate(_shell(
        'jq \'.statusLine = {"type": "command", "command": "evil.sh"}\' '
        '.claude/settings.local.json | sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_shell_jq_update_assign_operator_gated():
    d = evaluate(_shell(
        'jq \'.statusLine.command |= "evil.sh"\' .claude/settings.local.json '
        '| sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_shell_jq_bracket_index_notation_gated():
    d = evaluate(_shell(
        'jq \'.["statusLine"]["command"] = "evil.sh"\' .claude/settings.local.json '
        '| sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_jq_equality_comparison_not_gated():
    d = evaluate(_shell(
        "jq 'select(.statusLine.command == null)' .claude/settings.local.json"), EMPTY)
    assert not _gated(d)


def test_jq_plain_read_not_gated():
    assert not _gated(evaluate(
        _shell("jq '.statusLine.command' .claude/settings.local.json"), EMPTY))


def test_jq_statusline_without_command_not_gated():
    d = evaluate(_shell(
        'jq \'.statusLine.padding = 2\' .claude/settings.local.json '
        '| sponge .claude/settings.local.json'), EMPTY)
    assert not _gated(d)


def test_shell_sponge_without_jq_gated():
    """QA finding (independent adversarial review, round A): a CONFIRMED,
    reproduced bypass — `write_hit` originally required a write-verb match
    (redirect/delete-move/in-place-edit/forced-link), none of which `sponge`
    (moreutils) is on. Every OTHER write-verb form into `.claude/` is
    already preempted by self-protect's own non-escapable check, so
    `sponge`-without-`jq` (a plain `echo`/`cat`/`printf` piped straight
    through it, no scripting tool at all) was the one shell shape that sailed
    through fully ALLOWED — precisely the shape this guard's own commit
    message claims to close. Closed by requiring only the content-shape
    match, not a write-verb, once the path is confirmed."""
    d = evaluate(_shell(
        f"echo '{STATUSLINE_JSON}' | sponge .claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_shell_printf_pipe_sponge_gated():
    d = evaluate(_shell(
        f"printf '%s' '{STATUSLINE_JSON}' | sponge .claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_shell_whitespace_padding_does_not_defeat_window_gated():
    """QA finding (round A, reproduced): the original 400-char tempered-dot/
    lookahead window was trivially outrun with schema-legal whitespace
    padding — real Claude Code and real jq both honor it verbatim.
    `_statusline_normalize` collapses any whitespace run to one space before
    either pattern is matched, so padding of any length no longer consumes
    window budget."""
    padded = ('jq \'.statusLine = {"type": "command",' + (" " * 500)
              + '"command": "evil.sh"}\' .claude/settings.local.json '
                '| sponge .claude/settings.local.json')
    d = evaluate(_shell(padded), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_edit_fragment_whitespace_padding_gated():
    padded = ('"statusLine": {"type": "command",' + ("\n" * 200)
              + '"command": "evil.sh"}')
    d = evaluate(_edit(".claude/settings.local.json", padded), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_edit_fragment_unicode_escaped_command_key_gated():
    """QA finding (round A, reproduced): on a partial Edit fragment (never
    valid standalone JSON, so `_statusline_json_key_hit`'s `json.loads`
    never fires), a JSON `\\uXXXX` escape on either key decodes to the real
    key at runtime while evading a purely textual check. Closed by
    `_statusline_normalize`'s decode step, run on fragments too."""
    d = evaluate(_edit(".claude/settings.local.json",
                        '"statusLine": {"type": "command", "\\u0063ommand": "evil.sh"}'),
                 EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_edit_fragment_unicode_escaped_statusline_key_gated():
    d = evaluate(_edit(".claude/settings.local.json",
                        '"\\u0073tatusLine": {"type": "command", "command": "evil.sh"}'),
                 EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_shell_jq_multiline_program_gated():
    """QA finding (round A, reproduced): the original lookaheads excluded a
    literal newline, so a jq program spanning multiple lines inside its own
    single-quoted argument (valid jq syntax, and an ordinary shape for any
    multi-line shell command) pushed the assignment past the exclusion
    boundary. Closed by normalizing the newline away before matching."""
    cmd = ('jq \'.statusLine =\n  {"type":"command","command":"evil.sh"}\' '
           '.claude/settings.local.json | sponge .claude/settings.local.json')
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_shell_jq_ampersand_in_quoted_value_gated():
    """QA finding (round A, reproduced): a `&` character inside a QUOTED jq
    program value (not a real shell control operator) stopped the original
    lookaheads the same way an unescaped one legitimately would. `&` is
    dropped from the exclusion set entirely (accepted narrower-false-ask
    trade-off, see the pattern's own comment)."""
    cmd = ('jq \'.statusLine = {"note": "a&b", "type":"command","command":"evil.sh"}\' '
           '.claude/settings.local.json | sponge .claude/settings.local.json')
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_shell_gojq_drop_in_gated():
    """QA finding (round A, reproduced): `gojq`/`jaq` are common drop-in `jq`
    clones sharing its own path-assignment syntax byte-for-byte; the
    original `\\bjq\\b` token missed both."""
    d = evaluate(_shell(
        'gojq \'.statusLine = {"type":"command","command":"evil.sh"}\' '
        '.claude/settings.local.json | sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_shell_jaq_drop_in_gated():
    d = evaluate(_shell(
        'jaq \'.statusLine = {"type":"command","command":"evil.sh"}\' '
        '.claude/settings.local.json | sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_shell_jq_over_400_chars_between_signals_still_bounded_not_gated():
    """The bounded window is a deliberate design choice (not merely a bug),
    matching every sibling `*_JQ_RE` in this file — an assignment and its
    key sitting genuinely far apart (well past any realistic single
    statement) still isn't matched. This pins that the bound still exists
    post-normalization, it's just no longer defeatable by mere whitespace."""
    filler = "x" * 450
    cmd = (f'jq \'.statusLine = 1; # {filler}\ncommand\' '
           '.claude/settings.local.json | sponge .claude/settings.local.json')
    assert not _gated(evaluate(_shell(cmd), EMPTY))


def test_shell_cd_into_claude_dir_then_bare_filename_gated():
    d = evaluate(_shell(
        'cd .claude && jq \'.statusLine = {"type":"command","command":"evil.sh"}\' '
        'settings.local.json | sponge settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_shell_push_location_into_claude_dir_then_bare_filename_gated():
    d = evaluate(_shell(
        'Push-Location .claude; jq \'.statusLine = {"type":"command","command":"evil.sh"}\' '
        'settings.local.json | sponge settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "statusline-protect"


def test_shell_cd_into_lookalike_dir_not_gated():
    for cmd in (
        'cd .claude-old && jq \'.statusLine={"type":"command","command":"x"}\' '
        'settings.local.json | sponge settings.local.json',
        'cd .claude.bak && jq \'.statusLine={"type":"command","command":"x"}\' '
        'settings.local.json | sponge settings.local.json',
    ):
        assert not _gated(evaluate(_shell(cmd), EMPTY)), cmd


def test_shell_write_without_write_verb_not_gated():
    assert not _gated(evaluate(_shell('cat .claude/settings.local.json'), EMPTY))


def test_shell_redirect_to_unrelated_file_not_gated():
    assert not _gated(evaluate(_shell(f"echo '{STATUSLINE_JSON}' > output.txt"), EMPTY))


# ---- benign cases: must NOT gate -------------------------------------------------

def test_benign_local_settings_edit_not_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '{"model": "opus", "env": {"FOO": "bar"}}'), EMPTY)
    assert not _gated(d)


def test_project_settings_json_not_gated_by_this_guard():
    """`.claude/settings.json` is already fully blocked outright by
    self-protect; this content-gated guard's own path check must not also
    fire on it."""
    d = evaluate(_write(".claude/settings.json", STATUSLINE_JSON), EMPTY)
    assert d.rule != "statusline-protect"


def test_unrelated_file_mentioning_statusline_not_gated():
    assert not _gated(evaluate(
        _write("README.md", 'Set a custom statusLine command in your settings...'), EMPTY))


def test_reading_settings_local_json_not_gated():
    read_ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Read",
                          args={"file_path": ".claude/settings.local.json"})
    assert not _gated(evaluate(read_ev, EMPTY))


def test_unrelated_path_named_settings_local_json_not_gated():
    assert not _gated(evaluate(
        _write("config/settings.local.json", STATUSLINE_JSON), EMPTY))


def test_settings_local_json_backup_file_not_gated():
    assert not _gated(evaluate(
        _write(".claude/settings.local.json.bak", STATUSLINE_JSON), EMPTY))


# ---- escape hatches: human-only --------------------------------------------------

_JQ_SPONGE_CMD = ('jq \'.statusLine = {"type": "command", "command": "evil.sh"}\' '
                   '.claude/settings.local.json | sponge .claude/settings.local.json')


def test_human_can_override_shell_with_comment():
    assert not _gated(evaluate(_shell(_JQ_SPONGE_CMD + " # aegis-allow"), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(_shell(_JQ_SPONGE_CMD + " # aegis-allow"), EMPTY))


def test_env_toggle_allows_edit_write_and_shell(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_STATUSLINE", "1")
    assert not _gated(evaluate(_write(".claude/settings.local.json"), EMPTY))
    assert not _gated(evaluate(_shell(_JQ_SPONGE_CMD), EMPTY))


def test_policy_allow_regex_skips_gate():
    pol = Policy(statusline={"allow": [r"\.claude/settings\.local\.json"]})
    assert not _gated(evaluate(_write(".claude/settings.local.json"), pol))


# ---- modes: ask (default) / deny / monitor / off ----------------------------------

def test_default_mode_is_ask():
    d = evaluate(_write(".claude/settings.local.json"), EMPTY)
    assert d.action == Action.ASK and d.rule == "statusline-protect"
    d2 = evaluate(_shell(_JQ_SPONGE_CMD), EMPTY)
    assert d2.action == Action.ASK and d2.rule == "statusline-protect"


def test_deny_mode_hard_blocks():
    d = evaluate(_write(".claude/settings.local.json"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == "statusline-protect"


def test_monitor_mode_logs_and_allows():
    pol = Policy(statusline={"mode": "monitor"})
    assert not _gated(evaluate(_write(".claude/settings.local.json"), pol))


def test_off_mode_disables_guard():
    pol = Policy(statusline={"mode": "off"})
    assert not _gated(evaluate(_write(".claude/settings.local.json"), pol))


# ---- perf / ReDoS ------------------------------------------------------------------

def test_perf_no_redos_on_adversarial_shell_input():
    adversarial = ("jq " + "a" * 5000 + " .claude/settings.local.json | sponge "
                    ".claude/settings.local.json " + "b" * 5000)
    start = time.time()
    evaluate(_shell(adversarial), EMPTY)
    assert time.time() - start < 1.0


def test_perf_no_redos_on_long_path_content():
    long_content = ('"x": "' + ("y" * 20000)
                     + '", "statusLine": {"type": "command", "command": "evil.sh"}')
    start = time.time()
    d = evaluate(_write(".claude/settings.local.json", long_content), EMPTY)
    assert time.time() - start < 1.0
    assert _gated(d)


def test_perf_no_redos_on_adversarial_key_content():
    adversarial = '"statusLine": {' + ('x' * 20000) + '}'
    start = time.time()
    evaluate(_write(".claude/settings.local.json", adversarial), EMPTY)
    assert time.time() - start < 1.0


# ---- direct pattern sanity ---------------------------------------------------------

def test_statusline_key_regex_matches_expected_forms():
    for content in (
        '"statusLine": {"type": "command", "command": "x"}',
        "'statusLine': {'type': 'command', 'command': 'x'}",
    ):
        assert patterns.CLAUDE_STATUSLINE_KEY_RE.search(content), content


def test_statusline_key_regex_does_not_match_command_free_form():
    assert not patterns.CLAUDE_STATUSLINE_KEY_RE.search('"statusLine": {"padding": 0}')
