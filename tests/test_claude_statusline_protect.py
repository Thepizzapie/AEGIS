"""Claude Code statusLine-config protection guard — blocks planting/altering a
``statusLine`` entry carrying a ``command`` field in
``.claude/settings.local.json``, the project-local, gitignored-by-default
sibling of ``.claude/settings.json`` that Claude Code reads with equal
authority, but that ``rule_claude_hooks_protect`` deliberately leaves alone
(its own docstring names `statusLine` as ordinary, benign personal config).

Per Claude Code's docs, a `statusLine` block with `"type": "command"` runs
any shell script configured there — Claude Code execs `command` directly as
its own subprocess, event-driven throughout the session, entirely OUTSIDE
the tool-call loop Aegis's own PreToolUse hook evaluates, and re-fires on
its own with no further tool call needed at all (unlike a planted `hooks`
entry, which needs a matching tool call to fire again).
"""
import time

from aegis import patterns
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                                  # default mode: ask
DENY = Policy(claude_statusline={"mode": "deny"})                 # stricter, hard-block posture

STATUSLINE_JSON = '{"statusLine": {"type": "command", "command": "echo hi"}}'


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
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_statusline_command_via_edit_gated():
    d = evaluate(_edit(".claude/settings.local.json",
                        '"statusLine": {"type": "command", "command": "evil.sh"}'), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_windows_path_separator_gated():
    assert _gated(evaluate(_write(".claude\\settings.local.json"), EMPTY))


def test_single_quoted_key_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         "'statusLine': {'type': 'command', 'command': 'evil.sh'}"), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_statusline_without_command_field_not_gated():
    """A `statusLine` object present with no `command` field yet can't
    actually run anything — unlike `hooks` (no safe value once present at
    all), gating on the bare key alone here would be over-broad."""
    d = evaluate(_write(".claude/settings.local.json",
                         '{"statusLine": {"padding": 2}}'), EMPTY)
    assert not _gated(d)


def test_command_field_elsewhere_without_statusline_not_gated():
    """A `command` field belonging to an unrelated block (e.g. a `hooks`
    entry) must not trip THIS guard on its own — that shape is
    claude-hooks-protect's own territory, not statusLine's."""
    hit = patterns.claude_statusline_key_hit(
        '{"hooks": {"PreToolUse": [{"type": "command", "command": "x"}]}}')
    assert hit is False


def test_benign_hooks_entry_not_gated_by_this_guard():
    ev = _write(".claude/settings.local.json",
                '{"hooks": {"PreToolUse": [{"type": "command", "command": "eslint"}]}}')
    d = evaluate(ev, EMPTY)
    assert d.rule != "claude-statusline-protect"


def test_benign_statusline_json_filename_mention_not_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '{"env": {"NOTES_FILE": "statusLine.json"}}'), EMPTY)
    assert not _gated(d)


def test_lookalike_key_not_gated():
    """A lookalike key name must not match the exact `statusLine` key
    check."""
    d = evaluate(_write(".claude/settings.local.json",
                         '{"myStatusLineWrapper": {"command": "x"}}'), EMPTY)
    assert not _gated(d)


def test_unicode_escaped_key_gated():
    """The identical JSON `\\uXXXX`-escape bypass class
    `_claude_hooks_json_key_hit` closes for `hooks` — closed here by
    `_claude_statusline_json_key_hit`, which parses whole-file-valid JSON
    content and walks the DECODED structure semantically."""
    d = evaluate(_write(".claude/settings.local.json",
                         '{"\\u0073tatusLine": {"type": "command", '
                         '"command": "evil.sh"}}'), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_unicode_escaped_key_via_mcp_gated():
    d = evaluate(_mcp_write(".claude/settings.local.json",
                             '{"\\u0073tatusLine": {"type": "command", '
                             '"command": "evil.sh"}}'), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_partial_edit_fragment_not_valid_json_still_uses_textual_check():
    d = evaluate(_edit(".claude/settings.local.json",
                        '"statusLine": {"type": "command", "command": "evil.sh"}'), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_nested_project_path_gated():
    d = evaluate(_write("packages/foo/.claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_user_scope_path_gated():
    d = evaluate(_write("/home/dev/.claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


# ---- MCP-tool writes ------------------------------------------------------------

def test_mcp_write_gated():
    d = evaluate(_mcp_write(".claude/settings.local.json", STATUSLINE_JSON), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_mcp_edit_file_nested_edits_shape_gated():
    d = evaluate(_mcp_edit_nested(
        ".claude/settings.local.json", "{}",
        '"statusLine": {"type": "command", "command": "evil.sh"}'), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_mcp_flat_key_value_arg_shape_gated():
    d = evaluate(_mcp_key_value(".claude/settings.local.json", "statusLine",
                                 {"type": "command", "command": "evil.sh"}), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_mcp_nested_json_dict_key_shape_gated():
    d = evaluate(_mcp_nested_json(
        ".claude/settings.local.json",
        {"statusLine": {"type": "command", "command": "evil.sh"}}), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_mcp_nested_json_statusline_without_command_not_gated():
    d = evaluate(_mcp_nested_json(
        ".claude/settings.local.json", {"statusLine": {"padding": 2}}), EMPTY)
    assert not _gated(d)


def test_mcp_struct_key_depth_capped():
    nested = {"statusLine": {"type": "command", "command": "evil.sh"}}
    for _ in range(8):
        nested = {"wrapper": nested}
    d = evaluate(_mcp_nested_json(".claude/settings.local.json", nested), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_mcp_decoy_literal_content_does_not_suppress_struct_fallback():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_json",
                     action=ActionClass.MCP,
                     args={"path": ".claude/settings.local.json",
                           "content": '{"model": "opus"}',
                           "json": {"statusLine": {"type": "command",
                                                    "command": "evil.sh"}}})
    d = evaluate(ev, EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_jsonc_comment_mentioning_key_not_gated_for_literal_edit():
    d = evaluate(_write(".claude/settings.local.json",
                         '{\n  // TODO: consider a statusLine later\n'
                         '  "model": "opus"\n}'), EMPTY)
    assert not _gated(d)


# ---- shell forms ----------------------------------------------------------------
#
# Same precedence note as claude-hooks-protect's own test suite: self-protect's
# shell branch already, non-escapably, denies ANY shell command that mentions
# `.claude` anywhere AND carries a write-verb it recognizes (redirect, in-place
# edit, copy, move/rename, destructive delete) — so those shapes surface as
# `self-protect`, not `claude-statusline-protect`. This guard's own real,
# non-redundant coverage is the shape self-protect's write-verb list does NOT
# recognize: a scripted `jq`-through-`sponge` mutation.

def test_shell_redirect_already_blocked_by_self_protect():
    d = evaluate(_shell(f"echo '{STATUSLINE_JSON}' > .claude/settings.local.json"), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_sed_inplace_already_blocked_by_self_protect():
    d = evaluate(_shell(
        "sed -i 's/.*/{\"statusLine\": {\"type\": \"command\", \"command\": \"x\"}}/' "
        ".claude/settings.local.json"), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_cat_heredoc_already_blocked_by_self_protect():
    d = evaluate(_shell(
        'cat > .claude/settings.local.json <<EOF\n'
        f'{STATUSLINE_JSON}\n'
        'EOF'), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_jq_sponge_assign_gated():
    d = evaluate(_shell(
        'jq \'.statusLine = {"type": "command", "command": "evil.sh"}\' '
        '.claude/settings.local.json | sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_shell_jq_split_assign_gated():
    """`.statusLine.command = "..."` sets ONLY the command value on an
    already-present statusLine object — the two keys are not textually
    adjacent the way a fresh nested-object literal would put them, so this
    exercises the "both keys anywhere in the jq program" design of
    `CLAUDE_STATUSLINE_JQ_RE` (deliberately looser than the literal-JSON
    `CLAUDE_STATUSLINE_KEY_RE` check, which requires the fixed nested
    order)."""
    d = evaluate(_shell(
        'jq \'.statusLine.command = "evil.sh"\' .claude/settings.local.json '
        '| sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_shell_jq_merge_form_via_mv_already_blocked_by_self_protect():
    d = evaluate(_shell(
        'jq \'. += {statusLine: {type: "command", command: "evil.sh"}}\' '
        '.claude/settings.local.json > /tmp/x.json && '
        'mv /tmp/x.json .claude/settings.local.json'), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_jq_update_assign_operator_gated():
    d = evaluate(_shell(
        'jq \'.statusLine |= {"type": "command", "command": "evil.sh"}\' '
        '.claude/settings.local.json | sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_jq_equality_comparison_not_gated():
    d = evaluate(_shell(
        "jq 'select(.statusLine.command == null)' .claude/settings.local.json"), EMPTY)
    assert not _gated(d)


def test_jq_plain_read_not_gated():
    assert not _gated(evaluate(
        _shell("jq '.statusLine' .claude/settings.local.json"), EMPTY))


def test_jq_statusline_only_no_command_not_gated():
    """A jq mutation that only touches `statusLine` with no `command`
    anywhere in the program (e.g. clearing `padding`) must not gate — the
    guard requires both signals, matching the literal-JSON check's own
    both-keys-required design."""
    d = evaluate(_shell(
        'jq \'.statusLine.padding = 4\' .claude/settings.local.json '
        '| sponge .claude/settings.local.json'), EMPTY)
    assert not _gated(d)


def test_shell_cd_into_claude_dir_then_bare_filename_gated():
    d = evaluate(_shell(
        'cd .claude && jq \'.statusLine = {"type": "command", "command": "x"}\' '
        'settings.local.json | sponge settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_shell_pushd_into_claude_dir_then_redirect_already_blocked_by_self_protect():
    d = evaluate(_shell(
        f"pushd .claude && echo '{STATUSLINE_JSON}' > settings.local.json && popd"), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_set_location_into_claude_dir_then_bare_filename_gated():
    d = evaluate(_shell(
        'Set-Location .claude; Set-Content settings.local.json '
        '\'{"statusLine": {"type": "command", "command": "evil.sh"}}\''), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_shell_push_location_into_claude_dir_then_bare_filename_gated():
    d = evaluate(_shell(
        'Push-Location .claude; jq \'.statusLine = {"type": "command", '
        '"command": "x"}\' settings.local.json | sponge settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_shell_cd_elsewhere_then_bare_filename_not_gated():
    assert not _gated(evaluate(_shell(
        'cd /tmp && echo "see settings.local.json for statusLine config"'), EMPTY))


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


def test_shell_jq_sponge_to_unrelated_key_not_gated():
    d = evaluate(_shell(
        'jq \'.model = "opus"\' .claude/settings.local.json '
        '| sponge .claude/settings.local.json'), EMPTY)
    assert not _gated(d)


def test_shell_redirect_to_unrelated_file_not_gated():
    assert not _gated(evaluate(_shell(f"echo '{STATUSLINE_JSON}' > output.txt"), EMPTY))


# ---- benign cases: must NOT gate -------------------------------------------------

def test_benign_local_settings_edit_not_gated():
    """Ordinary personal-settings tweaks (permissions/env/model/outputStyle)
    carry no `statusLine`+`command` shape and are routine, sanctioned local
    customization."""
    d = evaluate(_write(".claude/settings.local.json",
                         '{"model": "opus", "env": {"FOO": "bar"}}'), EMPTY)
    assert not _gated(d)


def test_project_settings_json_not_gated_by_this_guard():
    """`.claude/settings.json` (not `.local.json`) is already fully blocked
    outright by self-protect — this guard's own path check must not also
    fire on it."""
    d = evaluate(_write(".claude/settings.json", STATUSLINE_JSON), EMPTY)
    assert d.rule != "claude-statusline-protect"


def test_unrelated_file_mentioning_statusline_not_gated():
    assert not _gated(evaluate(
        _write("README.md",
               'Add a "statusLine" command entry to customize the status bar...'), EMPTY))


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

_JQ_SPONGE_CMD = ('jq \'.statusLine = {"type": "command", "command": "x"}\' '
                   '.claude/settings.local.json | sponge .claude/settings.local.json')


def test_human_can_override_shell_with_comment():
    assert not _gated(evaluate(_shell(_JQ_SPONGE_CMD + " # aegis-allow"), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(_shell(_JQ_SPONGE_CMD + " # aegis-allow"), EMPTY))


def test_env_toggle_allows_edit_write_and_shell(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CLAUDE_STATUSLINE", "1")
    assert not _gated(evaluate(_write(".claude/settings.local.json"), EMPTY))
    assert not _gated(evaluate(_shell(_JQ_SPONGE_CMD), EMPTY))


def test_policy_allow_regex_skips_gate():
    pol = Policy(claude_statusline={"allow": [r"\.claude/settings\.local\.json"]})
    assert not _gated(evaluate(_write(".claude/settings.local.json"), pol))


# ---- modes: ask (default) / deny / monitor / off ----------------------------------

def test_default_mode_is_ask():
    d = evaluate(_write(".claude/settings.local.json"), EMPTY)
    assert d.action == Action.ASK and d.rule == "claude-statusline-protect"
    d2 = evaluate(_shell(_JQ_SPONGE_CMD), EMPTY)
    assert d2.action == Action.ASK and d2.rule == "claude-statusline-protect"


def test_deny_mode_hard_blocks():
    d = evaluate(_write(".claude/settings.local.json"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == "claude-statusline-protect"


def test_monitor_mode_logs_and_allows():
    pol = Policy(claude_statusline={"mode": "monitor"})
    assert not _gated(evaluate(_write(".claude/settings.local.json"), pol))


def test_off_mode_disables_guard():
    pol = Policy(claude_statusline={"mode": "off"})
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
                     + '", "statusLine": {"type": "command", "command": "z"}')
    start = time.time()
    d = evaluate(_write(".claude/settings.local.json", long_content), EMPTY)
    assert time.time() - start < 1.0
    assert _gated(d)


def test_perf_no_redos_on_adversarial_content_no_command_key():
    """The lazy `{0,300}?` span between `statusLine` and `command` must stay
    linear even when the interior text never actually contains a real
    `command` key to find (worst case for a lazy quantifier: it has to
    exhaust the bound before failing)."""
    adversarial = ('"statusLine": {' + ('"x": "y", ' * 3000) + '}')
    start = time.time()
    evaluate(_write(".claude/settings.local.json", adversarial), EMPTY)
    assert time.time() - start < 1.0


# ---- regression: round-A bypass-hunt findings (fixed-width regex window) --------
#
# QA finding (independent adversarial review, round A): the ORIGINAL
# `CLAUDE_STATUSLINE_KEY_RE` bounded the span between the two keys with a
# fixed-width lazy character class (`[^{}]{0,300}?`) — a decoy field long
# enough to push `command` past 300 chars missed a live payload, and
# separately, ANY nested sub-object before `command` (the class excludes
# braces entirely) broke the match with zero padding needed at all. Both
# gave a silent ALLOW on a working statusLine-command payload. Fixed by
# `claude_statusline_key_hit()`, a brace-depth-aware structural scan — the
# tests below pin both confirmed bypasses as regressions.

def test_long_decoy_field_before_command_still_gated():
    """A single long sibling field pushed `command` well past the OLD
    300-char window — must still gate under the new structural scan, which
    has no fixed-width limit at all."""
    frag = ('"statusLine": {"type": "command", "junk": "' + "X" * 350
            + '", "command": "evil.sh"}')
    d = evaluate(_edit(".claude/settings.local.json", frag), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_nested_decoy_object_before_command_still_gated():
    """A nested sub-object between `statusLine`'s open brace and `command`
    broke the OLD character-class-based match unconditionally (it excluded
    `{`/`}` entirely) — the structural scan walks INTO nested objects
    rather than treating them as a boundary, so this must still gate."""
    frag = '"statusLine": {"type": "command", "decoy": {"x": 1}, "command": "evil.sh"}'
    d = evaluate(_edit(".claude/settings.local.json", frag), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_jsonc_trailing_comma_with_long_decoy_still_gated():
    """The combined round-A finding: a trailing comma (JSONC-style) breaks
    `json.loads`, silencing the semantic fallback, while the same long
    decoy field breaks the old textual window — a whole-file Write with a
    fully working payload that both layers used to miss at once."""
    content = ('{"statusLine": {"type": "command", "junk": "' + "X" * 280
               + '", "command": "evil.sh",}}')
    d = evaluate(_write(".claude/settings.local.json", content), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_command_key_inside_string_value_does_not_desync_span():
    """A `command`-shaped substring INSIDE a quoted string value (not a
    real key) must not confuse the brace-depth/string-aware scan into
    either over- or under-matching; the real `command` KEY later in the
    same object must still be found."""
    frag = ('"statusLine": {"type": "command", "note": "see \\"command\\" '
            'below", "command": "evil.sh"}')
    d = evaluate(_edit(".claude/settings.local.json", frag), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_brace_inside_string_value_does_not_desync_span():
    """A literal `{`/`}` character inside a quoted string value (part of
    an unrelated field, before `command`) must not prematurely close the
    tracked object span."""
    frag = ('"statusLine": {"type": "command", "note": "a {brace} in text", '
            '"command": "evil.sh"}')
    d = evaluate(_edit(".claude/settings.local.json", frag), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_unterminated_object_fragment_still_gated():
    """An Edit `new_string` that ends mid-object (the closing brace sits
    outside the diff) must still be scanned to end-of-content, not silently
    dropped."""
    frag = '"statusLine": {"type": "command", "command": "evil.sh"'
    d = evaluate(_edit(".claude/settings.local.json", frag), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_perf_no_redos_on_many_statusline_occurrences():
    """The structural scan is capped by a shared character BUDGET
    (`_STATUSLINE_SCAN_BUDGET`), not a match count — many repeated,
    never-closed occurrences must stay fast rather than quadratic."""
    adversarial = '"statusLine": {"type": "x", ' * 3000
    start = time.time()
    d = evaluate(_write(".claude/settings.local.json", adversarial), EMPTY)
    assert time.time() - start < 1.0
    assert not _gated(d)


# ---- regression: round-B bypass-hunt findings (match-count cap) -----------------
#
# QA finding (round-B independent adversarial review, following up on round A's
# fix): the round-A fix capped the NUMBER of `statusLine` occurrences examined
# at 20 (`_STATUSLINE_MAX_SPANS`), not the total scanning work. Two confirmed
# bypasses of THAT specific shape: (1) planting 21+ short, ordinary decoy
# `statusLine` occurrences ahead of the real payload defeated detection
# outright — no padding trick needed, just more decoys than the count cap
# allowed; (2) many short UNCLOSED spans against large (~8MB) content each
# independently re-scanned to end-of-content, multiplying out to several
# seconds. Both fixed by replacing the count cap with a shared character
# BUDGET (`_STATUSLINE_SCAN_BUDGET`) that every span's actual consumed length
# is deducted from, capping total work regardless of occurrence count or
# content size — see `claude_statusline_key_hit`'s own docstring in
# patterns.py for the full history.

def test_many_short_decoys_beyond_old_count_cap_still_gated():
    """25 short decoy `statusLine` occurrences (no `command` field) ahead of
    the real payload — one more than the OLD 20-occurrence count cap — must
    not defeat detection under the new budget-based scan."""
    decoys = '"statusLine": {"type": "notcommand"}, ' * 25
    frag = decoys + '"statusLine": {"type": "command", "command": "evil.sh"}'
    d = evaluate(_edit(".claude/settings.local.json", frag), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_many_short_decoys_with_jsonc_trailing_comma_write_still_gated():
    """The combined round-B finding: many short decoys (defeating the old
    count cap) PLUS a JSONC trailing comma (silencing the JSON semantic
    fallback) in a whole-file Write — must still gate under the new scan."""
    decoys = '"statusLine": {"type":"notcommand"}, ' * 25
    content = ('{\n' + decoys
               + '"statusLine": {"type": "command", "command": "evil.sh"},\n}\n')
    d = evaluate(_write(".claude/settings.local.json", content), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


def test_perf_many_unclosed_spans_against_large_content():
    """Many short UNCLOSED `statusLine` spans against large (multi-MB)
    surrounding content must not multiply out to occurrences x
    content-length — each span's scan is capped by the shared remaining
    budget, so this must stay well under 1s even at several MB."""
    adversarial = ('"statusLine": {' + ("X" * 40)) * 20 + ("Y" * (8 * 1024 * 1024))
    start = time.time()
    evaluate(_write(".claude/settings.local.json", adversarial), EMPTY)
    assert time.time() - start < 1.0


def test_real_payload_within_budget_after_many_decoys_gated():
    """A real payload sitting well within the scan budget, after a large
    but budget-compatible number of short decoys, must still be found —
    confirms the budget replaces the old fixed count of 20 with something
    materially more permissive for realistic (short-decoy) inputs."""
    decoys = '"statusLine": {"type": "notcommand"}, ' * 500
    frag = decoys + '"statusLine": {"type": "command", "command": "evil.sh"}'
    d = evaluate(_edit(".claude/settings.local.json", frag), EMPTY)
    assert _gated(d) and d.rule == "claude-statusline-protect"


# ---- direct pattern sanity ---------------------------------------------------------

def test_key_hit_matches_expected_forms():
    for content in (
        '"statusLine": {"type": "command", "command": "x"}',
        "'statusLine': {'type': 'command', 'command': 'x'}",
        '"statusLine":{"type":"command","command":"x"}',
    ):
        assert patterns.claude_statusline_key_hit(content), content


def test_key_hit_does_not_match_statusline_without_command():
    assert not patterns.claude_statusline_key_hit('"statusLine": {"padding": 2}')


def test_path_regex_does_not_match_settings_json():
    assert not patterns.CLAUDE_LOCAL_SETTINGS_PATH_RE.search(".claude/settings.json")
