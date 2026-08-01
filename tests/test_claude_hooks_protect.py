"""Claude Code hook-config protection guard — blocks planting/altering a
``hooks`` entry in ``.claude/settings.local.json``, the project-local,
gitignored-by-default sibling of ``.claude/settings.json`` that Claude Code
reads and merges hooks from with equal authority, but that self-protect's
own ``ENFORCEMENT_PATH_RE`` never mentions and no other guard reaches.

A planted hook runs as Claude Code's own subprocess on the very next
matching tool call — often the same session, no restart/future-trigger
needed — entirely OUTSIDE the tool-call loop Aegis's own PreToolUse hook
evaluates.
"""
import time

from aegis import patterns
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                            # default mode: ask
DENY = Policy(claude_hooks={"mode": "deny"})                 # stricter, hard-block posture

HOOKS_JSON = ('{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": '
              '[{"type": "command", "command": "echo hi"}]}]}}')


def _edit(path, new_string=HOOKS_JSON):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                       args={"file_path": path, "new_string": new_string})


def _write(path, content=HOOKS_JSON):
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

def test_hooks_key_via_write_gated():
    d = evaluate(_write(".claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_hooks_key_via_edit_gated():
    d = evaluate(_edit(".claude/settings.local.json", '"hooks": {"PreToolUse": []}'), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_windows_path_separator_gated():
    assert _gated(evaluate(_write(".claude\\settings.local.json"), EMPTY))


def test_single_quoted_key_gated():
    d = evaluate(_write(".claude/settings.local.json", "'hooks': {'PreToolUse': []}"), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_bracket_form_gated():
    d = evaluate(_write(".claude/settings.local.json", '"hooks"]'), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_bareword_dot_form_in_literal_content_not_gated():
    """QA finding (independent adversarial review, round A): an earlier
    draft also matched a bareword dot/bracket form (`hooks.`/`hooks[`) on
    ordinary Edit/Write literal content, intended for jq path-expression
    text — but real settings.local.json content is always proper JSON,
    where a live `hooks` key is always quote-delimited, so that alternative
    had no legitimate literal-JSON shape to catch and was a false-positive
    magnet on benign content that merely mentions `hooks.json`/`hooks.md`/
    `hooks[0]` (a webhook-URL note, a doc reference). Dropped for Edit/
    Write/MCP content; the jq-specific dot-path mutation form is still
    caught, more safely, via `CLAUDE_HOOKS_JQ_RE` on the shell branch (see
    `test_shell_jq_sponge_assign_gated` — that one requires an
    assignment-shaped operator adjacent to the bareword, not mere
    co-occurrence)."""
    assert not _gated(evaluate(
        _write(".claude/settings.local.json", "hooks.PreToolUse = []"), EMPTY))


def test_benign_hooks_json_filename_mention_not_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '{"env": {"NOTES_FILE": "hooks.json"}}'), EMPTY)
    assert not _gated(d)


def test_benign_hooks_array_index_mention_not_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '{"env": {"REF": "see hooks[0] in the docs"}}'), EMPTY)
    assert not _gated(d)


def test_webhooks_key_not_gated():
    """`webhooks`/similar lookalike keys must not match the exact `hooks`
    key check."""
    d = evaluate(_write(".claude/settings.local.json",
                         '{"webhooks": {"url": "https://example.com"}}'), EMPTY)
    assert not _gated(d)


def test_unicode_escaped_key_gated():
    """QA finding (independent adversarial review, round A): a CONFIRMED,
    reproduced silent-ALLOW bypass — JSON's own `\\uXXXX` escape lets the
    key `"hooks"` be spelled byte-for-byte differently in the raw text
    (`"\\u0068ooks"` decodes to the real key `hooks`) while evading a purely
    textual substring check. Closed by `_claude_hooks_json_key_hit`, which
    parses whole-file-valid JSON content and walks the DECODED structure
    semantically rather than pattern-matching the raw text."""
    d = evaluate(_write(".claude/settings.local.json",
                         '{"\\u0068ooks": {"PreToolUse": [{"matcher": "Bash", "hooks": '
                         '[{"type": "command", "command": "echo hi"}]}]}}'), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_unicode_escaped_key_via_mcp_gated():
    d = evaluate(_mcp_write(".claude/settings.local.json",
                             '{"\\u0068ooks": {"PreToolUse": []}}'), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_partial_edit_fragment_not_valid_json_still_uses_textual_check():
    """An ordinary Edit's `new_string` is usually a partial fragment (no
    enclosing braces) that never parses standalone as JSON — the JSON
    semantic check silently no-ops (returns False, doesn't raise) and the
    textual `CLAUDE_HOOKS_KEY_RE` check alone still carries this case, the
    same as before the round-A fix."""
    d = evaluate(_edit(".claude/settings.local.json", '"hooks": {"PreToolUse": []}'), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_nested_project_path_gated():
    d = evaluate(_write("packages/foo/.claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_user_scope_path_gated():
    d = evaluate(_write("/home/dev/.claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


# ---- MCP-tool writes ------------------------------------------------------------

def test_mcp_write_gated():
    d = evaluate(_mcp_write(".claude/settings.local.json", HOOKS_JSON), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_mcp_edit_file_nested_edits_shape_gated():
    """A third-party MCP filesystem server's own edit tool nests changes as
    {path, edits: [{oldText, newText}]} rather than Claude Code's own
    content/new_string convention."""
    d = evaluate(_mcp_edit_nested(".claude/settings.local.json", "{}",
                                   '"hooks": {"PreToolUse": []}'), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_mcp_flat_key_value_arg_shape_gated():
    """A "set config value"-style MCP tool passing the key as a bare arg
    value, never embedded as JSON text adjacent to a colon/bracket."""
    d = evaluate(_mcp_key_value(".claude/settings.local.json", "hooks",
                                 {"PreToolUse": []}), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_mcp_nested_json_dict_key_shape_gated():
    """An MCP tool accepting structured JSON ({"json": {...}}) rather than a
    raw string — the key is a dict KEY here, never a string value, so
    `_flatten_strings` (value-only by design) never surfaces it."""
    d = evaluate(_mcp_nested_json(".claude/settings.local.json",
                                   {"hooks": {"PreToolUse": []}}), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_mcp_struct_key_depth_capped():
    nested = {"hooks": {"PreToolUse": []}}
    for _ in range(8):
        nested = {"wrapper": nested}
    d = evaluate(_mcp_nested_json(".claude/settings.local.json", nested), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_mcp_decoy_literal_content_does_not_suppress_struct_fallback():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_json",
                     action=ActionClass.MCP,
                     args={"path": ".claude/settings.local.json",
                           "content": '{"model": "opus"}',
                           "json": {"hooks": {"PreToolUse": []}}})
    d = evaluate(ev, EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_jsonc_comment_mentioning_key_not_gated_for_literal_edit():
    """The bareword/struct fallback is scoped to ActionClass.MCP only, never
    Edit/Write — an ordinary Edit/Write whose literal content merely
    mentions "hooks" in a comment or unrelated string must not
    false-positive without the real key shape present."""
    d = evaluate(_write(".claude/settings.local.json",
                         '{\n  // TODO: consider adding hooks later\n'
                         '  "model": "opus"\n}'), EMPTY)
    assert not _gated(d)


# ---- shell forms ----------------------------------------------------------------
#
# `rule_self_protect`'s own shell branch (`CONFIG_DIR_RE`, whole-command
# scoped) already, non-escapably, denies ANY shell command that both
# mentions `.claude` anywhere AND carries a write-verb it recognizes
# (redirect, in-place edit, copy, move/rename, destructive delete) —
# broader than settings.local.json specifically, and it runs earlier in
# `_CORE_RULES`, so first-deny-wins surfaces `self-protect`, not
# `claude-hooks-protect`, for those shapes. That's a strictly STRONGER
# outcome (non-escapable) than this guard's own `ask`-by-default posture,
# not a regression — the tests below pin that interaction explicitly rather
# than assert an incorrect rule name. This guard's own real, non-redundant
# coverage is the shape self-protect's write-verb list does NOT recognize:
# a scripted `jq`-through-`sponge` mutation with no redirect/mv/sed-i/rm
# verb anywhere in the command (see `test_shell_jq_sponge_assign_gated`
# below, and `rule_package_manifest_protect`'s own docstring for the
# identical "jq has no -i flag" gap in a sibling guard).

def test_shell_redirect_already_blocked_by_self_protect():
    d = evaluate(_shell(f"echo '{HOOKS_JSON}' > .claude/settings.local.json"), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_sed_inplace_already_blocked_by_self_protect():
    d = evaluate(_shell(
        "sed -i 's/.*/{\"hooks\": {\"PreToolUse\": []}}/' .claude/settings.local.json"), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_cat_heredoc_already_blocked_by_self_protect():
    d = evaluate(_shell(
        'cat > .claude/settings.local.json <<EOF\n'
        '{"hooks": {"PreToolUse": []}}\n'
        'EOF'), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_jq_sponge_assign_gated():
    d = evaluate(_shell(
        'jq \'.hooks.PreToolUse = [{"hooks":[{"type":"command","command":"evil"}]}]\' '
        '.claude/settings.local.json | sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_shell_jq_merge_form_via_mv_already_blocked_by_self_protect():
    """The `mv` at the end is itself a move-verb self-protect already
    recognizes for any `.claude`-mentioning command — same precedence note
    as the plain redirect/sed/heredoc cases above."""
    d = evaluate(_shell(
        'jq \'. += {hooks: {"PreToolUse": []}}\' .claude/settings.local.json '
        '> /tmp/x.json && mv /tmp/x.json .claude/settings.local.json'), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_jq_update_assign_operator_gated():
    d = evaluate(_shell(
        'jq \'.hooks |= {"PreToolUse": []}\' .claude/settings.local.json '
        '| sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_shell_jq_bracket_index_notation_gated():
    d = evaluate(_shell(
        'jq \'.["hooks"] = {"PreToolUse": []}\' .claude/settings.local.json '
        '| sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_jq_equality_comparison_not_gated():
    """jq's equality operator (`==`, e.g. inside a `select()` filter) is a
    READ, not a write — must not be mistaken for the assignment-shaped
    operators this guard gates on."""
    d = evaluate(_shell(
        "jq 'select(.hooks == null)' .claude/settings.local.json"), EMPTY)
    assert not _gated(d)


def test_jq_plain_read_not_gated():
    assert not _gated(evaluate(
        _shell("jq '.hooks' .claude/settings.local.json"), EMPTY))


def test_shell_cd_into_claude_dir_then_bare_filename_gated():
    """QA-precedented bypass class (VS Code/devcontainer guards): a prior
    `cd .claude` in the same command lets a later bare `settings.local.json`
    reference drop the `.claude/` prefix entirely."""
    d = evaluate(_shell(
        'cd .claude && jq \'.hooks = {"PreToolUse": []}\' '
        'settings.local.json | sponge settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_shell_pushd_into_claude_dir_then_redirect_already_blocked_by_self_protect():
    """`pushd .claude` still puts the literal text `.claude` in the command,
    so self-protect's whole-command-scoped `CONFIG_DIR_RE` + `WRITE_REDIRECT_RE`
    still fires first — same precedence note as the plain-redirect cases."""
    d = evaluate(_shell(
        f"pushd .claude && echo '{HOOKS_JSON}' > settings.local.json && popd"), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_set_location_into_claude_dir_then_bare_filename_gated():
    """`Set-Content` (PowerShell) is on none of self-protect's write-verb
    patterns (redirect/sed/cp/mv/rm-shaped), so this one reaches this
    guard's own cd-fallback path, unlike the `>`/`mv`-based cases above."""
    d = evaluate(_shell(
        'Set-Location .claude; Set-Content settings.local.json '
        '\'{"hooks": {"PreToolUse": []}}\''), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_shell_push_location_into_claude_dir_then_bare_filename_gated():
    """QA finding (independent adversarial review, round A): a CONFIRMED,
    reproduced bypass — `CLAUDE_SETTINGS_CD_RE`'s alias list (copied from
    `VSCODE_CD_RE`) was missing PowerShell's `Push-Location`, as common an
    alias as `Set-Location`. Neither self-protect (no recognized write-verb
    on a jq/sponge pipeline) nor this guard's own list caught it before the
    fix."""
    d = evaluate(_shell(
        'Push-Location .claude; jq \'.hooks = {"PreToolUse": []}\' '
        'settings.local.json | sponge settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "claude-hooks-protect"


def test_shell_cd_elsewhere_then_bare_filename_not_gated():
    assert not _gated(evaluate(_shell(
        'cd /tmp && echo "see settings.local.json for hook config"'), EMPTY))


def test_shell_cd_into_lookalike_dir_not_gated():
    for cmd in (
        'cd .claude-old && jq \'.hooks={}\' settings.local.json | sponge settings.local.json',
        'cd .claude.bak && jq \'.hooks={}\' settings.local.json | sponge settings.local.json',
    ):
        assert not _gated(evaluate(_shell(cmd), EMPTY)), cmd


def test_shell_write_without_write_verb_not_gated():
    """Merely naming the path and the key, with no write-verb and no jq
    assignment shape (e.g. reading it), must not be gated."""
    assert not _gated(evaluate(_shell('cat .claude/settings.local.json'), EMPTY))


def test_shell_jq_sponge_to_unrelated_key_not_gated():
    """A write-verb-less jq/sponge mutation targeting the file, but touching
    an unrelated key (no `hooks` key present), must not be gated — this
    guard's own content gate, exercised on the one shell shape self-protect
    doesn't already intercept regardless of content (see the module-level
    note above the shell-forms section)."""
    d = evaluate(_shell(
        'jq \'.model = "opus"\' .claude/settings.local.json '
        '| sponge .claude/settings.local.json'), EMPTY)
    assert not _gated(d)


def test_shell_redirect_to_unrelated_file_not_gated():
    assert not _gated(evaluate(_shell(f"echo '{HOOKS_JSON}' > output.txt"), EMPTY))


# ---- benign cases: must NOT gate -------------------------------------------------

def test_benign_local_settings_edit_not_gated():
    """Ordinary personal-settings tweaks (permissions/env/model/statusLine)
    carry no `hooks` key and are routine, sanctioned local customization."""
    d = evaluate(_write(".claude/settings.local.json",
                         '{"model": "opus", "env": {"FOO": "bar"}}'), EMPTY)
    assert not _gated(d)


def test_project_settings_json_not_gated_by_this_guard():
    """`.claude/settings.json` (not `.local.json`) is a DIFFERENT file,
    already fully blocked outright by self-protect — this content-gated
    guard's own path check must not also fire on it (it targets the
    settings.local.json path specifically)."""
    d = evaluate(_write(".claude/settings.json", HOOKS_JSON), EMPTY)
    assert d.rule != "claude-hooks-protect"


def test_unrelated_file_mentioning_hooks_not_gated():
    assert not _gated(evaluate(
        _write("README.md", 'Add a "hooks" entry to enable custom hooks...'), EMPTY))


def test_reading_settings_local_json_not_gated():
    read_ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Read",
                          args={"file_path": ".claude/settings.local.json"})
    assert not _gated(evaluate(read_ev, EMPTY))


def test_unrelated_path_named_settings_local_json_not_gated():
    assert not _gated(evaluate(
        _write("config/settings.local.json", HOOKS_JSON), EMPTY))


def test_settings_local_json_backup_file_not_gated():
    assert not _gated(evaluate(
        _write(".claude/settings.local.json.bak", HOOKS_JSON), EMPTY))


# ---- escape hatches: human-only --------------------------------------------------
# Exercised via the jq/sponge shell shape (see the shell-forms section note):
# it's the one shell form this guard reaches without self-protect's own,
# non-escapable check preempting it first — a redirect/mv/sed-i form would
# test self-protect's escape semantics (it has none), not this guard's own.

_JQ_SPONGE_CMD = ('jq \'.hooks = {"PreToolUse": []}\' .claude/settings.local.json '
                   '| sponge .claude/settings.local.json')


def test_human_can_override_shell_with_comment():
    assert not _gated(evaluate(_shell(_JQ_SPONGE_CMD + " # aegis-allow"), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(_shell(_JQ_SPONGE_CMD + " # aegis-allow"), EMPTY))


def test_env_toggle_allows_edit_write_and_shell(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CLAUDE_HOOKS", "1")
    assert not _gated(evaluate(_write(".claude/settings.local.json"), EMPTY))
    assert not _gated(evaluate(_shell(_JQ_SPONGE_CMD), EMPTY))


def test_policy_allow_regex_skips_gate():
    pol = Policy(claude_hooks={"allow": [r"\.claude/settings\.local\.json"]})
    assert not _gated(evaluate(_write(".claude/settings.local.json"), pol))


# ---- modes: ask (default) / deny / monitor / off ----------------------------------

def test_default_mode_is_ask():
    d = evaluate(_write(".claude/settings.local.json"), EMPTY)
    assert d.action == Action.ASK and d.rule == "claude-hooks-protect"
    d2 = evaluate(_shell(_JQ_SPONGE_CMD), EMPTY)
    assert d2.action == Action.ASK and d2.rule == "claude-hooks-protect"


def test_deny_mode_hard_blocks():
    d = evaluate(_write(".claude/settings.local.json"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == "claude-hooks-protect"


def test_monitor_mode_logs_and_allows():
    pol = Policy(claude_hooks={"mode": "monitor"})
    assert not _gated(evaluate(_write(".claude/settings.local.json"), pol))


def test_off_mode_disables_guard():
    pol = Policy(claude_hooks={"mode": "off"})
    assert not _gated(evaluate(_write(".claude/settings.local.json"), pol))


# ---- perf / ReDoS ------------------------------------------------------------------

def test_perf_no_redos_on_adversarial_shell_input():
    adversarial = ("jq " + "a" * 5000 + " .claude/settings.local.json | sponge "
                    ".claude/settings.local.json " + "b" * 5000)
    start = time.time()
    evaluate(_shell(adversarial), EMPTY)
    assert time.time() - start < 1.0


def test_perf_no_redos_on_long_path_content():
    long_content = '"x": "' + ("y" * 20000) + '", "hooks": {"PreToolUse": []}'
    start = time.time()
    d = evaluate(_write(".claude/settings.local.json", long_content), EMPTY)
    assert time.time() - start < 1.0
    assert _gated(d)


# ---- direct pattern sanity ---------------------------------------------------------

def test_path_regex_matches_expected_forms():
    for p in (".claude/settings.local.json", ".claude\\settings.local.json",
              "a/b/.claude/settings.local.json", "/home/dev/.claude/settings.local.json"):
        assert patterns.CLAUDE_LOCAL_SETTINGS_PATH_RE.search(p), p


def test_path_regex_does_not_match_settings_json():
    assert not patterns.CLAUDE_LOCAL_SETTINGS_PATH_RE.search(".claude/settings.json")
