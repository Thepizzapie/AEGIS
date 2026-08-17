"""Claude Code permission-escalation protection guard — blocks self-granting
a permission-prompt bypass in ``.claude/settings.local.json`` (the same
project-local, gitignored-by-default sibling file `rule_claude_hooks_
protect` already reaches for its ``hooks`` key, extended here to that
file's second self-escalation surface, ``permissions``), and the
file-write-free CLI-flag equivalent.

``permissions.defaultMode: "bypassPermissions"`` is the settings-file
equivalent of launching with ``--dangerously-skip-permissions``: it removes
Claude Code's own approval prompt for future tool calls, silently, with no
diff and no code review. An unscoped ``permissions.allow`` entry (bare
``"Bash"``, ``"Bash(*)"``, the universal ``"*"``) does the same for one
tool. Aegis's own hooks are unaffected by either change — what's lost is
the human checkpoint standing in front of everything this file's OTHER
guards don't already deny/ask on.
"""
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                                   # default mode: ask
DENY = Policy(claude_permissions={"mode": "deny"})                 # stricter, hard-block posture

BYPASS_MODE_JSON = '"permissions": {"defaultMode": "bypassPermissions"}'
BROAD_ALLOW_JSON = '"permissions": {"allow": ["Bash"]}'


def _edit(path, new_string=BYPASS_MODE_JSON):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                       args={"file_path": path, "new_string": new_string})


def _write(path, content=BYPASS_MODE_JSON):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write",
                       args={"file_path": path, "content": content})


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp_write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                       action=ActionClass.MCP, args={"path": path, "content": content})


def _mcp_nested_json(path, obj):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_json",
                       action=ActionClass.MCP, args={"path": path, "json": obj})


def _gated(d) -> bool:
    return d.action != Action.ALLOW


# ---- Edit/Write: defaultMode bypass ---------------------------------------------

def test_bypass_mode_via_write_gated():
    d = evaluate(_write(".claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_bypass_mode_via_edit_gated():
    d = evaluate(_edit(".claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_single_quoted_bypass_mode_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         "'permissions': {'defaultMode': 'bypassPermissions'}"), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_windows_path_separator_gated():
    assert _gated(evaluate(_write(".claude\\settings.local.json"), EMPTY))


def test_nested_project_path_gated():
    d = evaluate(_write("packages/foo/.claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_user_scope_path_gated():
    d = evaluate(_write("/home/dev/.claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_safer_default_mode_value_not_gated():
    """`defaultMode` values that only NARROW or bound what's auto-approved
    ("plan" is read-only, "dontAsk" auto-denies unless pre-approved) carry
    none of `"bypassPermissions"`'s risk and must not gate."""
    for mode in ("plan", "dontAsk", "default"):
        d = evaluate(_write(".claude/settings.local.json",
                             f'"permissions": {{"defaultMode": "{mode}"}}'), EMPTY)
        assert not _gated(d), mode


# ---- Edit/Write: broad `allow` grant ---------------------------------------------

def test_bare_bash_allow_gated():
    d = evaluate(_write(".claude/settings.local.json", BROAD_ALLOW_JSON), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_bash_wildcard_paren_allow_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '"permissions": {"allow": ["Bash(*)"]}'), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_universal_wildcard_allow_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '"permissions": {"allow": ["*"]}'), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_mcp_wildcard_allow_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '"permissions": {"allow": ["mcp__*"]}'), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_other_broad_tools_gated():
    for tool in ("Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch",
                 "WebSearch", "Task", "KillShell", "BashOutput"):
        d = evaluate(_write(".claude/settings.local.json",
                             f'"allow": ["{tool}"]'), EMPTY)
        assert _gated(d) and d.rule == "claude-permissions-protect", tool


def test_scoped_bash_allow_not_gated():
    """An ordinary SCOPED grant (`"Bash(npm test)"`) is routine, sanctioned
    configuration — the whole reason this guard is content-gated on the
    specific unscoped/wildcard shape rather than the `allow` key alone."""
    d = evaluate(_write(".claude/settings.local.json",
                         '"permissions": {"allow": ["Bash(npm test)"]}'), EMPTY)
    assert not _gated(d)


def test_scoped_edit_glob_allow_not_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '"permissions": {"allow": ["Edit(*.md)"]}'), EMPTY)
    assert not _gated(d)


def test_unlisted_tool_name_not_gated():
    """`_CLAUDE_PERMISSIONS_BROAD_TOOLS` is a curated list, the same
    judgment-call trade-off `rule_path_hijack_protect`'s own curated
    command-name list makes — an unlisted, low-privilege tool name granted
    unscoped is a disclosed, accepted gap, not a false negative to fix
    here."""
    d = evaluate(_write(".claude/settings.local.json",
                         '"permissions": {"allow": ["Glob"]}'), EMPTY)
    assert not _gated(d)


def test_broad_allow_paired_with_safer_deny_not_misattributed():
    """A genuinely SAFER `"deny": ["Bash"]` entry sharing the same edit
    chunk as an unrelated, SCOPED `"allow"` entry must never be
    misattributed to `allow` by a naive window-based co-occurrence check —
    `_claude_permissions_allow_broad_hit` stops scanning at the first
    sibling-key boundary."""
    d = evaluate(_write(".claude/settings.local.json",
                         '"permissions": {"allow": ["Bash(git *)"], "deny": ["Bash"]}'), EMPTY)
    assert not _gated(d)


def test_broad_allow_after_ask_boundary_not_misattributed():
    d = evaluate(_write(".claude/settings.local.json",
                         '"permissions": {"allow": ["Bash(git *)"], "ask": ["Bash"]}'), EMPTY)
    assert not _gated(d)


def test_broad_deny_alone_not_gated():
    """A `deny` list is strictly SAFER (more restrictive) than the default —
    a bare `"Bash"` under `deny`, with no `allow` key at all, must never
    gate."""
    d = evaluate(_write(".claude/settings.local.json",
                         '"permissions": {"deny": ["Bash"]}'), EMPTY)
    assert not _gated(d)


def test_broad_allow_after_closing_bracket_not_misattributed():
    d = evaluate(_write(".claude/settings.local.json",
                         '"permissions": {"allow": ["Bash(git *)"]}, "unrelated": ["Bash"]'), EMPTY)
    assert not _gated(d)


# ---- JSON semantic walk: whole-file content + unicode-escape evasion -------------

def test_unicode_escaped_default_mode_key_gated():
    """The same `\\uXXXX`-escape evasion class `rule_claude_hooks_protect`'s
    own QA history already found and closed for `hooks` applies equally
    here — closed the identical way, by parsing whole-file-valid JSON and
    walking the DECODED structure."""
    import json
    content = json.dumps({"permissions": {"defaultMode": "bypassPermissions"}})
    # sanity: the raw text still contains the literal ASCII spelling here;
    # exercise the actual escape form explicitly below.
    d = evaluate(_write(".claude/settings.local.json", content), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_unicode_escaped_default_mode_key_literal_escape_gated():
    content = ('{"\\u0070ermissions": {"defaultMode": "bypassPermissions"}}')
    d = evaluate(_write(".claude/settings.local.json", content), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_whole_file_json_broad_allow_gated():
    import json
    content = json.dumps({"permissions": {"allow": ["Bash(*)"]}})
    d = evaluate(_write(".claude/settings.local.json", content), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_partial_edit_fragment_not_valid_json_still_uses_textual_check():
    """An ordinary Edit's `new_string` is usually a partial fragment (no
    enclosing braces) that never parses standalone as JSON — the textual
    checks alone still carry this case."""
    d = evaluate(_edit(".claude/settings.local.json", BYPASS_MODE_JSON), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


# ---- MCP-tool writes --------------------------------------------------------------

def test_mcp_write_bypass_mode_gated():
    d = evaluate(_mcp_write(".claude/settings.local.json", BYPASS_MODE_JSON), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_mcp_nested_json_struct_bypass_mode_gated():
    """An MCP tool accepting structured JSON ({"json": {...}}) rather than a
    raw string — the dangerous shape is real Python structure here, never
    textual, so only the structural fallback sees it."""
    d = evaluate(_mcp_nested_json(".claude/settings.local.json",
                                   {"permissions": {"defaultMode": "bypassPermissions"}}), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_mcp_nested_json_struct_broad_allow_gated():
    d = evaluate(_mcp_nested_json(".claude/settings.local.json",
                                   {"permissions": {"allow": ["Bash"]}}), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_mcp_nested_json_struct_scoped_allow_not_gated():
    d = evaluate(_mcp_nested_json(".claude/settings.local.json",
                                   {"permissions": {"allow": ["Bash(npm test)"]}}), EMPTY)
    assert not _gated(d)


def test_mcp_struct_depth_capped():
    nested = {"permissions": {"defaultMode": "bypassPermissions"}}
    for _ in range(8):
        nested = {"wrapper": nested}
    d = evaluate(_mcp_nested_json(".claude/settings.local.json", nested), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


# ---- shell forms --------------------------------------------------------------
#
# Exactly like `rule_claude_hooks_protect`'s own module note: `rule_self_
# protect`'s shell branch already, non-escapably, denies ANY shell command
# that both mentions `.claude` anywhere AND carries a write-verb it
# recognizes — so for the plain redirect/sed/heredoc forms, first-deny-wins
# surfaces `self-protect`, not `claude-permissions-protect`. This guard's
# own non-redundant shell-branch coverage is (1) a scripted `jq`-through-
# `sponge` mutation with no recognized write-verb, and (2) the CLI-flag
# bypass form, which mentions neither `.claude` nor a write-verb at all.

def test_shell_redirect_already_blocked_by_self_protect():
    d = evaluate(_shell(f"echo '{{{BYPASS_MODE_JSON}}}' > .claude/settings.local.json"), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_sed_inplace_already_blocked_by_self_protect():
    d = evaluate(_shell(
        "sed -i 's/.*/{\"defaultMode\": \"bypassPermissions\"}/' "
        ".claude/settings.local.json"), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_jq_sponge_bypass_mode_gated():
    d = evaluate(_shell(
        'jq \'.permissions.defaultMode = "bypassPermissions"\' '
        '.claude/settings.local.json | sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_shell_jq_update_assign_operator_gated():
    d = evaluate(_shell(
        'jq \'.permissions.defaultMode |= "bypassPermissions"\' '
        '.claude/settings.local.json | sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_jq_equality_comparison_not_gated():
    d = evaluate(_shell(
        'jq \'select(.permissions.defaultMode == "bypassPermissions")\' '
        '.claude/settings.local.json'), EMPTY)
    assert not _gated(d)


def test_jq_plain_read_not_gated():
    assert not _gated(evaluate(
        _shell("jq '.permissions' .claude/settings.local.json"), EMPTY))


def test_shell_jq_scripted_allow_broadening_is_disclosed_accepted_gap():
    """Disclosed, accepted gap (see `CLAUDE_PERMISSIONS_JQ_RE`'s own comment
    in patterns.py): unlike `hooks` (no safe value at all), `permissions.
    allow` has plenty of legitimate values, so the jq/scripted-edit path is
    gated ONLY for the unambiguous `defaultMode` -> `bypassPermissions`
    shape, not for an `allow`-array broadening — pinning the accepted gap
    explicitly rather than silently leaving it untested."""
    d = evaluate(_shell(
        'jq \'.permissions.allow += ["Bash"]\' .claude/settings.local.json '
        '| sponge .claude/settings.local.json'), EMPTY)
    assert not _gated(d)


def test_shell_cd_into_claude_dir_then_bare_filename_gated():
    d = evaluate(_shell(
        'cd .claude && jq \'.permissions.defaultMode = "bypassPermissions"\' '
        'settings.local.json | sponge settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_shell_write_without_write_verb_or_jq_not_gated():
    assert not _gated(evaluate(_shell('cat .claude/settings.local.json'), EMPTY))


def test_shell_jq_sponge_to_unrelated_key_not_gated():
    d = evaluate(_shell(
        'jq \'.model = "opus"\' .claude/settings.local.json '
        '| sponge .claude/settings.local.json'), EMPTY)
    assert not _gated(d)


# ---- shell forms: CLI-flag bypass (no file write at all) -------------------------

def test_cli_dangerously_skip_permissions_flag_gated():
    d = evaluate(_shell('claude --dangerously-skip-permissions -p "do X"'), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_cli_permission_mode_bypass_space_form_gated():
    d = evaluate(_shell('claude --permission-mode bypassPermissions -p "do X"'), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_cli_permission_mode_bypass_equals_form_gated():
    d = evaluate(_shell('claude --permission-mode=bypassPermissions -p "do X"'), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_cli_claude_code_alias_gated():
    d = evaluate(_shell('claude-code --dangerously-skip-permissions -p "do X"'), EMPTY)
    assert _gated(d) and d.rule == "claude-permissions-protect"


def test_cli_permission_mode_dont_ask_not_gated():
    """`dontAsk` auto-DENIES unless pre-approved — the opposite risk
    direction from `bypassPermissions` — and must not gate."""
    d = evaluate(_shell('claude --permission-mode dontAsk -p "do X"'), EMPTY)
    assert not _gated(d)


def test_cli_permission_mode_plan_not_gated():
    d = evaluate(_shell('claude --permission-mode plan -p "do X"'), EMPTY)
    assert not _gated(d)


def test_cli_flag_unrelated_binary_not_gated():
    d = evaluate(_shell('some-other-tool --dangerously-skip-permissions'), EMPTY)
    assert not _gated(d)


def test_cli_flag_far_from_claude_mention_not_gated():
    """The 200-char bounded verb-adjacency window (the same shared
    convention `DIRENV_ACTIVATE_RE`/`SERVICE_ACTIVATE_RE` already use) means
    an unrelated `claude` mention far from the flag must not gate."""
    padding = "x" * 250
    d = evaluate(_shell(f'echo "claude {padding} --dangerously-skip-permissions"'), EMPTY)
    assert not _gated(d)


# ---- benign cases: must NOT gate -------------------------------------------------

def test_benign_local_settings_edit_not_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '{"model": "opus", "env": {"FOO": "bar"}}'), EMPTY)
    assert not _gated(d)


def test_ordinary_scoped_permissions_block_not_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '{"permissions": {"allow": ["Bash(npm run build)", '
                         '"Read(.env)"], "additionalDirectories": []}}'), EMPTY)
    assert not _gated(d)


def test_project_settings_json_not_gated_by_this_guard():
    """`.claude/settings.json` (not `.local.json`) is a DIFFERENT file,
    already fully blocked outright by self-protect."""
    d = evaluate(_write(".claude/settings.json", BYPASS_MODE_JSON), EMPTY)
    assert d.rule != "claude-permissions-protect"


def test_unrelated_file_mentioning_bypass_not_gated():
    assert not _gated(evaluate(
        _write("README.md", 'Set defaultMode to bypassPermissions for CI...'), EMPTY))


def test_reading_settings_local_json_not_gated():
    read_ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Read",
                          args={"file_path": ".claude/settings.local.json"})
    assert not _gated(evaluate(read_ev, EMPTY))


def test_unrelated_path_named_settings_local_json_not_gated():
    assert not _gated(evaluate(
        _write("config/settings.local.json", BYPASS_MODE_JSON), EMPTY))


def test_settings_local_json_backup_file_not_gated():
    assert not _gated(evaluate(
        _write(".claude/settings.local.json.bak", BYPASS_MODE_JSON), EMPTY))


# ---- escape hatches: human-only --------------------------------------------------

_JQ_SPONGE_CMD = ('jq \'.permissions.defaultMode = "bypassPermissions"\' '
                   '.claude/settings.local.json | sponge .claude/settings.local.json')
_CLI_BYPASS_CMD = 'claude --dangerously-skip-permissions -p "do X"'


def test_human_can_override_shell_jq_with_comment():
    assert not _gated(evaluate(_shell(_JQ_SPONGE_CMD + " # aegis-allow"), EMPTY))


def test_human_can_override_cli_bypass_with_comment():
    assert not _gated(evaluate(_shell(_CLI_BYPASS_CMD + " # aegis-allow"), EMPTY))


def test_agent_cannot_override_shell_jq_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(_shell(_JQ_SPONGE_CMD + " # aegis-allow"), EMPTY))


def test_agent_cannot_override_cli_bypass_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(_shell(_CLI_BYPASS_CMD + " # aegis-allow"), EMPTY))


def test_env_toggle_allows_edit_write_and_shell(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CLAUDE_PERMISSIONS", "1")
    assert not _gated(evaluate(_write(".claude/settings.local.json"), EMPTY))
    assert not _gated(evaluate(_shell(_JQ_SPONGE_CMD), EMPTY))
    assert not _gated(evaluate(_shell(_CLI_BYPASS_CMD), EMPTY))


def test_policy_allow_regex_skips_gate():
    pol = Policy(claude_permissions={"allow": [r"\.claude/settings\.local\.json"]})
    assert not _gated(evaluate(_write(".claude/settings.local.json"), pol))


def test_policy_allow_regex_skips_cli_bypass_gate():
    pol = Policy(claude_permissions={"allow": [r"--dangerously-skip-permissions"]})
    assert not _gated(evaluate(_shell(_CLI_BYPASS_CMD), pol))


# ---- modes: ask (default) / deny / monitor / off ----------------------------------

def test_default_mode_is_ask():
    d = evaluate(_write(".claude/settings.local.json"), EMPTY)
    assert d.action == Action.ASK and d.rule == "claude-permissions-protect"
    d2 = evaluate(_shell(_JQ_SPONGE_CMD), EMPTY)
    assert d2.action == Action.ASK and d2.rule == "claude-permissions-protect"
    d3 = evaluate(_shell(_CLI_BYPASS_CMD), EMPTY)
    assert d3.action == Action.ASK and d3.rule == "claude-permissions-protect"


def test_deny_mode_hard_blocks():
    d = evaluate(_write(".claude/settings.local.json"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == "claude-permissions-protect"


def test_monitor_mode_logs_and_allows():
    pol = Policy(claude_permissions={"mode": "monitor"})
    assert not _gated(evaluate(_write(".claude/settings.local.json"), pol))
    assert not _gated(evaluate(_shell(_CLI_BYPASS_CMD), pol))


def test_off_mode_disables_guard_entirely():
    pol = Policy(claude_permissions={"mode": "off"})
    assert not _gated(evaluate(_write(".claude/settings.local.json"), pol))
    assert not _gated(evaluate(_shell(_CLI_BYPASS_CMD), pol))
