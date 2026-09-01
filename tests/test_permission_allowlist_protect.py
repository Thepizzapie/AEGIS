"""Claude Code permission-allowlist self-escalation guard — blocks planting an
unrestricted Bash grant (bare ``"Bash"`` or wildcard ``"Bash(*)"``) into
``permissions.allow`` in ``.claude/settings.local.json``, and the equivalent,
file-free ``claude --allowedTools``/``--allowed-tools`` CLI invocation.

Unlike `permission_bypass`'s ``defaultMode: "bypassPermissions"``, this never
touches `defaultMode` at all — it reaches the identical practical outcome
(every future Bash call silently pre-approved) through a narrower, easier-to-
miss-in-review substitute that `rule_permission_bypass_protect`'s own test
suite (``test_additional_directories_not_gated``) explicitly leaves ungated.
"""
import time

from aegis import patterns
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                                    # default mode: ask
DENY = Policy(permission_allowlist={"mode": "deny"})                # stricter, hard-block posture

BASH_ALLOW_JSON = '{"permissions": {"allow": ["Read(src/**)", "Bash"]}}'
BASH_WILDCARD_JSON = '{"permissions": {"allow": ["Bash(*)"]}}'


def _edit(path, new_string=BASH_ALLOW_JSON):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                       args={"file_path": path, "new_string": new_string})


def _write(path, content=BASH_ALLOW_JSON):
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


# ---- Edit/Write -----------------------------------------------------------------

def test_bare_bash_allow_via_write_gated():
    d = evaluate(_write(".claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_bare_bash_allow_via_edit_gated():
    d = evaluate(_edit(".claude/settings.local.json",
                        '"permissions": {"allow": ["Bash"]}'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_bash_wildcard_allow_gated():
    d = evaluate(_write(".claude/settings.local.json", BASH_WILDCARD_JSON), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_bash_wildcard_with_internal_whitespace_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '{"permissions": {"allow": ["Bash( * )"]}}'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_windows_path_separator_gated():
    d = evaluate(_write(".claude\\settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_single_quoted_form_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         "'allow': ['Bash']"), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_scoped_bash_grant_not_gated():
    """The everyday-safe shape this guard is deliberately narrower than a
    bare-key gate: a command-prefix-scoped Bash grant is legitimate, routine
    settings.local.json content — the identical benign case
    `test_permission_bypass_protect.py::test_additional_directories_not_gated`
    already pins as ungated for the sibling guard."""
    for entry in ('"Bash(npm run build:*)"', '"Bash(git diff:*)"', '"Bash(git *)"'):
        d = evaluate(_write(".claude/settings.local.json",
                             '{"permissions": {"allow": [' + entry + ']}}'), EMPTY)
        assert not _gated(d), entry


def test_bash_as_substring_of_unrelated_scoped_grant_not_gated():
    """QA finding (independent adversarial review, bypass-hunting round,
    confirmed reproduced): an earlier draft anchored the unscoped-Bash
    pattern on a plain `\\b` word boundary, which matched "Bash" as a whole
    WORD embedded inside an unrelated, legitimately-scoped grant string —
    none of these grant the Bash tool at all, and all three false-positived
    (wrongly asked) before the fix anchored the match to a real value
    boundary (quote/comma/`=`/whitespace) instead."""
    for entry in (
        '"Read(Bash-scripts/**)"',
        '"Edit(src/Bash.Utils/**)"',
        '"WebFetch(domain:Bash.example.com)"',
    ):
        d = evaluate(_write(".claude/settings.local.json",
                             '{"permissions": {"allow": [' + entry + ']}}'), EMPTY)
        assert not _gated(d), entry


def test_bash_as_substring_via_jq_not_gated():
    d = evaluate(_shell(
        'jq \'.permissions.allow += ["Read(Bash-scripts/**)"]\' '
        '.claude/settings.local.json | sponge .claude/settings.local.json'), EMPTY)
    assert not _gated(d)


def test_cli_allowed_tools_bash_substring_of_scoped_tool_not_gated():
    d = evaluate(_shell('claude --allowedTools "Read(Bash-scripts/**)" -p "go"'), EMPTY)
    assert not _gated(d)


def test_other_tools_scoped_or_unscoped_not_gated():
    """Deliberately Bash-only: an unrestricted grant for a different tool is
    a disclosed, out-of-scope gap, not something this guard claims to catch."""
    for entry in ('"Read"', '"Write"', '"WebFetch"', '"Edit(**)"'):
        d = evaluate(_write(".claude/settings.local.json",
                             '{"permissions": {"allow": [' + entry + ']}}'), EMPTY)
        assert not _gated(d), entry


def test_lowercase_bash_not_gated():
    """Case-sensitive by design: a lowercase `"bash"` string does not grant
    the real `Bash` tool at all in Claude Code's own tool matching, so it
    carries no real capability to catch."""
    d = evaluate(_write(".claude/settings.local.json",
                         '{"permissions": {"allow": ["bash"]}}'), EMPTY)
    assert not _gated(d)


def test_bash_in_deny_array_not_gated():
    """An unrestricted Bash entry under `deny`/`ask` is the SAFE direction —
    narrowing what runs unattended, not widening it — and must never gate."""
    d = evaluate(_write(".claude/settings.local.json",
                         '{"permissions": {"deny": ["Bash"], "ask": ["Bash(*)"]}}'),
                 EMPTY)
    assert not _gated(d)


def test_bare_allow_key_alone_not_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '"allow"'), EMPTY)
    assert not _gated(d)


def test_bare_bash_string_alone_no_allow_key_not_gated():
    """`"Bash"` alone (no `allow` key anywhere) must not false-positive —
    e.g. an unrelated string value elsewhere in the file."""
    d = evaluate(_write(".claude/settings.local.json",
                         '{"note": "the Bash tool is powerful"}'), EMPTY)
    assert d.rule != "permission-allowlist-protect"


def test_additional_directories_and_other_permissions_keys_not_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '{"permissions": {"additionalDirectories": ["../docs"], '
                         '"defaultMode": "acceptEdits"}}'), EMPTY)
    assert not _gated(d)


def test_unicode_escaped_allow_key_gated():
    """QA finding (independent adversarial review, design/consistency
    round): a partial Edit fragment (not valid standalone JSON) spelling
    `allow` with a JSON `\\uXXXX` escape defeated every detection layer at
    once before `_permission_allowlist_normalize` existed — the textual
    regex never decoded it, and `json.loads()` raised on the non-standalone
    fragment so the structural walk never ran either. A confirmed,
    reproduced full bypass (silent ALLOW, no rule firing), closed by
    porting `_permission_bypass_normalize` over unchanged."""
    d = evaluate(_edit(".claude/settings.local.json",
                        '"\\u0061llow": ["Bash"]'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_unicode_escaped_allow_key_via_write_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '"\\u0061llow": ["Bash"]'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_unicode_escaped_bash_value_gated():
    d = evaluate(_edit(".claude/settings.local.json",
                        '"allow": ["\\u0042ash"]'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_unicode_escaped_key_via_mcp_edit_nested_gated():
    d = evaluate(_mcp_edit_nested(".claude/settings.local.json", "{}",
                                   '"\\u0061llow": ["Bash"]'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_unicode_escaped_shell_jq_sponge_gated():
    d = evaluate(_shell(
        'jq \'."\\u0061llow" += ["Bash"]\' .claude/settings.local.json '
        '| sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_nested_project_path_gated():
    d = evaluate(_write("packages/foo/.claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_user_scope_path_gated():
    d = evaluate(_write("/home/dev/.claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


# ---- MCP-tool writes --------------------------------------------------------------

def test_mcp_write_gated():
    d = evaluate(_mcp_write(".claude/settings.local.json", BASH_ALLOW_JSON), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_mcp_edit_file_nested_edits_shape_gated():
    d = evaluate(_mcp_edit_nested(".claude/settings.local.json", "{}",
                                   '"allow": ["Bash(*)"]'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_mcp_flat_key_value_arg_shape_gated():
    d = evaluate(_mcp_key_value(".claude/settings.local.json", "allow", "Bash"), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_mcp_dotted_key_set_config_shape_gated():
    d = evaluate(_mcp_key_value(".claude/settings.local.json", "permissions.allow",
                                 "Bash(*)"), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_mcp_nested_json_dict_key_shape_gated():
    d = evaluate(_mcp_nested_json(".claude/settings.local.json",
                                   {"permissions": {"allow": ["Bash"]}}), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_mcp_nested_json_scoped_grant_not_gated():
    d = evaluate(_mcp_nested_json(".claude/settings.local.json",
                                   {"permissions": {"allow": ["Bash(npm test:*)"]}}), EMPTY)
    assert not _gated(d)


def test_mcp_struct_depth_capped():
    nested = {"permissions": {"allow": ["Bash"]}}
    for _ in range(8):
        nested = {"wrapper": nested}
    d = evaluate(_mcp_nested_json(".claude/settings.local.json", nested), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_mcp_decoy_literal_content_does_not_suppress_struct_fallback():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_json",
                     action=ActionClass.MCP,
                     args={"path": ".claude/settings.local.json",
                           "content": '{"model": "opus"}',
                           "json": {"permissions": {"allow": ["Bash(*)"]}}})
    d = evaluate(ev, EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


# ---- shell forms: file-write -------------------------------------------------------
# Same self-protect-precedence interaction `test_permission_bypass_protect.py`
# documents: self-protect's own shell branch (write-verb + `.claude` mention,
# non-escapable) preempts this guard for any redirect/sed-i/heredoc/mv form.
# This guard's own real coverage is the write-verb-less jq/sponge shape
# self-protect never sees.

def test_shell_redirect_already_blocked_by_self_protect():
    d = evaluate(_shell(f"echo '{BASH_ALLOW_JSON}' > .claude/settings.local.json"), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_jq_sponge_assign_gated():
    d = evaluate(_shell(
        'jq \'.permissions.allow += ["Bash"]\' '
        '.claude/settings.local.json | sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_shell_jq_wildcard_assign_gated():
    d = evaluate(_shell(
        'jq \'.permissions.allow = ["Bash(*)"]\' .claude/settings.local.json '
        '| sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_jq_scoped_grant_not_gated():
    d = evaluate(_shell(
        'jq \'.permissions.allow += ["Bash(git diff:*)"]\' .claude/settings.local.json '
        '| sponge .claude/settings.local.json'), EMPTY)
    assert not _gated(d)


def test_jq_plain_read_not_gated():
    assert not _gated(evaluate(
        _shell("jq '.permissions.allow' .claude/settings.local.json"), EMPTY))


def test_shell_sponge_without_jq_gated():
    d = evaluate(_shell(
        f"echo '{BASH_ALLOW_JSON}' | sponge .claude/settings.local.json"), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_shell_whitespace_padding_does_not_defeat_window_gated():
    padded = ('jq \'.permissions.allow +=' + (" " * 500)
              + '["Bash"]\' .claude/settings.local.json '
                '| sponge .claude/settings.local.json')
    d = evaluate(_shell(padded), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_shell_jq_update_assign_operator_gated():
    d = evaluate(_shell(
        'jq \'.permissions.allow |= . + ["Bash"]\' .claude/settings.local.json '
        '| sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_shell_jq_bracket_index_notation_gated():
    d = evaluate(_shell(
        'jq \'.["permissions"]["allow"] += ["Bash"]\' '
        '.claude/settings.local.json | sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_jq_equality_comparison_not_gated():
    d = evaluate(_shell(
        'jq \'select(.permissions.allow == ["Bash"])\' '
        '.claude/settings.local.json'), EMPTY)
    assert not _gated(d)


def test_shell_jq_multiline_program_gated():
    cmd = ('jq \'.permissions.allow +=\n  ["Bash"]\' '
           '.claude/settings.local.json | sponge .claude/settings.local.json')
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_shell_jq_ampersand_in_quoted_value_gated():
    cmd = ('jq \'.permissions.allow = ["Read(a&b)", "Bash"]\' '
           '.claude/settings.local.json | sponge .claude/settings.local.json')
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_shell_jq_string_literal_padding_over_400_chars_still_gated():
    """The identical bypass shape using a jq no-op string-literal binding
    (`"..." as $unused |`) instead of a `#`-comment — confirms the unbounded
    `;`-scoped window is a real fix, not merely a comment-stripping patch
    that would leave this equally-valid filler shape open."""
    filler = '"' + ("a" * 380) + '" as $unused | '
    cmd = ("jq '" + filler + '.permissions.allow += ["Bash"]'
           + "' .claude/settings.local.json | sponge .claude/settings.local.json")
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_shell_jq_genuinely_unrelated_far_mention_in_same_statement_asks():
    """Accepted trade-off of the unbounded window, matching `PERMISSION_
    BYPASS_JQ_RE`'s own documented trade-off: a legitimate `jq` edit against
    `.claude/settings.local.json` (no dangerous assignment of its own)
    followed, in the SAME `;`-free compound command, by an unrelated mention
    of both signal words now asks unnecessarily — a narrow false positive,
    not a missed real plant."""
    cmd = ('jq \'.foo = 1\' .claude/settings.local.json && '
           'echo "totally unrelated: allow Bash"')
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_shell_jq_unrelated_mention_past_semicolon_boundary_not_gated():
    """The window still stops at a real `;` statement boundary."""
    cmd = ('jq \'.foo = 1\' .claude/settings.local.json ; '
           'echo "totally unrelated: allow Bash"')
    d = evaluate(_shell(cmd), EMPTY)
    assert not _gated(d)


def test_perf_no_redos_on_jq_comment_padding_near_normalize_cap():
    """The unbounded jq lookaheads must stay linear-time even against filler
    sized right up against `normalize.scan_surface`'s own shared 20,000-char
    truncation cap."""
    filler = "#" + ("a" * 19000) + "\n"
    cmd = ("jq '" + filler + '.permissions.allow += ["Bash"]'
           + "' .claude/settings.local.json | sponge .claude/settings.local.json")
    start = time.time()
    d = evaluate(_shell(cmd), EMPTY)
    assert time.time() - start < 1.0
    assert _gated(d)


def test_shell_jq_comment_padding_over_400_chars_still_gated():
    """The same fixed-window bypass class `PERMISSION_BYPASS_JQ_RE` was found
    vulnerable to (a jq `#`-comment as non-whitespace filler) — this guard's
    jq pattern uses the same unbounded, `;`-scoped design from the start."""
    filler = "#" + ("a" * 380) + "\n"
    cmd = ("cat .claude/settings.local.json | jq '" + filler
           + '.permissions.allow += ["Bash"]'
           + "' | sponge .claude/settings.local.json")
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_shell_gojq_drop_in_gated():
    d = evaluate(_shell(
        'gojq \'.permissions.allow += ["Bash"]\' '
        '.claude/settings.local.json | sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_shell_jaq_drop_in_gated():
    d = evaluate(_shell(
        'jaq \'.permissions.allow += ["Bash"]\' '
        '.claude/settings.local.json | sponge .claude/settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_shell_cd_into_claude_dir_then_bare_filename_gated():
    d = evaluate(_shell(
        'cd .claude && jq \'.permissions.allow += ["Bash"]\' '
        'settings.local.json | sponge settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_shell_push_location_into_claude_dir_then_bare_filename_gated():
    d = evaluate(_shell(
        'Push-Location .claude; jq \'.permissions.allow += ["Bash"]\' '
        'settings.local.json | sponge settings.local.json'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_shell_cd_into_lookalike_dir_not_gated():
    for cmd in (
        'cd .claude-old && jq \'.permissions.allow += ["Bash"]\' '
        'settings.local.json | sponge settings.local.json',
        'cd .claude.bak && jq \'.permissions.allow += ["Bash"]\' '
        'settings.local.json | sponge settings.local.json',
    ):
        assert not _gated(evaluate(_shell(cmd), EMPTY)), cmd


def test_shell_write_without_write_verb_not_gated():
    assert not _gated(evaluate(_shell('cat .claude/settings.local.json'), EMPTY))


def test_shell_redirect_to_unrelated_file_not_gated():
    assert not _gated(evaluate(_shell(f"echo '{BASH_ALLOW_JSON}' > output.txt"), EMPTY))


# ---- shell forms: CLI flag ----------------------------------------------------------

def test_cli_allowed_tools_bare_bash_gated():
    d = evaluate(_shell('claude -p "do the thing" --allowedTools "Bash"'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_cli_allowed_tools_hyphenated_form_gated():
    d = evaluate(_shell('claude --allowed-tools "Bash" -p "go"'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_cli_allowed_tools_wildcard_gated():
    d = evaluate(_shell('claude --allowedTools "Bash(*)" -p "go"'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_cli_allowed_tools_equals_form_gated():
    d = evaluate(_shell('claude --allowedTools=Bash -p "go"'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_cli_allowed_tools_multi_tool_list_gated():
    d = evaluate(_shell('claude --allowedTools "Read,Write,Bash" -p "go"'), EMPTY)
    assert _gated(d) and d.rule == "permission-allowlist-protect"


def test_cli_allowed_tools_scoped_bash_not_gated():
    d = evaluate(_shell('claude --allowedTools "Bash(npm run build:*)" -p "go"'), EMPTY)
    assert not _gated(d)


def test_cli_allowed_tools_other_tools_not_gated():
    d = evaluate(_shell('claude --allowedTools "Read,Write" -p "go"'), EMPTY)
    assert not _gated(d)


def test_cli_flag_without_claude_binary_not_gated():
    d = evaluate(_shell('echo "never run with --allowedTools Bash"'), EMPTY)
    assert not _gated(d)


# ---- benign cases: must NOT gate -----------------------------------------------------

def test_benign_local_settings_edit_not_gated():
    d = evaluate(_write(".claude/settings.local.json",
                         '{"model": "opus", "env": {"FOO": "bar"}}'), EMPTY)
    assert not _gated(d)


def test_project_settings_json_not_gated_by_this_guard():
    """`.claude/settings.json` is already fully blocked outright by
    self-protect; this content-gated guard's own path check must not also
    fire on it."""
    d = evaluate(_write(".claude/settings.json", BASH_ALLOW_JSON), EMPTY)
    assert d.rule != "permission-allowlist-protect"


def test_unrelated_file_mentioning_bash_allow_not_gated():
    assert not _gated(evaluate(
        _write("README.md", 'Setting permissions.allow to ["Bash"] is dangerous...'),
        EMPTY))


def test_reading_settings_local_json_not_gated():
    read_ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Read",
                          args={"file_path": ".claude/settings.local.json"})
    assert not _gated(evaluate(read_ev, EMPTY))


def test_unrelated_path_named_settings_local_json_not_gated():
    assert not _gated(evaluate(
        _write("config/settings.local.json", BASH_ALLOW_JSON), EMPTY))


def test_settings_local_json_backup_file_not_gated():
    assert not _gated(evaluate(
        _write(".claude/settings.local.json.bak", BASH_ALLOW_JSON), EMPTY))


# ---- escape hatches: human-only --------------------------------------------------

_JQ_SPONGE_CMD = ('jq \'.permissions.allow += ["Bash"]\' '
                   '.claude/settings.local.json | sponge .claude/settings.local.json')
_CLI_CMD = 'claude --allowedTools "Bash" -p "go"'


def test_human_can_override_shell_jq_with_comment():
    assert not _gated(evaluate(_shell(_JQ_SPONGE_CMD + " # aegis-allow"), EMPTY))


def test_human_can_override_cli_form_with_comment():
    assert not _gated(evaluate(_shell(_CLI_CMD + " # aegis-allow"), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(_shell(_JQ_SPONGE_CMD + " # aegis-allow"), EMPTY))
    assert _gated(evaluate(_shell(_CLI_CMD + " # aegis-allow"), EMPTY))


def test_env_toggle_allows_edit_write_shell_and_cli(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_PERMISSION_ALLOWLIST", "1")
    assert not _gated(evaluate(_write(".claude/settings.local.json"), EMPTY))
    assert not _gated(evaluate(_shell(_JQ_SPONGE_CMD), EMPTY))
    assert not _gated(evaluate(_shell(_CLI_CMD), EMPTY))


def test_policy_allow_regex_skips_gate():
    pol = Policy(permission_allowlist={"allow": [r"\.claude/settings\.local\.json"]})
    assert not _gated(evaluate(_write(".claude/settings.local.json"), pol))


def test_policy_allow_regex_skips_cli_gate():
    pol = Policy(permission_allowlist={"allow": [r"--allowedTools"]})
    assert not _gated(evaluate(_shell(_CLI_CMD), pol))


# ---- modes: ask (default) / deny / monitor / off ----------------------------------

def test_default_mode_is_ask():
    d = evaluate(_write(".claude/settings.local.json"), EMPTY)
    assert d.action == Action.ASK and d.rule == "permission-allowlist-protect"
    d2 = evaluate(_shell(_JQ_SPONGE_CMD), EMPTY)
    assert d2.action == Action.ASK and d2.rule == "permission-allowlist-protect"
    d3 = evaluate(_shell(_CLI_CMD), EMPTY)
    assert d3.action == Action.ASK and d3.rule == "permission-allowlist-protect"


def test_deny_mode_hard_blocks():
    d = evaluate(_write(".claude/settings.local.json"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == "permission-allowlist-protect"
    d2 = evaluate(_shell(_CLI_CMD), DENY)
    assert d2.blocked and d2.action == Action.DENY and d2.rule == "permission-allowlist-protect"


def test_monitor_mode_logs_and_allows():
    pol = Policy(permission_allowlist={"mode": "monitor"})
    assert not _gated(evaluate(_write(".claude/settings.local.json"), pol))
    assert not _gated(evaluate(_shell(_CLI_CMD), pol))


def test_off_mode_disables_guard():
    pol = Policy(permission_allowlist={"mode": "off"})
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
    adversarial = "claude " + ("x" * 5000) + " --allowedTools Bash"
    start = time.time()
    d = evaluate(_shell(adversarial), EMPTY)
    assert time.time() - start < 1.0
    assert _gated(d)


def test_perf_no_redos_on_long_allow_array_content():
    long_array = ", ".join(f'"Bash(cmd{i}:*)"' for i in range(50))
    content = '{"permissions": {"allow": [' + long_array + ', "Bash"]}}'
    start = time.time()
    d = evaluate(_write(".claude/settings.local.json", content), EMPTY)
    assert time.time() - start < 1.0
    assert _gated(d)


def test_perf_no_redos_on_adversarial_key_content():
    adversarial = '"permissions": {' + ('x' * 20000) + '}'
    start = time.time()
    evaluate(_write(".claude/settings.local.json", adversarial), EMPTY)
    assert time.time() - start < 1.0


# ---- direct pattern sanity ---------------------------------------------------------

def test_allow_array_regex_matches_expected_forms():
    for content in (
        '"allow": ["Bash"]',
        "'allow': ['Bash']",
        '"allow": ["Read(**)", "Bash(*)"]',
    ):
        assert patterns.PERMISSION_ALLOWLIST_ALLOW_ARRAY_RE.search(content), content


def test_allow_array_regex_does_not_match_scoped_grant():
    assert not patterns.PERMISSION_ALLOWLIST_ALLOW_ARRAY_RE.search(
        '"allow": ["Bash(git diff:*)"]')


def test_allow_array_regex_does_not_cross_array_boundary():
    assert not patterns.PERMISSION_ALLOWLIST_ALLOW_ARRAY_RE.search(
        '"allow": ["Read(**)"], "deny": ["Bash"]')


def test_cli_regex_matches_expected_forms():
    for cmd in (
        'claude --allowedTools Bash',
        'claude --allowedTools "Bash(*)"',
        'claude --allowed-tools Bash',
    ):
        assert patterns.PERMISSION_ALLOWLIST_CLI_RE.search(cmd), cmd


def test_cli_regex_does_not_match_scoped_grant():
    assert not patterns.PERMISSION_ALLOWLIST_CLI_RE.search(
        'claude --allowedTools "Bash(git diff:*)"')
