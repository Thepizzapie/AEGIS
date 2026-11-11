"""Claude Code project-MCP auto-approval protection guard -- blocks
pre-approving project-scoped MCP servers (``enableAllProjectMcpServers``
set to anything but false/null, ``enabledMcpjsonServers`` set to anything
but []/null) in ``.claude/settings.local.json``, and the ``claude config
set|add`` / inline ``claude --settings`` CLI forms.

Either setting answers Claude Code's own one-time "approve this project's
MCP servers?" prompt in advance, so every matching stdio server in a
committed ``.mcp.json`` is spawned as a command at the next session start.
"""
import time

from aegis import patterns, rules
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.loader import load_policy
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(claude_mcp_autoapprove={"mode": "deny"})
RULE = "claude-mcp-autoapprove-protect"
LOCAL = ".claude/settings.local.json"
ENABLE_ALL = '{"enableAllProjectMcpServers": true}'


def _edit(path, new_string, old_string=""):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                      args={"file_path": path, "old_string": old_string,
                            "new_string": new_string})


def _multiedit(path, edits):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                      args={"file_path": path, "edits": edits})


def _write(path, content=ENABLE_ALL):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write",
                      args={"file_path": path, "content": content})


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp(tool, args):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, action=ActionClass.MCP, args=args)


def _gated(d) -> bool:
    return d.action != Action.ALLOW


def _ours(d) -> bool:
    return _gated(d) and d.rule == RULE


# ---- Edit/Write: gated shapes ---------------------------------------------------

def test_enable_all_via_write_gated():
    assert _ours(evaluate(_write(LOCAL), EMPTY))


def test_enable_all_via_edit_gated():
    assert _ours(evaluate(_edit(LOCAL, '"enableAllProjectMcpServers": true'), EMPTY))


def test_enabled_list_via_write_gated():
    assert _ours(evaluate(_write(LOCAL, '{"enabledMcpjsonServers": ["evil"]}'), EMPTY))


def test_enabled_list_multiline_gated():
    assert _ours(evaluate(_write(LOCAL, '{\n  "enabledMcpjsonServers": [\n    "evil"\n  ]\n}'), EMPTY))


def test_string_true_value_gated():
    assert _ours(evaluate(_write(LOCAL, '{"enableAllProjectMcpServers": "true"}'), EMPTY))


def test_truncated_fragment_ending_at_colon_gated():
    assert _ours(evaluate(_edit(LOCAL, '"enableAllProjectMcpServers":'), EMPTY))


def test_windows_path_and_nested_project_gated():
    assert _ours(evaluate(_write(r"C:\repo\.claude\settings.local.json"), EMPTY))
    assert _ours(evaluate(_write("/home/u/proj/.claude/settings.local.json"), EMPTY))


def test_unicode_escaped_key_gated():
    content = '{"\\u0065nableAllProjectMcpServers": true}'
    assert _ours(evaluate(_write(LOCAL, content), EMPTY))


def test_unicode_escaped_key_in_partial_fragment_gated():
    assert _ours(evaluate(_edit(LOCAL, '"enabledMcpjson\\u0053ervers": ["x"]'), EMPTY))


def test_user_scope_path_gated():
    assert _ours(evaluate(_write("~/.claude/settings.local.json"), EMPTY))
    assert _ours(evaluate(_write("/home/u/.claude/settings.local.json"), EMPTY))


def test_single_quoted_key_gated():
    assert _ours(evaluate(_edit(LOCAL, "'enableAllProjectMcpServers': true"), EMPTY))


def test_case_insensitive_key_gated():
    assert _ours(evaluate(_write(LOCAL, '{"ENABLEALLPROJECTMCPSERVERS": true}'), EMPTY))


def test_value_flip_anchored_on_key_suffix_gated():
    """Edit replaces old_string wholesale, so the realistic value-only flip
    re-anchors on a SUFFIX of the key name and never spells it in full."""
    for old, new in (('Servers": false', 'Servers": true'),
                     ('ProjectMcpServers": false', 'ProjectMcpServers": true'),
                     ('jsonServers": []', 'jsonServers": ["evil"]')):
        assert _ours(evaluate(_edit(LOCAL, new, old_string=old), EMPTY)), old


def test_old_names_key_new_does_not_is_a_deletion_not_gated():
    """Edit replaces old_string wholesale: if old names the key and new
    doesn't, the key leaves the file. QA round 1 flagged the earlier,
    conservative ask here as a false positive on an ordinary deletion."""
    for old, new in (('"enableAllProjectMcpServers": false', "true"),
                     ('"enableAllProjectMcpServers": false,\n  "model": "opus"', '"model": "sonnet"'),
                     ('"enabledMcpjsonServers": ["a"]', '["a", "evil"]')):
        assert not _gated(evaluate(_edit(LOCAL, new, old_string=old), EMPTY)), old


def test_short_suffix_anchor_gated():
    """QA round 1: suffixes shorter than 4 chars (`rs":`, `s":`) slipped."""
    for old, new in (('rs": false', 'rs": true'), ('s": false', 's": true'),
                     ('s": []', 's": ["evil"]')):
        assert _ours(evaluate(_edit(LOCAL, new, old_string=old), EMPTY)), new


def test_prefix_anchor_at_end_gated():
    d = evaluate(_edit(LOCAL, '"enableAllProj', old_string='"zz'), EMPTY)
    assert _ours(d)


def test_multiedit_split_key_assembly_gated():
    d = evaluate(_multiedit(LOCAL, [
        {"old_string": '"includeCoAuthoredBy"', "new_string": '"enableAllXX"'},
        {"old_string": 'XX"', "new_string": 'ProjectMcpServers"'},
    ]), EMPTY)
    assert _ours(d)


def test_key_rename_gated():
    """QA round 1: plant a harmless key, then rename it into an approval key
    -- new_string names the key with no colon/value at all."""
    d = evaluate(_edit(LOCAL, '"enableAllProjectMcpServers"', old_string='"zz"'), EMPTY)
    assert _ours(d)


def test_key_rename_in_single_multiedit_gated():
    d = evaluate(_multiedit(LOCAL, [
        {"old_string": "{", "new_string": '{"zz": true,'},
        {"old_string": '"zz"', "new_string": '"enabledMcpjsonServers"'},
    ]), EMPTY)
    assert _ours(d)


def test_suffix_inside_other_identifier_not_gated():
    for old, new in (('"fooServers": 1', '"fooServers": 2'),
                     ('"disabledMcpjsonServers": []', '"disabledMcpjsonServers": ["x"]'),
                     ('"enableAllProjectMcpServers": true', '"enableAllProjectMcpServers": false')):
        assert not _gated(evaluate(_edit(LOCAL, new, old_string=old), EMPTY)), new


def test_multiedit_entry_gated():
    d = evaluate(_multiedit(LOCAL, [
        {"old_string": '"model": "a"', "new_string": '"model": "b"'},
        {"old_string": "{", "new_string": '{"enableAllProjectMcpServers": true,'},
    ]), EMPTY)
    assert _ours(d)


# ---- Edit/Write: allowed shapes -------------------------------------------------

def test_explicit_false_not_gated():
    assert not _gated(evaluate(_write(LOCAL, '{"enableAllProjectMcpServers": false}'), EMPTY))


def test_empty_list_and_null_not_gated():
    assert not _gated(evaluate(_write(LOCAL, '{"enabledMcpjsonServers": []}'), EMPTY))
    assert not _gated(evaluate(_write(LOCAL, '{"enabledMcpjsonServers": null,'
                                             ' "enableAllProjectMcpServers": null}'), EMPTY))


def test_turning_approval_off_not_gated():
    d = evaluate(_edit(LOCAL, '"enableAllProjectMcpServers": false',
                       old_string='"enableAllProjectMcpServers": true'), EMPTY)
    assert not _gated(d)


def test_deleting_key_not_gated():
    d = evaluate(_edit(LOCAL, "", old_string=',\n  "enabledMcpjsonServers": ["evil"]'), EMPTY)
    assert not _gated(d)


def test_disabled_list_not_gated():
    assert not _gated(evaluate(_write(LOCAL, '{"disabledMcpjsonServers": ["x"]}'), EMPTY))


def test_benign_local_settings_edit_not_gated():
    assert not _gated(evaluate(_write(LOCAL, '{"model": "opus", "permissions": {"allow": []}}'),
                               EMPTY))


def test_comment_mentioning_key_without_colon_not_gated():
    assert not _gated(evaluate(_write(LOCAL, '{\n // never set enableAllProjectMcpServers\n'
                                             ' "model": "opus"\n}'), EMPTY))


def test_other_file_mentioning_key_not_gated():
    assert not _gated(evaluate(_write("docs/notes.md", ENABLE_ALL), EMPTY))


def test_lookalike_path_not_gated():
    assert not _gated(evaluate(_write("my.claude/settings.local.json"), EMPTY))
    assert not _gated(evaluate(_write(".claude/settings.local.json.bak"), EMPTY))


def test_project_settings_json_blocked_by_self_protect_not_this_guard():
    d = evaluate(_write(".claude/settings.json"), EMPTY)
    assert d.blocked and d.rule != RULE


# ---- MCP-tool forms -------------------------------------------------------------

def test_mcp_write_file_gated():
    assert _ours(evaluate(_mcp("mcp__fs__write_file", {"path": LOCAL, "content": ENABLE_ALL}), EMPTY))


def test_mcp_edit_file_edits_gated():
    d = evaluate(_mcp("mcp__fs__edit_file", {"path": LOCAL, "edits": [
        {"oldText": "{", "newText": '{"enabledMcpjsonServers": ["evil"],'}]}), EMPTY)
    assert _ours(d)


def test_mcp_nested_json_struct_gated():
    d = evaluate(_mcp("mcp__fs__write_json", {"path": LOCAL,
                                              "json": {"enableAllProjectMcpServers": True}}), EMPTY)
    assert _ours(d)


def test_mcp_nested_json_struct_safe_value_not_gated():
    d = evaluate(_mcp("mcp__fs__write_json", {"path": LOCAL,
                                              "json": {"enableAllProjectMcpServers": False}}), EMPTY)
    assert not _gated(d)


def test_mcp_key_value_shape_gated_and_safe_value_allowed():
    on = _mcp("mcp__json__set_key", {"path": LOCAL, "key": "enableAllProjectMcpServers",
                                     "value": True})
    off = _mcp("mcp__json__set_key", {"path": LOCAL, "key": "enableAllProjectMcpServers",
                                      "value": False})
    off_str = _mcp("mcp__json__set_key", {"path": LOCAL, "key": "enabledMcpjsonServers",
                                          "value": "[]"})
    assert _ours(evaluate(on, EMPTY))
    assert not _gated(evaluate(off, EMPTY))
    assert not _gated(evaluate(off_str, EMPTY))


def test_mcp_struct_depth_capped():
    obj = {"enableAllProjectMcpServers": True}
    for _ in range(20):
        obj = {"n": obj}
    d = evaluate(_mcp("mcp__fs__write_json", {"path": LOCAL, "json": obj}), EMPTY)
    assert not _ours(d)  # depth cap (12) is a disclosed bound, pinned here


def test_env_toggle_allows_mcp(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CLAUDE_MCP_AUTOAPPROVE", "1")
    d = evaluate(_mcp("mcp__fs__write_json", {"path": LOCAL,
                                              "json": {"enableAllProjectMcpServers": True}}), EMPTY)
    assert not _gated(d)


def test_mcp_decoy_content_does_not_suppress_struct_fallback():
    d = evaluate(_mcp("mcp__fs__write_json", {"path": LOCAL, "content": '{"model": "x"}',
                                              "json": {"enabledMcpjsonServers": ["evil"]}}), EMPTY)
    assert _ours(d)


# ---- shell forms ----------------------------------------------------------------
# Redirect/heredoc/mv shapes into .claude/ are preempted by self-protect
# (first-deny-wins); this guard's own coverage is jq|sponge and the CLI.

def test_shell_redirect_already_blocked_by_self_protect():
    d = evaluate(_shell(f"echo '{ENABLE_ALL}' > {LOCAL}"), EMPTY)
    assert d.blocked and d.rule == "self-protect"


def test_shell_jq_sponge_assign_gated():
    d = evaluate(_shell(f"jq '.enableAllProjectMcpServers = true' {LOCAL} | sponge {LOCAL}"), EMPTY)
    assert _ours(d)


def test_shell_jq_list_append_gated():
    d = evaluate(_shell(f"jq '.enabledMcpjsonServers += [\"evil\"]' {LOCAL} | sponge {LOCAL}"), EMPTY)
    assert _ours(d)


def test_shell_jq_bareword_merge_gated():
    d = evaluate(_shell(f"jq '. + {{enableAllProjectMcpServers: true}}' {LOCAL} | sponge {LOCAL}"),
                 EMPTY)
    assert _ours(d)


def test_shell_jq_bracket_and_toggle_gated():
    d = evaluate(_shell(f"jq '.[\"enableAllProjectMcpServers\"] |= not' {LOCAL} | sponge {LOCAL}"),
                 EMPTY)
    assert _ours(d)


def test_shell_jq_setpath_gated():
    d = evaluate(_shell(f"jq 'setpath([\"enabledMcpjsonServers\"]; [\"x\"])' {LOCAL} | sponge {LOCAL}"),
                 EMPTY)
    assert _ours(d)


def test_shell_jq_cd_then_bare_filename_gated():
    d = evaluate(_shell("cd .claude && jq '.enableAllProjectMcpServers = true' "
                        "settings.local.json | sponge settings.local.json"), EMPTY)
    assert _ours(d)


def test_shell_jq_safe_values_not_gated():
    for prog in (".enableAllProjectMcpServers = false", ".enabledMcpjsonServers = []",
                 "select(.enableAllProjectMcpServers == true)",
                 ".enableAllProjectMcpServers"):
        d = evaluate(_shell(f"jq '{prog}' {LOCAL} | sponge {LOCAL}"), EMPTY)
        assert not _gated(d), prog


def test_shell_jq_del_not_this_guard():
    # `del` is caught by self-protect's delete-verb check, not this rule.
    d = evaluate(_shell(f"jq 'del(.enableAllProjectMcpServers)' {LOCAL} | sponge {LOCAL}"), EMPTY)
    assert not _ours(d)


def test_shell_jq_on_unrelated_file_not_gated():
    d = evaluate(_shell("jq '.enableAllProjectMcpServers = true' x.json | sponge x.json"), EMPTY)
    assert not _gated(d)


def test_shell_jq_does_not_cross_semicolon():
    d = evaluate(_shell(f"jq '.model' {LOCAL}; echo 'enableAllProjectMcpServers = true'"), EMPTY)
    assert not _gated(d)


def test_cli_config_set_gated():
    assert _ours(evaluate(_shell("claude config set enableAllProjectMcpServers true"), EMPTY))
    assert _ours(evaluate(_shell("claude config set -g enableAllProjectMcpServers true"), EMPTY))
    assert _ours(evaluate(_shell("claude config add enabledMcpjsonServers evil"), EMPTY))


def test_cli_config_set_safe_not_gated():
    assert not _gated(evaluate(_shell("claude config set enableAllProjectMcpServers false"), EMPTY))
    assert not _gated(evaluate(_shell("claude config get enableAllProjectMcpServers"), EMPTY))
    assert not _gated(evaluate(_shell("claude config set theme dark"), EMPTY))


def test_cli_inline_settings_gated():
    d = evaluate(_shell("claude --settings '{\"enableAllProjectMcpServers\": true}' -p hi"), EMPTY)
    assert _ours(d)


def test_cli_inline_settings_safe_not_gated():
    d = evaluate(_shell("claude --settings '{\"model\": \"opus\"}' -p hi"), EMPTY)
    assert not _ours(d)


def test_cli_settings_equals_and_double_quoted_gated():
    assert _ours(evaluate(_shell("claude --settings='{\"enabledMcpjsonServers\": [\"e\"]}' -p x"),
                          EMPTY))
    assert _ours(evaluate(_shell('claude --settings "{\\"enableAllProjectMcpServers\\": true}" -p x'),
                          EMPTY))


def test_cli_settings_file_then_unrelated_clause_not_gated():
    """QA round 1: the inline-JSON check is scoped to the --settings arg."""
    d = evaluate(_shell("claude --settings f.json -p x; grep '\"enableAllProjectMcpServers\": true' notes"),
                 EMPTY)
    assert not _ours(d)


def test_cli_settings_file_path_not_gated_documented_gap():
    assert not _ours(evaluate(_shell("claude --settings /tmp/s.json -p hi"), EMPTY))


def test_shell_jq_update_assign_true_gated():
    d = evaluate(_shell(f"jq '.enableAllProjectMcpServers |= true' {LOCAL} | sponge {LOCAL}"), EMPTY)
    assert _ours(d)


def test_shell_pushd_and_set_location_then_bare_filename_gated():
    for pre in ("pushd .claude;", "Set-Location .claude;"):
        d = evaluate(_shell(pre + " jq '.enableAllProjectMcpServers = true' "
                            "settings.local.json | sponge settings.local.json"), EMPTY)
        assert _ours(d), pre


def test_shell_cd_elsewhere_then_bare_filename_not_gated():
    d = evaluate(_shell("cd /tmp && jq '.enableAllProjectMcpServers = true' "
                        "settings.local.json | sponge settings.local.json"), EMPTY)
    assert not _gated(d)


def test_shell_write_verb_required():
    d = evaluate(_shell(f"echo '\"enableAllProjectMcpServers\": true' ; cat {LOCAL}"), EMPTY)
    assert not _gated(d)


def test_shell_cat_read_not_gated():
    assert not _gated(evaluate(_shell(f"cat {LOCAL}"), EMPTY))


def test_jq_truthy_value_expressions_gated():
    """QA round 1: a safe literal used as an operand is not safe."""
    for prog in (".enableAllProjectMcpServers //= true", ".enableAllProjectMcpServers = false or true",
                 ".enableAllProjectMcpServers = false == false", ".enableAllProjectMcpServers = null or 1",
                 ".enabledMcpjsonServers = [] + [\"evil\"]", ".enableAllProjectMcpServers = false // true"):
        d = evaluate(_shell(f"jq '{prog}' {LOCAL} | sponge {LOCAL}"), EMPTY)
        assert _ours(d), prog


def test_jq_escaped_quote_merge_gated():
    d = evaluate(_shell(f'jq ". + {{\\"enableAllProjectMcpServers\\": true}}" {LOCAL} | sponge {LOCAL}'),
                 EMPTY)
    assert _ours(d)


def test_jq_read_only_projection_not_gated():
    d = evaluate(_shell(f"jq '{{enableAllProjectMcpServers: .enableAllProjectMcpServers}}' {LOCAL}"), EMPTY)
    assert not _gated(d)


def test_cli_settings_dynamic_arg_gated():
    """QA round 1 regression: a variable / command-substitution argument
    falls back to the whole de-obfuscated command."""
    for cmd in ("claude --settings \"$(echo eyJlbmFibGVBbGxQcm9qZWN0TWNwU2VydmVycyI6dHJ1ZX0= | base64 -d)\" -p hi",
                "S='{\"enableAllProjectMcpServers\":true}'; claude --settings \"$S\" -p hi"):
        assert _ours(evaluate(_shell(cmd), EMPTY)), cmd


def test_cli_second_settings_flag_inspected():
    d = evaluate(_shell("claude --settings a.json --settings '{\"enableAllProjectMcpServers\":true}' -p x"),
                 EMPTY)
    assert _ours(d)


def test_cli_config_add_any_value_gated():
    for v in ("null", "'[]'", "evil"):
        assert _ours(evaluate(_shell(f"claude config add enabledMcpjsonServers {v}"), EMPTY)), v


def test_permission_rule_naming_key_not_gated():
    d = evaluate(_write(LOCAL, '{"permissions": {"allow": ["Bash(grep enableAllProjectMcpServers:*)"]}}'),
                 EMPTY)
    assert not _gated(d)


def test_mcp_filepath_arg_gated():
    d = evaluate(_mcp("mcp__fs__write_file", {"filePath": LOCAL, "content": ENABLE_ALL}), EMPTY)
    assert _ours(d)


def test_grep_for_key_not_gated():
    assert not _gated(evaluate(_shell(f"grep enableAllProjectMcpServers {LOCAL}"), EMPTY))


# ---- escape hatches -------------------------------------------------------------

_JQ = f"jq '.enableAllProjectMcpServers = true' {LOCAL} | sponge {LOCAL}"


def test_human_can_override_shell_with_comment():
    assert not _gated(evaluate(_shell(_JQ + " # aegis-allow"), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(_shell(_JQ + " # aegis-allow"), EMPTY))


def test_env_toggle_allows(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CLAUDE_MCP_AUTOAPPROVE", "1")
    assert not _gated(evaluate(_write(LOCAL), EMPTY))
    assert not _gated(evaluate(_shell(_JQ), EMPTY))
    assert not _gated(evaluate(_shell("claude config set enableAllProjectMcpServers true"), EMPTY))


def test_policy_allow_regex_skips_gate():
    pol = Policy(claude_mcp_autoapprove={"allow": [r"\.claude/settings\.local\.json"]})
    assert not _gated(evaluate(_write(LOCAL), pol))


# ---- modes ----------------------------------------------------------------------

def test_default_mode_is_ask():
    assert evaluate(_write(LOCAL), EMPTY).action == Action.ASK
    assert evaluate(_shell(_JQ), EMPTY).action == Action.ASK


def test_deny_mode_hard_blocks():
    d = evaluate(_write(LOCAL), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == RULE


def test_monitor_and_off_modes_allow():
    for m in ("monitor", "off", False):
        assert not _gated(evaluate(_write(LOCAL), Policy(claude_mcp_autoapprove={"mode": m})))


def test_policy_knob_loads_from_yaml(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("claude_mcp_autoapprove:\n  mode: deny\n")
    pol = load_policy(f)
    assert pol.claude_mcp_autoapprove == {"mode": "deny"}
    assert evaluate(_write(LOCAL), pol).action == Action.DENY


# ---- perf -----------------------------------------------------------------------

def test_perf_no_redos_on_jq_padding():
    adv = "jq '" + "#x" * 100000 + f"' {LOCAL} | sponge {LOCAL}"
    t = time.time()
    evaluate(_shell(adv), EMPTY)
    assert time.time() - t < 1.0


def test_shell_jq_comment_padding_gated():
    d = evaluate(_shell("jq '#" + "x" * 450 + "\n.enableAllProjectMcpServers = true' "
                        f"{LOCAL} | sponge {LOCAL}"), EMPTY)
    assert _ours(d)


def test_perf_long_content():
    content = '{"x": "' + "y" * 50000 + '", "enableAllProjectMcpServers": true}'
    t = time.time()
    d = evaluate(_write(LOCAL, content), EMPTY)
    assert time.time() - t < 1.0 and _ours(d)


def test_perf_many_key_tokens():
    adv = "enableAllProjectMcpServers: false " * 5000
    t = time.time()
    patterns.CLAUDE_MCP_AUTOAPPROVE_VALUE_RE.search(adv)
    evaluate(_shell("jq '" + adv + f"' {LOCAL} | sponge {LOCAL}"), EMPTY)
    assert time.time() - t < 1.0


def test_perf_no_redos_on_repeated_claude_config_set():
    """QA round 1: the old single CLI regex was cubic on this (7.5s at 5KB),
    long enough to trip the hook timeout, which fails open."""
    for adv in ("claude config set " * 2000, "jq " * 7000 + LOCAL + " | sponge " + LOCAL,
                "claude --settings " * 2000):
        t = time.time()
        rules.rule_claude_mcp_autoapprove_protect(_shell(adv), EMPTY)
        assert time.time() - t < 0.5, adv[:30]


# ---- direct pattern sanity ------------------------------------------------------

def test_value_regex_matches_each_key_unsafe():
    assert patterns.CLAUDE_MCP_AUTOAPPROVE_VALUE_RE.search('"enableAllProjectMcpServers": true')
    assert patterns.CLAUDE_MCP_AUTOAPPROVE_VALUE_RE.search('"enabledMcpjsonServers": ["a"]')


def test_value_regex_ignores_safe_and_benign():
    for t in ('"enableAllProjectMcpServers": false', '"enabledMcpjsonServers": []',
              '"enabledMcpjsonServers":null', '"disabledMcpjsonServers": ["a"]',
              '"enableAllProjectMcpServersX": true'):
        assert not patterns.CLAUDE_MCP_AUTOAPPROVE_VALUE_RE.search(t), t


# ---- QA round 2 regressions -----------------------------------------------------

def test_r2_settings_quote_split_key_gated():
    for cmd in ('claude --settings "{\\"enableAll""ProjectMcpServers\\":true}"',
                'claude --settings="{\\"enabledMcp""jsonServers\\":[\\"x\\"]}"'):
        assert _ours(evaluate(_shell(cmd), EMPTY)), cmd


def test_r2_settings_inside_bash_c_gated():
    d = evaluate(_shell("bash -c \"claude --settings '{\\\"enableAllProjectMcpServers\\\":true}'\""), EMPTY)
    assert _ours(d)


def test_r2_settings_explicit_safe_values_not_gated():
    for cmd in ("claude --settings '{\"enableAllProjectMcpServers\": false}' -p x",
                "claude --settings '{\"enabledMcpjsonServers\": []}' -p x",
                "claude config set enabledMcpjsonServers '[]'"):
        assert not _gated(evaluate(_shell(cmd), EMPTY)), cmd


def test_r2_perf_many_dynamic_settings_args():
    ev = _shell("claude" + " --settings $x" * 1400)
    t = time.time()
    rules.rule_claude_mcp_autoapprove_protect(ev, EMPTY)
    assert time.time() - t < 0.5


def test_r2_jq_key_construction_gated():
    for prog in (".enableAllProjectMcpServers? = true",
                 '. + {("enableAllProjectMcpServers"): true}',
                 '.["enableAll"+"ProjectMcpServers"]=true',
                 '.["enableAll\\("Project")McpServers"]=true'):
        d = evaluate(_shell(f"jq '{prog}' {LOCAL} | sponge {LOCAL}"), EMPTY)
        assert _ours(d), prog
    d = evaluate(_shell(f"jq --arg k enableAllProjectMcpServers '.[$k]=true' {LOCAL} | sponge {LOCAL}"),
                 EMPTY)
    assert _ours(d)


def test_r2_jq_unrelated_write_not_gated():
    for prog in ('.model = "x"', '.disabledMcpjsonServers += ["x"]'):
        d = evaluate(_shell(f"jq '{prog}' {LOCAL} | sponge {LOCAL}"), EMPTY)
        assert not _gated(d), prog


def test_r2_deeply_nested_json_does_not_crash():
    content = '{"a":' + '[' * 3000 + ']' * 3000 + '}'
    for ev in (_write(LOCAL, content), _edit(LOCAL, content),
               _mcp("mcp__fs__write_file", {"path": LOCAL, "content": content})):
        rules.rule_claude_mcp_autoapprove_protect(ev, EMPTY)  # must not raise


def test_r2_edit_adding_permission_rule_naming_key_not_gated():
    d = evaluate(_edit(LOCAL, '["Bash(grep enableAllProjectMcpServers:*)",', old_string="["), EMPTY)
    assert not _gated(d)


# ---- QA round 3 regressions -----------------------------------------------------

_J = "'{\"enableAllProjectMcpServers\":true}'"


def test_r3_settings_unrecognised_claude_binary_gated():
    for pre in ("`which claude`", "$(which claude)", "claude.exe",
                "node node_modules/@anthropic-ai/claude-code/cli.js", "c=claude; $c"):
        assert _ours(evaluate(_shell(f"{pre} --settings {_J}"), EMPTY)), pre


def test_r3_jq_path_expression_and_not_value_gated():
    for prog in ("(.enableAllProjectMcpServers, .foo) |= true",
                 "path(.enableAllProjectMcpServers) as $p | setpath($p; true)",
                 '. + {"enableAllProjectMcpServers": false | not}',
                 ". + {enableAllProjectMcpServers: null | not}"):
        d = evaluate(_shell(f"jq '{prog}' {LOCAL} | sponge {LOCAL}"), EMPTY)
        assert _ours(d), prog


def test_r3_mcp_servers_read_and_alt_read_not_this_guard():
    for cmd in (f"jq -r '.mcpServers | keys[]' .mcp.json > servers.txt && cat {LOCAL}",
                f"jq '.enableAllProjectMcpServers // false' {LOCAL} > /tmp/x"):
        assert rules.rule_claude_mcp_autoapprove_protect(_shell(cmd), EMPTY) is None, cmd


# ---- QA round 4 regressions (structural jq judgement) ---------------------------

def _rule(cmd):
    return rules.rule_claude_mcp_autoapprove_protect(_shell(cmd), EMPTY)


def test_r4_jq_truthy_operand_forms_gated():
    for prog in ('.enabledMcpjsonServers = [] - [] + ["evil"]',
                 ".enableAllProjectMcpServers = false as $x | true",
                 ".enableAllProjectMcpServers = false and false or true"):
        assert _rule(f"jq '{prog}' {LOCAL} | sponge {LOCAL}"), prog
    assert _ours(evaluate(_shell(
        f"jq '.enabledMcpjsonServers = null as $n | [\"evil\"]' {LOCAL} > t && mv t {LOCAL}"), EMPTY))


def test_r4_jq_dynamic_key_construction_gated():
    for prog in ('.["enable"+"AllProject"+"McpServers"] = true',
                 '.["en"+"ableAllPro"+"jectMcpSer"+"vers"] = true',
                 '.["enabled"+"Mcpjson"+"Servers"] = ["evil"]',
                 '. + ("eyJ4IjoxfQ=="|@base64d|fromjson)',
                 '. + ([["enableAllProjectMcpServers", true]] | map({key: .[0], value: .[1]}) | from_entries)'):
        assert _rule(f"jq '{prog}' {LOCAL} | sponge {LOCAL}"), prog
    assert _rule(f"jq --arg a enable --arg b AllProject '.[$a+$b+\"McpServers\"]=true' {LOCAL} | sponge {LOCAL}")


def test_r4_settings_binary_never_spelling_claude_gated():
    for pre in ("~/.local/bin/cl?ude", "/usr/local/bin/cla*"):
        assert _rule(f"{pre} --settings '{{\"enableAllProjectMcpServers\":true}}' -p hi"), pre


def test_r4_non_jq_writers_gated():
    for cmd in (f"python3 -c 'import json;d=json.load(open(\"{LOCAL}\"));"
                f"d[\"enableAll\"+\"ProjectMcpServers\"]=True;print(json.dumps(d))' | sponge {LOCAL}",
                f"sed 's/\"model\"/\"enableAllProjectMcpServers\"/' {LOCAL} | sponge {LOCAL}"):
        assert _rule(cmd), cmd


def test_r4_ordinary_settings_writes_not_gated():
    for cmd in (f"n=$(jq '.enabledMcpjsonServers|length' {LOCAL}); echo $n > /tmp/out",
                f"jq --arg m opus '.model = $m' {LOCAL} | sponge {LOCAL}",
                f"jq '.permissions.allow += [\"Bash(ls)\", \"Bash(cat)\"]' {LOCAL} | sponge {LOCAL}",
                f"jq '.disabledMcpjsonServers += [\"x\"]' {LOCAL} | sponge {LOCAL}",
                f"echo '{{\"enableAllProjectMcpServers\": false}}' | sponge {LOCAL}",
                f"cat {LOCAL} | sponge {LOCAL}"):
        assert _rule(cmd) is None, cmd
