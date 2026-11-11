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

from aegis import patterns
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


def test_case_insensitive_key_gated():
    assert _ours(evaluate(_write(LOCAL, '{"ENABLEALLPROJECTMCPSERVERS": true}'), EMPTY))


def test_value_flip_anchored_on_key_in_old_string_gated():
    # old_string anchors on the key (and the following space); new_string is
    # only the replacement value -- the key name never appears in it.
    d = evaluate(_edit(LOCAL, "true", old_string='"enableAllProjectMcpServers": false'), EMPTY)
    assert _ours(d)


def test_list_append_anchored_on_key_in_old_string_gated():
    d = evaluate(_edit(LOCAL, '["a", "evil"]', old_string='"enabledMcpjsonServers": ["a"]'), EMPTY)
    assert _ours(d)


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


def test_mcp_decoy_content_does_not_suppress_struct_fallback():
    d = evaluate(_mcp("mcp__fs__write_json", {"path": LOCAL, "content": '{"model": "x"}',
                                              "json": {"enabledMcpjsonServers": ["evil"]}}), EMPTY)
    assert _ours(d)


# ---- shell forms ----------------------------------------------------------------
# Redirect/heredoc/mv shapes into .claude/ are preempted by self-protect
# (first-deny-wins); this guard's own coverage is jq|sponge and the CLI.

def test_shell_redirect_blocked_by_someone():
    d = evaluate(_shell(f"echo '{ENABLE_ALL}' > {LOCAL}"), EMPTY)
    assert d.blocked


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
                 "del(.enableAllProjectMcpServers)", "select(.enableAllProjectMcpServers == true)",
                 ".enableAllProjectMcpServers"):
        d = evaluate(_shell(f"jq '{prog}' {LOCAL} | sponge {LOCAL}"), EMPTY)
        assert not _ours(d), prog


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
    for m in ("monitor", "off"):
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


def test_perf_long_content():
    content = '{"x": "' + "y" * 50000 + '", "enableAllProjectMcpServers": true}'
    t = time.time()
    d = evaluate(_write(LOCAL, content), EMPTY)
    assert time.time() - t < 1.0 and _ours(d)


def test_perf_many_key_tokens():
    adv = "enableAllProjectMcpServers: false " * 5000
    t = time.time()
    patterns.CLAUDE_MCP_AUTOAPPROVE_VALUE_RE.search(adv)
    patterns.CLAUDE_MCP_AUTOAPPROVE_JQ_RE.search("jq '" + adv)
    assert time.time() - t < 1.0
