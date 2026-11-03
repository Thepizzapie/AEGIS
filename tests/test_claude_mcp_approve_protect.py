"""Claude Code MCP trust-prompt bypass guard: ``enableAllProjectMcpServers:
true`` / non-empty ``enabledMcpjsonServers`` planted in
``.claude/settings.local.json`` silences Claude Code's per-server trust
prompt for a ``.mcp.json`` that arrived via git."""
import time

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

P = ".claude/settings.local.json"
EMPTY = Policy()
DENY = Policy(claude_mcp_approve={"mode": "deny"})
ALL = '{"enableAllProjectMcpServers": true}'
LIST = '{"enabledMcpjsonServers": ["evil"]}'
RULE = "claude-mcp-approve-protect"


def _edit(path, s):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit", args={"file_path": path, "new_string": s})


def _write(path, s):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write", args={"file_path": path, "content": s})


def _sh(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp(args):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__x", action=ActionClass.MCP, args=args)


def gated(d):
    return d.action != Action.ALLOW and d.rule == RULE


def test_enable_all_write_gated():
    assert gated(evaluate(_write(P, ALL), EMPTY))


def test_enabled_list_edit_gated():
    assert gated(evaluate(_edit(P, '"enabledMcpjsonServers": ["a"]'), EMPTY))


def test_default_is_ask_and_deny_mode_denies():
    assert evaluate(_write(P, ALL), EMPTY).action == Action.ASK
    assert evaluate(_write(P, ALL), DENY).action == Action.DENY


def test_safe_values_allowed():
    for s in ('{"enableAllProjectMcpServers": false}', '{"enabledMcpjsonServers": []}',
              '{"model": "opus"}'):
        assert not gated(evaluate(_write(P, s), EMPTY)), s


def test_other_file_ignored():
    assert not gated(evaluate(_write("settings.json.bak", ALL), EMPTY))
    assert not gated(evaluate(_write("notes.json", ALL), EMPTY))


def test_nested_and_windows_paths():
    assert gated(evaluate(_write("pkg/.claude/settings.local.json", ALL), EMPTY))
    assert gated(evaluate(_write(".claude\\settings.local.json", ALL), EMPTY))


def test_unicode_escape_fragment():
    assert gated(evaluate(_edit(P, '"\\u0065nableAllProjectMcpServers": true'), EMPTY))


def test_whitespace_and_case():
    assert gated(evaluate(_write(P, '{"ENABLEALLPROJECTMCPSERVERS"  :\n   true}'), EMPTY))


def test_true_as_string():
    assert gated(evaluate(_write(P, '{"enableAllProjectMcpServers": "true"}'), EMPTY))


def test_mcp_write_and_structural():
    assert gated(evaluate(_mcp({"path": P, "content": ALL}), EMPTY))
    assert gated(evaluate(_mcp({"path": P, "json": {"enableAllProjectMcpServers": True}}), EMPTY))
    assert gated(evaluate(_mcp({"path": P, "json": {"x": {"enabledMcpjsonServers": ["a"]}}}), EMPTY))
    assert not gated(evaluate(_mcp({"path": P, "json": {"enableAllProjectMcpServers": False}}), EMPTY))


def test_mcp_key_value_shape():
    assert gated(evaluate(_mcp({"path": P, "key": "enableAllProjectMcpServers", "value": True}), EMPTY))
    assert not gated(evaluate(_mcp({"path": P, "key": "enableAllProjectMcpServers", "value": False}), EMPTY))


def test_shell_redirect_and_tee_blocked():
    # self-protect's CONFIG_DIR_RE write-verb check preempts these (non-
    # escapable DENY) before this rule runs, same as every sibling guard.
    for c in (f"echo '{ALL}' > {P}", f"echo '{LIST}' | tee {P}"):
        assert evaluate(_sh(c), EMPTY).action == Action.DENY


def test_shell_jq_sponge():
    assert gated(evaluate(_sh(f"jq '.enableAllProjectMcpServers = true' {P} | sponge {P}"), EMPTY))
    assert gated(evaluate(_sh(f"jq '.enabledMcpjsonServers += [\"x\"]' {P} | sponge {P}"), EMPTY))


def test_shell_jq_false_masking_regression():
    for c in (f"jq '.enableAllProjectMcpServers = true | .x = false' {P} | sponge {P}",
              f"jq '.enableAllProjectMcpServers = true' {P} | sponge {P} && echo false",
              f"jq '.enableAllProjectMcpServers = false | .enableAllProjectMcpServers = true' {P} | sponge {P}",
              f"jq '.enabledMcpjsonServers = [\"x\"] | .enableAllProjectMcpServers = false' {P} | sponge {P}",
              f"jq '.enableAllProjectMcpServers |= true' {P} | sponge {P}"):
        assert gated(evaluate(_sh(c), EMPTY)), c


def test_jq_without_sink_not_gated():
    assert not gated(evaluate(_sh(f"jq '.enableAllProjectMcpServers = true' {P}"), EMPTY))


def test_echo_into_sponge_gated():
    assert gated(evaluate(_sh(f"echo '{ALL}' | sponge {P}"), EMPTY))


def test_split_edit_plant_gated(tmp_path, monkeypatch):
    # key already on disk with a safe value -> value-flip fragments ask
    d = tmp_path / ".claude"
    d.mkdir()
    (d / "settings.local.json").write_text('{"enableAllProjectMcpServers": false}')
    f = str(d / "settings.local.json")
    for s in ("true", ": true", ":true", '"true"', '["evil"]', ': ["a"]', "[",
              '"enableAllProjectMcpServers"', '{"enableAllProjectMcpServers": '):
        assert gated(evaluate(_edit(f, s), EMPTY)), s
    assert not gated(evaluate(_edit(f, "false"), EMPTY))
    assert not gated(evaluate(_edit(f, "[]"), EMPTY))


def test_split_key_edit_without_disk_gated():
    for s in ('"enableAllProjectMcpServers"', '"enabledMcpjsonServers":'):
        assert gated(evaluate(_edit(P, s), EMPTY)), s


def test_old_string_naming_key_makes_value_fragment_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Edit", args={
        "file_path": P, "old_string": '"enableAllProjectMcpServers": false', "new_string": "true"})
    assert gated(evaluate(ev, EMPTY))


def test_permissions_allow_array_fill_not_gated():
    for s in ('["Bash(git status)"]', '["Bash(ls:*)", "Read(*)"]', "true", "[ \"a\" ]"):
        assert not gated(evaluate(_edit(P, s), EMPTY)), s


def test_multiedit_split_plant_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                    args={"file_path": P, "edits": [
                        {"old_string": '"enableAllProjectMcpServers": false', "new_string": "true"}]})
    assert gated(evaluate(ev, EMPTY))


def test_jsonc_comments_gated():
    for s in ('"enabledMcpjsonServers": [ // c\n "a"]', '"enabledMcpjsonServers": [\n/* c */ "a"]',
              '"enableAllProjectMcpServers":/*c*/true'):
        assert gated(evaluate(_write(P, s), EMPTY)), s


def test_cd_then_bare_filename_jq_gated():
    c = f"cd .claude && jq '.enableAllProjectMcpServers = true' settings.local.json | sponge settings.local.json"
    assert gated(evaluate(_sh(c), EMPTY))
    assert not gated(evaluate(_sh("cd src && jq '.enableAllProjectMcpServers = true' settings.local.json | sponge settings.local.json"), EMPTY))


def test_shell_cd_form_blocked():
    d = evaluate(_sh(f"cd .claude && echo '{ALL}' > settings.local.json"), EMPTY)
    assert d.action == Action.DENY


def test_shell_read_only_not_gated():
    assert not gated(evaluate(_sh(f"cat {P}"), EMPTY))
    assert not gated(evaluate(_sh(f"grep enableAllProjectMcpServers {P}"), EMPTY))


def test_shell_human_override():
    c = f"jq '.enableAllProjectMcpServers = true' {P} | sponge {P}  # aegis-allow"
    assert gated(evaluate(_sh(c.replace("  # aegis-allow", "")), EMPTY))
    assert not gated(evaluate(_sh(c), EMPTY))


def test_env_toggle_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CLAUDE_MCP_APPROVE", "1")
    assert not gated(evaluate(_write(P, ALL), EMPTY))
    c = f"jq '.enableAllProjectMcpServers = true' {P} | sponge {P}"
    assert not gated(evaluate(_sh(c), EMPTY))


def test_policy_allow_regex():
    pol = Policy(claude_mcp_approve={"allow": [r"trusted/\.claude"]})
    assert not gated(evaluate(_write("trusted/.claude/settings.local.json", ALL), pol))
    assert gated(evaluate(_write(P, ALL), pol))


def test_off_and_monitor():
    assert gated(evaluate(_write(P, ALL), EMPTY))
    assert not gated(evaluate(_write(P, ALL), Policy(claude_mcp_approve={"mode": "off"})))
    assert not gated(evaluate(_write(P, ALL), Policy(claude_mcp_approve={"mode": "monitor"})))


def test_empty_content_ignored():
    assert not gated(evaluate(_write(P, ""), EMPTY))


def test_loader_roundtrip(tmp_path):
    from aegis.loader import load_policy
    f = tmp_path / "p.yaml"
    f.write_text("claude_mcp_approve:\n  mode: deny\n")
    assert load_policy(str(f)).claude_mcp_approve == {"mode": "deny"}


def test_perf_no_redos():
    t = time.time()
    evaluate(_sh("jq " + "# " + "a" * 200000 + f" {P}"), EMPTY)
    evaluate(_write(P, '"enabledMcpjsonServers": ' + "[ " * 50000), EMPTY)
    assert time.time() - t < 3
