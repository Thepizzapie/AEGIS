"""JetBrains "Before launch: run External Tool" auto-exec protection guard —
blocks wiring a run/debug configuration in `.idea/runConfigurations/*.xml`
to run an External Tool automatically before every launch (an
`<option name="ToolBeforeRunTask" enabled="true" actionId="..." />` entry),
or defining/redefining that tool's own command in `.idea/tools/*.xml`
(`<tool name="...">`'s `<exec><option name="COMMAND" value="..." /></exec>`).

THREAT MODEL: `rule_devcontainer_exec_protect`'s, `rule_vscode_tasks_
protect`'s, and `rule_jetbrains_watcher_protect`'s own docstrings all
disclosed this exact surface — a JetBrains run configuration's "Before
launch" step — as a related but distinct, not-covered IDE-auto-run
primitive. Either file alone is a real step toward the attack: wiring
`ToolBeforeRunTask` onto an EXISTING, already-reviewed run configuration
silently attaches a new auto-run step with no change to the tool
definition at all, while redefining an ALREADY-WIRED tool's own `COMMAND`
changes what runs with no change to `runConfigurations/*.xml` at all.

Default mode is `ask` (not `deny`) — a real Before-Launch External Tool can
be legitimate, shared team tooling, so this guard needs a human to have
actually looked at it, matching every sibling `*_protect` guard's default.
"""
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                                    # default mode: ask
DENY = Policy(jetbrains_run_config={"mode": "deny"})                # stricter, hard-block posture

RULE = "jetbrains-run-config-protect"


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _edit(path, tool="Edit"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args={"file_path": path})


def _write(path, content=None):
    args = {"file_path": path}
    if content is not None:
        args["content"] = content
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write", args=args)


def _edit_content(path, new_string):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                       args={"file_path": path, "new_string": new_string})


def _multi_edit(path, new_string):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                       args={"file_path": path,
                             "edits": [{"old_string": "x", "new_string": new_string}]})


def _mcp_write(path, content=None):
    args = {"path": path}
    if content is not None:
        args["content"] = content
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                       action=ActionClass.MCP, args=args)


def _mcp_write_nested(path, text):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                       action=ActionClass.MCP,
                       args={"path": path,
                             "content": [{"type": "text", "text": text}]})


def _gated(d) -> bool:
    return d.action != Action.ALLOW


RUNCONFIG_XML = (
    '<component name="ProjectRunConfigurationManager">\n'
    '  <configuration name="App" type="Application" factoryName="Application">\n'
    "    <method v=\"2\">\n"
    '      <option name="ToolBeforeRunTask" enabled="true" '
    'actionId="Tool_External Tools_Evil" />\n'
    "    </method>\n"
    "  </configuration>\n"
    "</component>\n"
)
RUNCONFIG_BENIGN_XML = (
    '<component name="ProjectRunConfigurationManager">\n'
    '  <configuration name="App" type="Application" factoryName="Application">\n'
    "    <method v=\"2\" />\n"
    "  </configuration>\n"
    "</component>\n"
)
TOOLS_XML = (
    '<toolSet name="External Tools">\n'
    '  <tool name="Evil" showInMainMenu="true">\n'
    "    <exec>\n"
    '      <option name="COMMAND" value="/tmp/evil.sh" />\n'
    '      <option name="PARAMETERS" value="" />\n'
    '      <option name="WORKING_DIRECTORY" value="$ProjectFileDir$" />\n'
    "    </exec>\n"
    "  </tool>\n"
    "</toolSet>\n"
)
TOOLS_BENIGN_XML = (
    '<toolSet name="External Tools">\n'
    '  <tool name="Lint" showInMainMenu="true" />\n'
    "</toolSet>\n"
)


# ---- .idea/runConfigurations/*.xml (ToolBeforeRunTask wiring) -----------------

def test_write_runconfig_wiring_gated():
    d = evaluate(_write(".idea/runConfigurations/App.xml", RUNCONFIG_XML), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_write_benign_runconfig_not_gated():
    d = evaluate(_write(".idea/runConfigurations/App.xml", RUNCONFIG_BENIGN_XML), EMPTY)
    assert d.action == Action.ALLOW


def test_write_empty_content_not_gated():
    d = evaluate(_write(".idea/runConfigurations/App.xml"), EMPTY)
    assert d.action == Action.ALLOW


def test_non_runconfig_idea_file_not_gated():
    d = evaluate(_write(".idea/misc.xml", RUNCONFIG_XML), EMPTY)
    assert d.action == Action.ALLOW


def test_edit_new_string_runconfig_gated():
    d = evaluate(_edit_content(
        ".idea/runConfigurations/App.xml",
        '<option name="ToolBeforeRunTask" enabled="true" actionId="Tool_x" />'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_multi_edit_runconfig_gated():
    d = evaluate(_multi_edit(
        ".idea/runConfigurations/App.xml",
        '<option name="ToolBeforeRunTask" enabled="true" actionId="Tool_x" />'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mcp_write_flat_content_runconfig_gated():
    d = evaluate(_mcp_write(".idea/runConfigurations/App.xml", RUNCONFIG_XML), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mcp_write_nested_content_runconfig_gated():
    d = evaluate(_mcp_write_nested(".idea/runConfigurations/App.xml", RUNCONFIG_XML), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mcp_bare_token_structural_gated():
    # `ToolBeforeRunTask` needs no name= adjacency, so it surfaces as a bare
    # leaf value via `_flatten_strings` regardless of MCP structure.
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__jetbrains__write_runconfig",
                     action=ActionClass.MCP,
                     args={"path": ".idea/runConfigurations/App.xml",
                           "method": {"option": {"name": "ToolBeforeRunTask",
                                                  "enabled": "true"}}})
    d = evaluate(ev, EMPTY)
    assert _gated(d) and d.rule == RULE


def test_shell_heredoc_runconfig_gated():
    cmd = ("cat > .idea/runConfigurations/App.xml <<'EOF'\n" + RUNCONFIG_XML + "EOF")
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_shell_echo_append_runconfig_gated():
    d = evaluate(_shell(
        'echo \'<option name="ToolBeforeRunTask" enabled="true" actionId="x" />\' '
        ">> .idea/runConfigurations/App.xml"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_shell_read_only_runconfig_not_gated():
    d = evaluate(_shell("cat .idea/runConfigurations/App.xml"), EMPTY)
    assert d.action == Action.ALLOW


def test_shell_unrelated_write_runconfig_not_gated():
    d = evaluate(_shell('echo \'<option name="SELECTED_FACTORY_NAME" value="Application" />\' '
                        ">> .idea/runConfigurations/App.xml"), EMPTY)
    assert d.action == Action.ALLOW


def test_shell_before_task_without_path_not_gated():
    d = evaluate(_shell('grep -r "ToolBeforeRunTask" .'), EMPTY)
    assert d.action == Action.ALLOW


def test_shell_cd_into_runconfig_dir_then_bare_filename_gated():
    cmd = ('cd .idea/runConfigurations && echo '
           '\'<option name="ToolBeforeRunTask" enabled="true" actionId="x" />\' '
           ">> App.xml")
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_shell_cd_elsewhere_then_bare_filename_runconfig_not_gated():
    cmd = ('cd /tmp && echo '
           '\'<option name="ToolBeforeRunTask" enabled="true" actionId="x" />\' '
           ">> App.xml")
    d = evaluate(_shell(cmd), EMPTY)
    assert d.action == Action.ALLOW


# ---- .idea/tools/*.xml (COMMAND definition) ------------------------------------

def test_write_tools_command_gated():
    d = evaluate(_write(".idea/tools/External Tools.xml", TOOLS_XML), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_write_benign_tools_not_gated():
    d = evaluate(_write(".idea/tools/External Tools.xml", TOOLS_BENIGN_XML), EMPTY)
    assert d.action == Action.ALLOW


def test_non_tools_idea_file_not_gated():
    d = evaluate(_write(".idea/misc.xml", TOOLS_XML), EMPTY)
    assert d.action == Action.ALLOW


def test_command_value_elsewhere_not_matching_key_not_gated():
    content = '<option name="description" value="the command runs later" />'
    d = evaluate(_write(".idea/tools/External Tools.xml", content), EMPTY)
    assert d.action == Action.ALLOW


def test_edit_new_string_tools_gated():
    d = evaluate(_edit_content(".idea/tools/External Tools.xml",
                                '<option name="COMMAND" value="/tmp/evil.sh" />'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mcp_write_flat_content_tools_gated():
    d = evaluate(_mcp_write(".idea/tools/External Tools.xml", TOOLS_XML), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mcp_structural_name_value_pair_tools_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__jetbrains__write_tool",
                     action=ActionClass.MCP,
                     args={"path": ".idea/tools/External Tools.xml",
                           "tool": {"exec": {"option": [
                               {"name": "COMMAND", "value": "/tmp/evil.sh"},
                               {"name": "WORKING_DIRECTORY", "value": "$ProjectFileDir$"},
                           ]}}})
    d = evaluate(ev, EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mcp_structural_unrelated_name_value_tools_not_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__jetbrains__write_tool",
                     action=ActionClass.MCP,
                     args={"path": ".idea/tools/External Tools.xml",
                           "option": {"name": "WORKING_DIRECTORY", "value": "$ProjectFileDir$"}})
    d = evaluate(ev, EMPTY)
    assert d.action == Action.ALLOW


def test_single_quoted_command_attr_tools_gated():
    d = evaluate(_write(".idea/tools/External Tools.xml",
                         "<option name='COMMAND' value='/tmp/evil.sh' />"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mixed_case_command_attr_tools_gated():
    d = evaluate(_write(".idea/tools/External Tools.xml",
                         '<OPTION NAME="command" VALUE="/tmp/evil.sh" />'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_shell_heredoc_tools_gated():
    cmd = ("cat > '.idea/tools/External Tools.xml' <<'EOF'\n" + TOOLS_XML + "EOF")
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_shell_read_only_tools_not_gated():
    d = evaluate(_shell("cat '.idea/tools/External Tools.xml'"), EMPTY)
    assert d.action == Action.ALLOW


def test_shell_cd_into_tools_dir_then_bare_filename_gated():
    cmd = ('cd .idea/tools && echo \'<option name="COMMAND" value="/tmp/evil.sh" />\' '
           ">> Tools.xml")
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_shell_cd_elsewhere_then_bare_filename_tools_not_gated():
    cmd = ('cd /tmp && echo \'<option name="COMMAND" value="/tmp/evil.sh" />\' '
           ">> Tools.xml")
    d = evaluate(_shell(cmd), EMPTY)
    assert d.action == Action.ALLOW


def test_non_xml_path_not_gated():
    d = evaluate(_write("notes.md", TOOLS_XML), EMPTY)
    assert d.action == Action.ALLOW


# ---- escapability: human-only, matching every sibling *_protect guard --------

def test_human_can_override_shell_form_with_comment():
    d = evaluate(_shell(
        'echo \'<option name="COMMAND" value="/tmp/evil.sh" />\' '
        ">> '.idea/tools/External Tools.xml' # aegis-allow"), EMPTY)
    assert d.action == Action.ALLOW


def test_agent_cannot_override_shell_form_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "spawned-agent")
    d = evaluate(_shell(
        'echo \'<option name="COMMAND" value="/tmp/evil.sh" />\' '
        ">> '.idea/tools/External Tools.xml' # aegis-allow"), EMPTY)
    assert _gated(d)


def test_env_toggle_allows_edit_form(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_JETBRAINS_RUN_CONFIG", "1")
    d = evaluate(_write(".idea/runConfigurations/App.xml", RUNCONFIG_XML), EMPTY)
    assert d.action == Action.ALLOW


def test_env_toggle_allows_shell_form(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_JETBRAINS_RUN_CONFIG", "1")
    d = evaluate(_shell(
        'echo \'<option name="COMMAND" value="x" />\' '
        ">> '.idea/tools/External Tools.xml'"), EMPTY)
    assert d.action == Action.ALLOW


def test_policy_allowlist_permits_matching_path():
    policy = Policy(jetbrains_run_config={"allow": [r"runConfigurations"]})
    d = evaluate(_write(".idea/runConfigurations/App.xml", RUNCONFIG_XML), policy)
    assert d.action == Action.ALLOW


def test_policy_allowlist_does_not_cover_unmatched_path():
    policy = Policy(jetbrains_run_config={"allow": [r"unrelated\.xml"]})
    d = evaluate(_write(".idea/runConfigurations/App.xml", RUNCONFIG_XML), policy)
    assert _gated(d)


# ---- mode knob --------------------------------------------------------------

def test_default_mode_is_ask():
    d = evaluate(_write(".idea/runConfigurations/App.xml", RUNCONFIG_XML), EMPTY)
    assert d.action == Action.ASK


def test_deny_mode_hard_blocks():
    d = evaluate(_write(".idea/runConfigurations/App.xml", RUNCONFIG_XML), DENY)
    assert d.action == Action.DENY


def test_off_mode_allows():
    policy = Policy(jetbrains_run_config={"mode": "off"})
    d = evaluate(_write(".idea/runConfigurations/App.xml", RUNCONFIG_XML), policy)
    assert d.action == Action.ALLOW


def test_yaml_boolean_false_mode_treated_as_off():
    policy = Policy(jetbrains_run_config={"mode": False})
    d = evaluate(_write(".idea/runConfigurations/App.xml", RUNCONFIG_XML), policy)
    assert d.action == Action.ALLOW


def test_monitor_mode_logs_and_allows(tmp_path, monkeypatch):
    import json
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AEGIS_AUDIT", str(audit))
    policy = Policy(jetbrains_run_config={"mode": "monitor"})
    d = evaluate(_write(".idea/runConfigurations/App.xml", RUNCONFIG_XML), policy)
    assert d.action == Action.ALLOW
    rows = [json.loads(l) for l in audit.read_text().splitlines() if l.strip()]
    monitor = [r for r in rows if r.get("rule") == "jetbrains-run-config-protect-monitor"]
    assert monitor and monitor[0]["decision"] == "deny"
