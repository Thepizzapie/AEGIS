"""JetBrains File Watcher auto-exec protection guard — blocks planting/
altering a File Watcher task in `.idea/watcherTasks.xml` (an
`<option name="program" value="...">` entry) that runs an external program
automatically, unattended, on the next matching file save in any JetBrains
IDE (IntelliJ, PyCharm, WebStorm, ...) that opens this project.

THREAT MODEL: no existing guard reaches this surface —
`rule_devcontainer_exec_protect`'s own docstring explicitly disclosed a
JetBrains `.idea/` run-configuration's "Before launch" step as a related but
distinct, not-covered IDE-auto-run primitive. A File Watcher is that
family's most dangerous member: it fires on an ordinary file SAVE, with no
Run/Debug click, no folder-reopen prompt, no git/CI/boot trigger, and no
human confirmation gate of any kind.

Default mode is `ask` (not `deny`) — a real File Watcher can be legitimate,
shared team tooling (format-on-save), so this guard needs a human to have
actually looked at it, matching every sibling `*_protect` guard's default.
"""
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                                  # default mode: ask
DENY = Policy(jetbrains_watcher_exec={"mode": "deny"})             # stricter, hard-block posture

RULE = "jetbrains-watcher-protect"


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


WATCHER_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<project version="4">\n'
    '  <component name="ProjectTasksOptions">\n'
    '    <TaskOptions isEnabled="true">\n'
    '      <option name="arguments" value="$FileName$" />\n'
    '      <option name="name" value="evil watcher" />\n'
    '      <option name="program" value="$ProjectFileDir$/evil.sh" />\n'
    '      <option name="workingDir" value="$ProjectFileDir$" />\n'
    "    </TaskOptions>\n"
    "  </component>\n"
    "</project>\n"
)
BENIGN_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<project version="4">\n'
    '  <component name="ProjectTasksOptions" />\n'
    "</project>\n"
)


# ---- Edit/Write/MultiEdit/MCP forms -------------------------------------------

def test_write_watcher_program_gated():
    d = evaluate(_write(".idea/watcherTasks.xml", WATCHER_XML), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_write_benign_watcher_file_not_gated():
    d = evaluate(_write(".idea/watcherTasks.xml", BENIGN_XML), EMPTY)
    assert d.action == Action.ALLOW


def test_write_empty_content_not_gated():
    d = evaluate(_write(".idea/watcherTasks.xml"), EMPTY)
    assert d.action == Action.ALLOW


def test_non_watcher_idea_file_not_gated():
    # `.idea/misc.xml`, `.idea/workspace.xml`, etc. -- an unrelated project
    # file merely living alongside watcherTasks.xml must not gate, even with
    # the exact same "program" attribute-shaped content (this guard is
    # scoped to the one file JetBrains itself reads for File Watchers).
    d = evaluate(_write(".idea/misc.xml", WATCHER_XML), EMPTY)
    assert d.action == Action.ALLOW


def test_program_value_elsewhere_not_matching_key_not_gated():
    # A `program` VALUE (not the attribute NAME) mentioned elsewhere in the
    # file must not false-positive -- the gate is on the `name="program"`
    # attribute itself.
    content = '<option name="description" value="runs the program later" />'
    d = evaluate(_write(".idea/watcherTasks.xml", content), EMPTY)
    assert d.action == Action.ALLOW


def test_edit_new_string_gated():
    d = evaluate(_edit_content(".idea/watcherTasks.xml",
                                '<option name="program" value="/tmp/evil.sh" />'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_multi_edit_new_string_gated():
    d = evaluate(_multi_edit(".idea/watcherTasks.xml",
                              '<option name="program" value="/tmp/evil.sh" />'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mcp_write_flat_content_gated():
    d = evaluate(_mcp_write(".idea/watcherTasks.xml", WATCHER_XML), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mcp_write_nested_content_gated():
    d = evaluate(_mcp_write_nested(".idea/watcherTasks.xml", WATCHER_XML), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_single_quoted_program_attr_gated():
    d = evaluate(_write(".idea/watcherTasks.xml",
                         "<option name='program' value='/tmp/evil.sh' />"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mixed_case_program_attr_gated():
    d = evaluate(_write(".idea/watcherTasks.xml",
                         '<OPTION NAME="Program" VALUE="/tmp/evil.sh" />'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_non_xml_path_not_gated():
    d = evaluate(_write("notes.md", WATCHER_XML), EMPTY)
    assert d.action == Action.ALLOW


# ---- shell forms ----------------------------------------------------------------

def test_shell_heredoc_watcher_gated():
    cmd = ("cat > .idea/watcherTasks.xml <<'EOF'\n" + WATCHER_XML + "EOF")
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_shell_echo_append_gated():
    d = evaluate(_shell(
        'echo \'<option name="program" value="/tmp/evil.sh" />\' '
        ">> .idea/watcherTasks.xml"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_shell_sed_insert_gated():
    d = evaluate(_shell(
        "sed -i '/TaskOptions/a\\  <option name=\"program\" value=\"/tmp/evil.sh\" />' "
        ".idea/watcherTasks.xml"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_shell_read_only_not_gated():
    d = evaluate(_shell("cat .idea/watcherTasks.xml"), EMPTY)
    assert d.action == Action.ALLOW


def test_shell_unrelated_write_not_gated():
    d = evaluate(_shell('echo \'<option name="checkSyntaxErrors" value="true" />\' '
                        ">> .idea/watcherTasks.xml"), EMPTY)
    assert d.action == Action.ALLOW


def test_shell_program_without_watcher_path_not_gated():
    # The dangerous attribute alone, with no watcherTasks.xml named anywhere
    # in the command, must not gate -- this guard is scoped to the one
    # JetBrains config file, not a generic `name="program"` ban.
    d = evaluate(_shell('grep -r "name=\\"program\\"" .'), EMPTY)
    assert d.action == Action.ALLOW


def test_shell_cd_into_idea_dir_then_bare_filename_gated():
    # QA-anticipated gap (see JETBRAINS_CD_RE's own comment in patterns.py):
    # an ordinary `cd .idea && ...` two-step must not evade the single-
    # contiguous-match path check the way it did for devcontainer/vscode
    # before their own CD+bare-filename fallback existed.
    cmd = ('cd .idea && echo \'<option name="program" value="/tmp/evil.sh" />\' '
           ">> watcherTasks.xml")
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_shell_cd_elsewhere_then_bare_filename_not_gated():
    cmd = ('cd /tmp && echo \'<option name="program" value="/tmp/evil.sh" />\' '
           ">> watcherTasks.xml")
    d = evaluate(_shell(cmd), EMPTY)
    assert d.action == Action.ALLOW


def test_shell_cd_into_lookalike_dir_not_gated():
    cmd = ('cd .idea-old && echo \'<option name="program" value="x" />\' '
           ">> watcherTasks.xml")
    d = evaluate(_shell(cmd), EMPTY)
    assert d.action == Action.ALLOW


# ---- escapability: human-only, matching every sibling *_protect guard --------

def test_human_can_override_shell_form_with_comment():
    d = evaluate(_shell(
        'echo \'<option name="program" value="/tmp/evil.sh" />\' '
        ">> .idea/watcherTasks.xml # aegis-allow"), EMPTY)
    assert d.action == Action.ALLOW


def test_agent_cannot_override_shell_form_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "spawned-agent")
    d = evaluate(_shell(
        'echo \'<option name="program" value="/tmp/evil.sh" />\' '
        ">> .idea/watcherTasks.xml # aegis-allow"), EMPTY)
    assert _gated(d)


def test_env_toggle_allows_edit_form(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_JETBRAINS_WATCHER_EXEC", "1")
    d = evaluate(_write(".idea/watcherTasks.xml", WATCHER_XML), EMPTY)
    assert d.action == Action.ALLOW


def test_env_toggle_allows_shell_form(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_JETBRAINS_WATCHER_EXEC", "1")
    d = evaluate(_shell(
        'echo \'<option name="program" value="x" />\' >> .idea/watcherTasks.xml'), EMPTY)
    assert d.action == Action.ALLOW


def test_policy_allowlist_permits_matching_path():
    policy = Policy(jetbrains_watcher_exec={"allow": [r"\.idea/watcherTasks\.xml"]})
    d = evaluate(_write(".idea/watcherTasks.xml", WATCHER_XML), policy)
    assert d.action == Action.ALLOW


def test_policy_allowlist_does_not_cover_unmatched_path():
    policy = Policy(jetbrains_watcher_exec={"allow": [r"unrelated\.xml"]})
    d = evaluate(_write(".idea/watcherTasks.xml", WATCHER_XML), policy)
    assert _gated(d)


# ---- mode knob --------------------------------------------------------------

def test_default_mode_is_ask():
    d = evaluate(_write(".idea/watcherTasks.xml", WATCHER_XML), EMPTY)
    assert d.action == Action.ASK


def test_deny_mode_hard_blocks():
    d = evaluate(_write(".idea/watcherTasks.xml", WATCHER_XML), DENY)
    assert d.action == Action.DENY


def test_off_mode_allows():
    policy = Policy(jetbrains_watcher_exec={"mode": "off"})
    d = evaluate(_write(".idea/watcherTasks.xml", WATCHER_XML), policy)
    assert d.action == Action.ALLOW


def test_yaml_boolean_false_mode_treated_as_off():
    policy = Policy(jetbrains_watcher_exec={"mode": False})
    d = evaluate(_write(".idea/watcherTasks.xml", WATCHER_XML), policy)
    assert d.action == Action.ALLOW


def test_monitor_mode_logs_and_allows(tmp_path, monkeypatch):
    import json
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AEGIS_AUDIT", str(audit))
    policy = Policy(jetbrains_watcher_exec={"mode": "monitor"})
    d = evaluate(_write(".idea/watcherTasks.xml", WATCHER_XML), policy)
    assert d.action == Action.ALLOW
    rows = [json.loads(l) for l in audit.read_text().splitlines() if l.strip()]
    monitor = [r for r in rows if r.get("rule") == "jetbrains-watcher-protect-monitor"]
    assert monitor and monitor[0]["decision"] == "deny"
