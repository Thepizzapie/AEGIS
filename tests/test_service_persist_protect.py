"""Systemd unit / launchd persistence protection guard — blocks planting/
altering a systemd unit (``/etc/systemd/system/*.service``,
``~/.config/systemd/user/*.service``, a ``*.timer``/``*.socket`` sibling, or a
``<unit>.service.d/override.conf`` drop-in) or a launchd property list
(``~/Library/LaunchAgents/*.plist``, ``/Library/LaunchDaemons/*.plist``), and
the ``systemctl enable``/``launchctl load``-style activation commands that
flip an already-present unit into "runs automatically" with no file write at
all.

Linux/macOS analog of the Windows scheduled-task/service persistence
``PERSIST_RE`` already denies inside ``rule_containment`` — neither surface
had any coverage anywhere in this file before this guard.

Default mode is ``ask`` (not ``deny``) — shipping a systemd unit for one's
own app, or enabling a launchd agent for a dev tool, is routine, sanctioned
work, unlike planting an MCP server. A dedicated ``mode: deny`` policy is
used below to test the stricter posture explicitly.
"""
import time

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                          # default mode: ask
DENY = Policy(service_persist={"mode": "deny"})            # stricter, hard-block posture


def _edit(path, tool="Edit"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args={"file_path": path})


def _write(path, content=None):
    args = {"file_path": path}
    if content is not None:
        args["content"] = content
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write", args=args)


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp_write(path):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                       action=ActionClass.MCP, args={"path": path})


def _mcp_write_arg(key, path):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write",
                       action=ActionClass.MCP, args={key: path})


def _gated(d) -> bool:
    return d.action != Action.ALLOW


# ---- systemd unit files, via Edit/Write -----------------------------------

def test_etc_system_unit_gated():
    d = evaluate(_write("/etc/systemd/system/evil.service"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


def test_user_config_unit_gated():
    d = evaluate(_edit("~/.config/systemd/user/evil.service"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


def test_etc_user_unit_gated():
    assert _gated(evaluate(_write("/etc/systemd/user/evil.service"), EMPTY))


def test_usr_lib_system_unit_gated():
    assert _gated(evaluate(_write("/usr/lib/systemd/system/evil.service"), EMPTY))


def test_timer_socket_path_mount_units_gated():
    for ext in ("timer", "socket", "path", "mount"):
        d = evaluate(_write(f"/etc/systemd/system/evil.{ext}"), EMPTY)
        assert _gated(d) and d.rule == "service-persist-protect", ext


def test_service_dropin_override_gated():
    """A drop-in overrides ExecStart= on an EXISTING, already-enabled unit —
    no brand-new suspicious file, just a hijack of a trusted target."""
    d = evaluate(_write("/etc/systemd/system/sshd.service.d/override.conf"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


def test_timer_dropin_override_gated():
    d = evaluate(_write("/etc/systemd/system/backup.timer.d/override.conf"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


# ---- launchd plists, via Edit/Write ----------------------------------------

def test_user_launch_agent_gated():
    d = evaluate(_write("~/Library/LaunchAgents/com.evil.agent.plist"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


def test_system_launch_agent_gated():
    assert _gated(evaluate(_write("/Library/LaunchAgents/com.evil.agent.plist"), EMPTY))


def test_launch_daemon_gated():
    d = evaluate(_write("/Library/LaunchDaemons/com.evil.daemon.plist"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


# ---- MCP-tool writes -------------------------------------------------------------

def test_mcp_tool_write_to_unit_gated():
    d = evaluate(_mcp_write("/etc/systemd/system/evil.service"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


def test_mcp_tool_alternate_path_arg_keys_gated():
    for key in ("target_file", "targetFile", "filename", "file", "uri"):
        d = evaluate(_mcp_write_arg(key, "~/Library/LaunchAgents/evil.plist"), EMPTY)
        assert _gated(d) and d.rule == "service-persist-protect", key


# ---- shell-based mutation ---------------------------------------------------------

def test_shell_redirect_to_unit_gated():
    assert _gated(evaluate(
        _shell("echo 'ExecStart=/tmp/evil.sh' > /etc/systemd/system/evil.service"), EMPTY))
    assert _gated(evaluate(_shell("cat evil.plist | tee ~/Library/LaunchAgents/x.plist"), EMPTY))


def test_shell_delete_unit_gated():
    assert _gated(evaluate(_shell("rm /etc/systemd/system/evil.service"), EMPTY))


def test_shell_inplace_edit_and_copy_gated():
    assert _gated(evaluate(
        _shell("sed -i 's/x/evil/' /etc/systemd/system/app.service"), EMPTY))
    d = evaluate(_shell("cp evil.plist ~/Library/LaunchAgents/x.plist"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


def test_shell_read_only_not_gated():
    assert not _gated(evaluate(_shell("cat /etc/systemd/system/app.service"), EMPTY))
    assert not _gated(evaluate(_shell("systemctl status app.service"), EMPTY))
    assert not _gated(evaluate(_shell("launchctl list"), EMPTY))


def test_find_path_indirection_gated():
    assert _gated(evaluate(
        _shell("cp evil.service $(find / -path '*systemd/system*')"), EMPTY))
    assert _gated(evaluate(
        _shell("mv evil.plist $(find / -path '*LaunchAgents*')"), EMPTY))


def test_forced_symlink_swap_gated():
    d = evaluate(_shell("ln -sf evil.service /etc/systemd/system/app.service"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


def test_rsync_to_systemd_dir_gated():
    d = evaluate(_shell("rsync -a evil/ ~/.config/systemd/user/"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


def test_tar_extract_to_launch_agents_dir_gated():
    d = evaluate(_shell("tar xf payload.tar -C ~/Library/LaunchAgents/"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


def test_bare_dir_gated_only_with_verb():
    """The bare directory reference alone (no verb) never gates —
    SERVICE_PERSIST_DIR_RE only matters paired with a write/archive verb."""
    assert not _gated(evaluate(_shell("ls ~/Library/LaunchAgents"), EMPTY))
    d = evaluate(_shell("rsync -a evil/ ~/Library/LaunchAgents"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


# ---- path-separator / Windows-trim bypass (same class as the other guards) ----

def test_doubled_separator_does_not_bypass():
    """QA finding class (independent adversarial review of a sibling guard,
    rule_shell_persist_protect's own round-2 QA): a doubled slash / a `.`
    path component is byte-identical to the real path as far as the OS is
    concerned. This guard routes every separator through `_SEP`/`_WIN_TRIM`
    the same way, but had no regression test of its own locking that in."""
    for path in (
        "/etc//systemd/system/evil.service",
        "/etc/./systemd/system/evil.service",
        "etc/systemd//system/evil.service",
    ):
        d = evaluate(_write(path), EMPTY)
        assert _gated(d) and d.rule == "service-persist-protect", path
    d = evaluate(_write("Library//LaunchAgents/evil.plist"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


def test_windows_trailing_dot_does_not_bypass():
    d = evaluate(_write("systemd./system/evil.service"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


def test_etc_doubled_slash_shell_form_does_not_bypass():
    d = evaluate(_shell(
        "echo 'ExecStart=/tmp/evil.sh' >> /etc//systemd/system/evil.service"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


# ---- activation commands: no file write needed -----------------------------------

def test_systemctl_enable_gated():
    d = evaluate(_shell("systemctl enable evil.service"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


def test_systemctl_enable_now_gated():
    d = evaluate(_shell("systemctl enable --now evil.service"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


def test_systemctl_user_enable_gated():
    d = evaluate(_shell("systemctl --user enable evil.service"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


def test_systemctl_reenable_link_edit_gated():
    assert _gated(evaluate(_shell("systemctl reenable evil.service"), EMPTY))
    assert _gated(evaluate(_shell("systemctl link /tmp/evil.service"), EMPTY))
    assert _gated(evaluate(_shell("systemctl edit evil.service"), EMPTY))


def test_systemd_run_scheduling_gated():
    assert _gated(evaluate(
        _shell("systemd-run --on-calendar='daily' /tmp/evil.sh"), EMPTY))
    assert _gated(evaluate(
        _shell("systemd-run --on-boot=5min /tmp/evil.sh"), EMPTY))


def test_systemd_run_oneshot_not_gated():
    """A plain (unscheduled) systemd-run just runs a transient command NOW —
    not a persistence primitive, the same "no signal, no gate" trade-off
    every guard in this file makes for its own ordinary/benign shape."""
    assert not _gated(evaluate(_shell("systemd-run /tmp/build.sh"), EMPTY))


def test_launchctl_load_bootstrap_enable_gated():
    assert _gated(evaluate(_shell("launchctl load ~/Library/LaunchAgents/x.plist"), EMPTY))
    assert _gated(evaluate(
        _shell("launchctl bootstrap gui/501 ~/Library/LaunchAgents/x.plist"), EMPTY))
    assert _gated(evaluate(_shell("launchctl enable gui/501/com.evil.agent"), EMPTY))


def test_launchctl_unload_not_gated():
    """Unloading/deactivating is not itself a persistence-installing action."""
    assert not _gated(evaluate(_shell("launchctl unload ~/Library/LaunchAgents/x.plist"), EMPTY))
    assert not _gated(evaluate(_shell("launchctl bootout gui/501/com.evil.agent"), EMPTY))


def test_systemctl_disable_not_gated():
    assert not _gated(evaluate(_shell("systemctl disable evil.service"), EMPTY))


def test_systemctl_start_restart_not_gated():
    """Starting/restarting an already-enabled unit runs it NOW — it doesn't
    change whether the unit persists across a future boot/login, so it's
    outside this guard's "installs persistence" scope, the same way plain
    (unscheduled) `systemd-run` is excluded."""
    assert not _gated(evaluate(_shell("systemctl start evil.service"), EMPTY))
    assert not _gated(evaluate(_shell("systemctl restart evil.service"), EMPTY))


def test_launchctl_submit_and_kickstart_not_gated():
    """launchctl submit runs a command immediately from argv (no plist ever
    written) and kickstart -k restarts an already-loaded job — both an
    IMMEDIATE run, not a persistence-installing one, the same "activation,
    not execution, is what's gated" line plain systemd-run sits on. Disclosed
    gap (independent adversarial review, round A), not a new bypass class."""
    assert not _gated(evaluate(
        _shell("launchctl submit -l com.evil.persist -- /usr/bin/python3 /tmp/evil.py"), EMPTY))
    assert not _gated(evaluate(
        _shell("launchctl kickstart -k gui/501/com.evil.agent"), EMPTY))


# ---- activation-command scan-gap bound (QA round A fix) --------------------------

def test_systemctl_enable_with_long_flag_gated():
    """QA finding (independent adversarial review, round A): the original
    40-char scan-gap bound between `systemctl` and `enable` was crossed by
    an entirely ordinary intervening flag, letting the whole command sail
    through unflagged even with the target path present verbatim in the
    text. Fixed by widening the bound to 200 (the same bound
    _find_predicate_re already uses for an analogous shape)."""
    d = evaluate(_shell(
        "systemctl --root=/mnt/some/very/long/alternate/rootfs/for/testing "
        "enable /etc/systemd/system/evil.service"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


def test_launchctl_load_with_long_flag_gated():
    d = evaluate(_shell(
        "launchctl asuser 501 /bin/launchctl load "
        "~/Library/LaunchAgents/com.evil.agent.plist"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


def test_systemd_run_scheduling_with_long_flag_gated():
    d = evaluate(_shell(
        "systemd-run --description='a totally ordinary, innocuous-looking "
        "description string' --on-calendar=daily /tmp/evil.sh"), EMPTY)
    assert _gated(d) and d.rule == "service-persist-protect"


# ---- false-positive guards --------------------------------------------------------

def test_unrelated_plist_not_gated():
    """Info.plist/entitlements.plist are ordinary, unrelated iOS/macOS project
    files with no LaunchAgents/LaunchDaemons parent — must not fire."""
    assert not _gated(evaluate(_write("MyApp/Info.plist"), EMPTY))
    assert not _gated(evaluate(_write("MyApp/entitlements.plist"), EMPTY))


def test_unrelated_service_file_not_gated():
    assert not _gated(evaluate(_write("src/user.service.ts"), EMPTY))


def test_unrelated_edit_allowed():
    assert not _gated(evaluate(_edit("src/app.py"), EMPTY))
    assert not _gated(evaluate(_write("README.md"), EMPTY))


def test_commit_message_mention_not_gated():
    assert not _gated(evaluate(
        _shell('git commit -m "document systemd unit deploy steps"'), EMPTY))


def test_find_fallback_excludes_bare_extensions():
    """Bare `.plist`/`.timer`/`.service` extensions are too generic to safely
    use as find-predicate fallback fragments — same trade-off
    SHELL_PERSIST_FIND_RE's docstring accepts for "config"/"profile"."""
    from aegis import patterns
    assert not patterns.service_persist_find_hit("find . -name '*.plist'")
    assert not patterns.service_persist_find_hit("find . -name '*.service'")


# ---- escape hatches: human-only --------------------------------------------------

def test_human_can_override_shell_with_comment():
    assert not _gated(evaluate(
        _shell("systemctl enable trusted.service  # aegis-allow"), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(
        _shell("systemctl enable evil.service  # aegis-allow"), EMPTY))


def test_env_toggle_allows_edit_and_shell(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_SERVICE_PERSIST", "1")
    assert not _gated(evaluate(_write("/etc/systemd/system/evil.service"), EMPTY))
    assert not _gated(evaluate(_shell("systemctl enable evil.service"), EMPTY))


# ---- modes: ask (default) / deny / monitor / off ----------------------------------

def test_default_mode_is_ask():
    d = evaluate(_write("/etc/systemd/system/evil.service"), EMPTY)
    assert d.action == Action.ASK and d.rule == "service-persist-protect"
    d2 = evaluate(_shell("systemctl enable evil.service"), EMPTY)
    assert d2.action == Action.ASK and d2.rule == "service-persist-protect"


def test_deny_mode_hard_blocks():
    d = evaluate(_write("/etc/systemd/system/evil.service"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == "service-persist-protect"


def test_monitor_mode_logs_and_allows():
    pol = Policy(service_persist={"mode": "monitor"})
    assert not _gated(evaluate(_write("/etc/systemd/system/evil.service"), pol))
    assert not _gated(evaluate(_shell("systemctl enable evil.service"), pol))


def test_off_mode_disables_guard():
    pol = Policy(service_persist={"mode": "off"})
    assert not _gated(evaluate(_write("/etc/systemd/system/evil.service"), pol))


def test_mode_off_unquoted_yaml_boolean_disables_guard():
    """YAML 1.1 parses an unquoted `off` as boolean False — the guard must
    still recognize it as 'disabled', the same fix every sibling *_protect
    guard already applies for its own `mode` knob."""
    pol = Policy(service_persist={"mode": False})
    assert not _gated(evaluate(_write("/etc/systemd/system/evil.service"), pol))


def test_policy_allow_regex_exempts_trusted_path():
    pol = Policy(service_persist={"allow": [r"deploy/systemd/system/evil\.service"]})
    assert not _gated(evaluate(_write("deploy/systemd/system/evil.service"), pol))
    assert _gated(evaluate(_write("/etc/systemd/system/evil.service"), pol))


def test_policy_allow_regex_exempts_trusted_shell_command():
    pol = Policy(service_persist={"allow": [r"trusted-deploy\.sh"]})
    assert not _gated(evaluate(_shell("bash trusted-deploy.sh && systemctl enable app.service"), pol))
    assert _gated(evaluate(_shell("systemctl enable evil.service"), pol))


# ---- performance / ReDoS ----------------------------------------------------------

def test_no_quadratic_blowup_on_adversarial_input():
    from aegis import patterns
    adversarial = "systemd/system/evil.service" * 8000
    start = time.time()
    patterns.SYSTEMD_UNIT_PATH_RE.search(adversarial)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"SYSTEMD_UNIT_PATH_RE took {elapsed:.2f}s on adversarial input"

    start = time.time()
    patterns.LAUNCHD_PLIST_PATH_RE.search("LaunchAgents/x.plist" * 8000)
    elapsed2 = time.time() - start
    assert elapsed2 < 1.0, f"LAUNCHD_PLIST_PATH_RE took {elapsed2:.2f}s on adversarial input"


def test_find_re_no_quadratic_blowup():
    from aegis import patterns
    adversarial = "find . -name x " * 8000
    start = time.time()
    patterns.service_persist_find_hit(adversarial)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"service_persist_find_hit took {elapsed:.2f}s on adversarial input"


def test_activate_re_no_quadratic_blowup():
    from aegis import patterns
    adversarial = "systemctl status x; " * 8000
    start = time.time()
    patterns.SERVICE_ACTIVATE_CMD_RE.search(adversarial)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"SERVICE_ACTIVATE_CMD_RE took {elapsed:.2f}s on adversarial input"


def test_engine_no_quadratic_blowup():
    cmd = "find . -name x " * 8000
    start = time.time()
    evaluate(_shell(cmd), EMPTY)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"rule_service_persist_protect took {elapsed:.2f}s on adversarial find input"


def test_activate_re_no_blowup_at_widened_bound():
    """The 200-char scan-gap widening (QA round A fix) must stay linear-time
    — a bounded gap, not an unbounded/nested quantifier, so this must not
    regress into the same shape FIND_WORD_RE's own comment documents as
    having bitten this file's guards before."""
    from aegis import patterns
    adversarial = "systemctl status x; " * 8000
    start = time.time()
    patterns.SERVICE_ACTIVATE_CMD_RE.search(adversarial)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"SERVICE_ACTIVATE_CMD_RE took {elapsed:.2f}s at the widened bound"

    start = time.time()
    patterns.SERVICE_ACTIVATE_CMD_RE.search("systemctl " + "x" * 200000)
    elapsed2 = time.time() - start
    assert elapsed2 < 1.0, f"SERVICE_ACTIVATE_CMD_RE took {elapsed2:.2f}s on a long non-match tail"


# ---- cross-guard sanity: no accidental overlap with git-config-exec --------------

def test_no_overlap_with_git_config_exec_bang_value_guard():
    """rule_git_config_exec_protect's QA history (round A) disclosed that a
    systemd unit's `ExecStart=!...` line could false-positive its bang-value
    INI check before it was scoped to git's own section vocabulary. Confirms
    a real systemd unit path with that exact content trips ONLY this guard,
    not git-config-exec, through the full evaluate() pipeline."""
    d = evaluate(_write("/etc/systemd/system/evil.service",
                         content="[Service]\nExecStart=!/usr/bin/evil.sh\n"), EMPTY)
    assert d.rule == "service-persist-protect"
