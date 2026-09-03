"""Cron persistence protection guard — blocks planting/altering a cron file:
``/etc/cron.d/*``, ``/etc/cron.{hourly,daily,weekly,monthly}/*``,
``/etc/crontab``, ``/etc/anacrontab``, or a user's spool crontab
(``/var/spool/cron/crontabs/<user>`` on Debian/Ubuntu, ``/var/spool/cron/
<user>`` on RHEL/Fedora).

The last major Unix scheduling/auto-run primitive with no coverage anywhere
in this file before this guard: ``PERSIST_RE`` (``rule_containment``) scans
SHELL text only (never an Edit/Write/MCP event's path/content — see
``rule_containment``'s own ``_is_shell(ev) and patterns.PERSIST_RE...``
gate), and even from a shell it has no alternative at all for a spool
crontab written directly, bypassing the ``crontab`` CLI its own
``\\bcrontab\\b`` check watches for.

Default mode is ``ask`` (not ``deny``) — shipping a cron job for a backup/
cleanup task is routine, sanctioned work. A dedicated ``mode: deny`` policy
is used below to test the stricter posture explicitly.

Because ``rule_containment`` runs before this guard in ``_CORE_RULES`` and
already denies, non-escapably, any shell command mentioning the bare word
``crontab`` or the literal substring ``/etc/cron``, a shell command touching
``/etc/cron.d``/``/etc/cron.daily``/etc. is intercepted there first — this
guard's own shell branch is exercised end-to-end only by the surface
containment's ``PERSIST_RE`` does NOT reach: a user's spool crontab.
"""
import time

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                       # default mode: ask
DENY = Policy(cron_persist={"mode": "deny"})            # stricter, hard-block posture


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


# ---- cron files, via Edit/Write --------------------------------------------

def test_cron_d_file_gated():
    d = evaluate(_write("/etc/cron.d/evil"), EMPTY)
    assert _gated(d) and d.rule == "cron-persist-protect"


def test_cron_schedule_dirs_gated():
    for name in ("hourly", "daily", "weekly", "monthly"):
        d = evaluate(_write(f"/etc/cron.{name}/evil.sh"), EMPTY)
        assert _gated(d) and d.rule == "cron-persist-protect", name


def test_etc_crontab_gated():
    d = evaluate(_edit("/etc/crontab"), EMPTY)
    assert _gated(d) and d.rule == "cron-persist-protect"


def test_etc_anacrontab_gated():
    d = evaluate(_write("/etc/anacrontab"), EMPTY)
    assert _gated(d) and d.rule == "cron-persist-protect"


def test_debian_spool_crontab_gated():
    d = evaluate(_write("/var/spool/cron/crontabs/root"), EMPTY)
    assert _gated(d) and d.rule == "cron-persist-protect"


def test_rhel_spool_crontab_gated():
    d = evaluate(_write("/var/spool/cron/root"), EMPTY)
    assert _gated(d) and d.rule == "cron-persist-protect"


# ---- MCP-tool writes --------------------------------------------------------

def test_mcp_tool_write_to_cron_d_gated():
    d = evaluate(_mcp_write("/etc/cron.d/evil"), EMPTY)
    assert _gated(d) and d.rule == "cron-persist-protect"


def test_mcp_tool_alternate_path_arg_keys_gated():
    for key in ("target_file", "targetFile", "filename", "file", "uri"):
        d = evaluate(_mcp_write_arg(key, "/var/spool/cron/crontabs/root"), EMPTY)
        assert _gated(d) and d.rule == "cron-persist-protect", key


# ---- shell-based mutation: the spool crontab (not reached by PERSIST_RE) --

def test_shell_redirect_to_spool_crontab_gated():
    d = evaluate(_shell("echo '* * * * * root /tmp/evil.sh' >> "
                         "/var/spool/cron/crontabs/root"), EMPTY)
    assert _gated(d) and d.rule == "cron-persist-protect"


def test_shell_rhel_spool_redirect_gated():
    d = evaluate(_shell("echo '* * * * * /tmp/evil.sh' >> /var/spool/cron/root"), EMPTY)
    assert _gated(d) and d.rule == "cron-persist-protect"


def test_shell_copy_to_spool_crontab_gated():
    d = evaluate(_shell("cp evil_cron /var/spool/cron/crontabs/root"), EMPTY)
    assert _gated(d) and d.rule == "cron-persist-protect"


def test_shell_inplace_edit_spool_crontab_gated():
    d = evaluate(_shell("sed -i 's/x/evil/' /var/spool/cron/crontabs/root"), EMPTY)
    assert _gated(d) and d.rule == "cron-persist-protect"


def test_shell_forced_symlink_swap_spool_crontab_gated():
    d = evaluate(_shell("ln -sf evil_cron /var/spool/cron/crontabs/root"), EMPTY)
    assert _gated(d) and d.rule == "cron-persist-protect"


def test_shell_read_only_spool_not_gated():
    assert not _gated(evaluate(_shell("cat /var/spool/cron/crontabs/root"), EMPTY))
    assert not _gated(evaluate(_shell("ls /var/spool/cron/crontabs"), EMPTY))


def test_find_path_indirection_spool_gated():
    d = evaluate(_shell("cp evil_cron $(find / -path '*spool/cron*')"), EMPTY)
    assert _gated(d) and d.rule == "cron-persist-protect"


def test_rsync_to_cron_d_dir_gated():
    """Bare directory reference — CRON_DIR_RE, paired with an archive/sync verb.
    Note: unlike the spool tests above, this path ALSO matches containment's
    PERSIST_RE ('/etc/cron' substring), which runs first and wins — see the
    cross-guard overlap test below."""
    d = evaluate(_shell("rsync -a evil/ /etc/cron.d/"), EMPTY)
    assert _gated(d)


def test_bare_dir_gated_only_with_verb():
    assert not _gated(evaluate(_shell("ls /var/spool/cron/crontabs"), EMPTY))
    d = evaluate(_shell("rsync -a evil/ /var/spool/cron/crontabs"), EMPTY)
    assert _gated(d) and d.rule == "cron-persist-protect"


# ---- path-separator / Windows-trim bypass (same class as sibling guards) ---

def test_doubled_separator_does_not_bypass():
    for path in (
        "/var/spool//cron/crontabs/root",
        "/var/spool/./cron/crontabs/root",
        "var/spool/cron//crontabs/root",
    ):
        d = evaluate(_write(path), EMPTY)
        assert _gated(d) and d.rule == "cron-persist-protect", path


def test_windows_trailing_dot_does_not_bypass():
    d = evaluate(_write("var./spool/cron/crontabs/root"), EMPTY)
    assert _gated(d) and d.rule == "cron-persist-protect"


def test_etc_doubled_slash_shell_form_does_not_bypass():
    d = evaluate(_shell(
        "echo '* * * * * evil' >> /var/spool//cron/crontabs/root"), EMPTY)
    assert _gated(d) and d.rule == "cron-persist-protect"


# ---- false-positive guards --------------------------------------------------

def test_unrelated_path_not_gated():
    assert not _gated(evaluate(_write("src/app.py"), EMPTY))
    assert not _gated(evaluate(_write("README.md"), EMPTY))
    assert not _gated(evaluate(_write("/etc/cron.dxyz/notreal"), EMPTY))
    assert not _gated(evaluate(_write("/etc/crontabsomethingelse"), EMPTY))


def test_find_fallback_excludes_bare_crontab_word():
    """The bare word 'crontab'/'crontabs' is deliberately excluded from the
    find-fallback fragments — PERSIST_RE already denies any shell text
    containing it non-escapably regardless of `find` syntax, so this guard
    would never even be reached for that case."""
    from aegis import patterns
    assert not patterns.cron_find_hit("find . -name crontab")


# ---- escape hatches: human-only ---------------------------------------------

def test_human_can_override_shell_with_comment():
    assert not _gated(evaluate(
        _shell("cp trusted_cron /var/spool/cron/crontabs/root  # aegis-allow"), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(
        _shell("cp evil_cron /var/spool/cron/crontabs/root  # aegis-allow"), EMPTY))


def test_env_toggle_allows_edit_and_shell(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CRON_PERSIST", "1")
    assert not _gated(evaluate(_write("/etc/cron.d/evil"), EMPTY))
    assert not _gated(evaluate(
        _shell("cp evil_cron /var/spool/cron/crontabs/root"), EMPTY))


# ---- modes: ask (default) / deny / monitor / off ----------------------------

def test_default_mode_is_ask():
    d = evaluate(_write("/etc/cron.d/evil"), EMPTY)
    assert d.action == Action.ASK and d.rule == "cron-persist-protect"
    d2 = evaluate(_shell("cp evil_cron /var/spool/cron/crontabs/root"), EMPTY)
    assert d2.action == Action.ASK and d2.rule == "cron-persist-protect"


def test_deny_mode_hard_blocks():
    d = evaluate(_write("/etc/cron.d/evil"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == "cron-persist-protect"


def test_monitor_mode_logs_and_allows():
    pol = Policy(cron_persist={"mode": "monitor"})
    assert not _gated(evaluate(_write("/etc/cron.d/evil"), pol))
    assert not _gated(evaluate(
        _shell("cp evil_cron /var/spool/cron/crontabs/root"), pol))


def test_off_mode_disables_guard():
    pol = Policy(cron_persist={"mode": "off"})
    assert not _gated(evaluate(_write("/etc/cron.d/evil"), pol))


def test_mode_off_unquoted_yaml_boolean_disables_guard():
    """YAML 1.1 parses an unquoted `off` as boolean False — the guard must
    still recognize it as 'disabled', the same fix every sibling *_protect
    guard already applies for its own `mode` knob."""
    pol = Policy(cron_persist={"mode": False})
    assert not _gated(evaluate(_write("/etc/cron.d/evil"), pol))


def test_policy_allow_regex_exempts_trusted_path():
    pol = Policy(cron_persist={"allow": [r"deploy/cron\.d/backup"]})
    assert not _gated(evaluate(_write("deploy/cron.d/backup"), pol))
    assert _gated(evaluate(_write("/etc/cron.d/evil"), pol))


def test_policy_allow_regex_exempts_trusted_shell_command():
    pol = Policy(cron_persist={"allow": [r"trusted-deploy\.sh"]})
    assert not _gated(evaluate(
        _shell("bash trusted-deploy.sh && "
               "cp backup_cron /var/spool/cron/crontabs/root"), pol))
    assert _gated(evaluate(
        _shell("cp evil_cron /var/spool/cron/crontabs/root"), pol))


# ---- cross-guard sanity: containment fires first for /etc/cron* shell text -

def test_etc_cron_shell_mention_intercepted_by_containment_first():
    """rule_containment's PERSIST_RE runs before this guard in _CORE_RULES
    and already denies, non-escapably, any shell command mentioning the
    literal substring '/etc/cron' — confirms that overlap resolves to
    containment, not a double-gate or a silent miss."""
    d = evaluate(_shell("echo '* * * * * evil' >> /etc/cron.d/evil"), EMPTY)
    assert _gated(d) and d.rule == "containment-persistence"


def test_crontab_command_intercepted_by_containment_first():
    d = evaluate(_shell("crontab -u root evil_cron"), EMPTY)
    assert _gated(d) and d.rule == "containment-persistence"


# ---- performance / ReDoS ----------------------------------------------------

def test_no_quadratic_blowup_on_adversarial_input():
    from aegis import patterns
    adversarial = "var/spool/cron/crontabs/root" * 8000
    start = time.time()
    patterns.CRON_FILE_PATH_RE.search(adversarial)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"CRON_FILE_PATH_RE took {elapsed:.2f}s on adversarial input"


def test_find_re_no_quadratic_blowup():
    from aegis import patterns
    adversarial = "find . -name x " * 8000
    start = time.time()
    patterns.cron_find_hit(adversarial)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"cron_find_hit took {elapsed:.2f}s on adversarial input"


def test_engine_no_quadratic_blowup():
    cmd = "find . -name x " * 8000
    start = time.time()
    evaluate(_shell(cmd), EMPTY)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"rule_cron_persist_protect took {elapsed:.2f}s on adversarial find input"
