"""Anti-forensics protection guard — blocks clearing/disabling interactive-
shell command history or the OS-level audit/auth trail (login accounting,
the kernel audit framework, system event logs).

THREAT MODEL: after a harmful action, a rogue or prompt-injected agent's next
move is often not to repeat it but to cover its tracks — clear the shell's
own command history, or clear/disable the OS-level log a human incident-
responder would reach for during a post-hoc review. Self-protection already
denies tampering with Aegis's OWN ``~/.aegis/audit.jsonl``, but nothing else
in ``rules.py`` named a shell-history or system-log path before this guard —
MITRE ATT&CK's "Indicator Removal" family (T1070.001/.002/.003).

Default mode is ``ask`` (not ``deny``), the same posture every sibling
``*_protect`` guard uses — a dedicated ``mode: deny`` policy is used below to
test the stricter posture explicitly.
"""
import time

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                              # default mode: ask
DENY = Policy(history_tamper={"mode": "deny"})                 # stricter, hard-block posture


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _edit(path, tool="Edit"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args={"file_path": path})


def _gated(d) -> bool:
    return d.action != Action.ALLOW


# ---- shell command-history clearing/disabling --------------------------------

def test_history_dash_c_gated():
    d = evaluate(_shell("history -c"), EMPTY)
    assert _gated(d) and d.rule == "history-tamper-protect"


def test_history_clear_long_flag_gated():
    assert _gated(evaluate(_shell("history --clear"), EMPTY))


def test_history_cw_gated():
    assert _gated(evaluate(_shell("history -cw"), EMPTY))


def test_unset_histfile_gated():
    d = evaluate(_shell("unset HISTFILE"), EMPTY)
    assert _gated(d) and d.rule == "history-tamper-protect"


def test_histfile_devnull_gated():
    assert _gated(evaluate(_shell("export HISTFILE=/dev/null"), EMPTY))
    assert _gated(evaluate(_shell("HISTFILE=/dev/null"), EMPTY))


def test_histfile_emptied_gated():
    assert _gated(evaluate(_shell("HISTFILE="), EMPTY))
    assert _gated(evaluate(_shell("export HISTFILE=''"), EMPTY))


def test_histsize_zeroed_gated():
    assert _gated(evaluate(_shell("HISTSIZE=0"), EMPTY))
    assert _gated(evaluate(_shell("export HISTFILESIZE=0"), EMPTY))


def test_set_plus_o_history_gated():
    d = evaluate(_shell("set +o history"), EMPTY)
    assert _gated(d) and d.rule == "history-tamper-protect"


def test_zsh_unsetopt_history_gated():
    assert _gated(evaluate(_shell("unsetopt histappend"), EMPTY))


def test_powershell_clear_history_gated():
    d = evaluate(_shell("Clear-History"), EMPTY)
    assert _gated(d) and d.rule == "history-tamper-protect"


def test_powershell_disable_psreadline_save_gated():
    d = evaluate(_shell("Set-PSReadLineOption -HistorySaveStyle SaveNothing"), EMPTY)
    assert _gated(d) and d.rule == "history-tamper-protect"


# ---- shell-history FILE tampering ---------------------------------------------

def test_delete_bash_history_gated():
    assert _gated(evaluate(_shell("rm ~/.bash_history"), EMPTY))
    assert _gated(evaluate(_shell("rm -f ~/.bash_history"), EMPTY))


def test_delete_zsh_history_gated():
    assert _gated(evaluate(_shell("rm ~/.zsh_history"), EMPTY))


def test_delete_fish_history_gated():
    d = evaluate(_shell("rm ~/.local/share/fish/fish_history"), EMPTY)
    assert _gated(d) and d.rule == "history-tamper-protect"


def test_delete_powershell_history_gated():
    d = evaluate(_shell("Remove-Item ConsoleHost_history.txt"), EMPTY)
    assert _gated(d) and d.rule == "history-tamper-protect"


def test_truncate_via_redirect_gated():
    assert _gated(evaluate(_shell("> ~/.bash_history"), EMPTY))
    assert _gated(evaluate(_shell("cat /dev/null > ~/.zsh_history"), EMPTY))


def test_shred_history_gated():
    d = evaluate(_shell("shred -u ~/.bash_history"), EMPTY)
    assert _gated(d) and d.rule == "history-tamper-protect"


def test_inplace_edit_history_gated():
    d = evaluate(_shell("sed -i '/secret/d' ~/.bash_history"), EMPTY)
    assert _gated(d) and d.rule == "history-tamper-protect"


def test_move_history_gated():
    assert _gated(evaluate(_shell("mv ~/.bash_history /tmp/gone"), EMPTY))


def test_forced_symlink_to_devnull_gated():
    """QA finding (independent adversarial review, bypass-hunting round): a
    forced `ln -sf /dev/null <target>` swaps the history/log file for a
    symlink into the void with no delete/redirect/in-place-edit verb ever
    appearing — closed by adding FORCED_LINK_WRITE_RE (already used by
    rule_ld_preload_protect and others for the identical shape) to this
    guard's own touches-target checks."""
    assert _gated(evaluate(_shell("ln -sf /dev/null ~/.bash_history"), EMPTY))
    assert _gated(evaluate(_shell("ln -sf /dev/null /var/log/wtmp"), EMPTY))


def test_unforced_symlink_not_gated():
    """Disclosed, accepted gap: a bare `ln -s` (no -f/--force) refuses to
    overwrite a target that already exists, so it's not treated as a
    mutation — the same trade-off FORCED_LINK_WRITE_RE's other callers
    (e.g. rule_ld_preload_protect) already accept."""
    assert not _gated(evaluate(_shell("ln -s /dev/null ~/.bash_history"), EMPTY))


def test_read_only_history_not_gated():
    assert not _gated(evaluate(_shell("cat ~/.bash_history"), EMPTY))
    assert not _gated(evaluate(_shell("grep ssh ~/.bash_history"), EMPTY))
    assert not _gated(evaluate(_shell("less ~/.zsh_history"), EMPTY))


# ---- system audit/auth-trail tampering ----------------------------------------

def test_auditctl_disable_gated():
    d = evaluate(_shell("auditctl -e 0"), EMPTY)
    assert _gated(d) and d.rule == "history-tamper-protect"


def test_systemctl_stop_auditd_gated():
    assert _gated(evaluate(_shell("systemctl stop auditd"), EMPTY))
    assert _gated(evaluate(_shell("systemctl disable auditd"), EMPTY))
    assert _gated(evaluate(_shell("systemctl mask auditd"), EMPTY))


def test_service_auditd_stop_gated():
    d = evaluate(_shell("service auditd stop"), EMPTY)
    assert _gated(d) and d.rule == "history-tamper-protect"


def test_journalctl_vacuum_gated():
    assert _gated(evaluate(_shell("journalctl --vacuum-time=1s"), EMPTY))
    assert _gated(evaluate(_shell("journalctl --vacuum-size=1K"), EMPTY))


def test_wevtutil_clear_gated():
    assert _gated(evaluate(_shell("wevtutil cl Security"), EMPTY))
    assert _gated(evaluate(_shell("wevtutil clear-log Application"), EMPTY))


def test_powershell_clear_eventlog_gated():
    d = evaluate(_shell("Clear-EventLog -LogName Security"), EMPTY)
    assert _gated(d) and d.rule == "history-tamper-protect"


def test_delete_wtmp_btmp_utmp_gated():
    assert _gated(evaluate(_shell("rm /var/log/wtmp"), EMPTY))
    assert _gated(evaluate(_shell("> /var/log/btmp"), EMPTY))
    assert _gated(evaluate(_shell("rm /var/run/utmp"), EMPTY))


def test_delete_auth_log_gated():
    assert _gated(evaluate(_shell("rm /var/log/auth.log"), EMPTY))
    assert _gated(evaluate(_shell("> /var/log/secure"), EMPTY))


def test_delete_audit_log_gated():
    d = evaluate(_shell("rm /var/log/audit/audit.log"), EMPTY)
    assert _gated(d) and d.rule == "history-tamper-protect"


def test_auditd_service_read_only_not_gated():
    assert not _gated(evaluate(_shell("systemctl status auditd"), EMPTY))
    assert not _gated(evaluate(_shell("journalctl -u auditd"), EMPTY))


def test_cd_then_bare_accounting_filename_gated():
    """QA finding (independent adversarial review, bypass-hunting round):
    unlike SHELL_HISTORY_PATH_RE, AUDIT_LOG_PATH_RE required the literal
    'var/log/' path prefix in the same token, so `cd /var/log && rm wtmp`
    slipped through with no path match at all — closed by adding a
    bare-filename fallback for the four names distinctive enough to
    bare-match safely (wtmp/btmp/utmp/lastlog)."""
    assert _gated(evaluate(_shell("cd /var/log && rm wtmp"), EMPTY))
    assert _gated(evaluate(_shell("cd /var/log && rm -f btmp"), EMPTY))
    assert _gated(evaluate(_shell("cd /var/run && rm utmp"), EMPTY))
    assert _gated(evaluate(_shell("cd /var/log && > lastlog"), EMPTY))


def test_bare_generic_audit_names_excluded_by_design():
    """'auth.log'/'secure'/'audit.log' are deliberately excluded from the
    bare-filename fallback -- each is a plausible name for a project's OWN
    log/config file, too generic to bare-match without the 'var/log/' path
    context. Verified directly against the pattern, not the full guard,
    since an unrelated project file legitimately named this way must stay
    allowed even outside a matched shell command."""
    from aegis import patterns
    assert not patterns.AUDIT_LOG_PATH_RE.search("cd /var/log && rm auth.log")
    assert not patterns.AUDIT_LOG_PATH_RE.search("cd /var/log && rm secure")


# ---- false-positive guards -----------------------------------------------------

def test_unrelated_history_mention_not_gated():
    assert not _gated(evaluate(
        _shell("git commit -m 'document bash history behavior'"), EMPTY))
    assert not _gated(evaluate(_shell("cat notes/history.md"), EMPTY))
    assert not _gated(evaluate(_shell("echo 'this is a history lesson'"), EMPTY))


def test_unrelated_log_not_gated():
    assert not _gated(evaluate(_shell("rm /var/log/nginx/access.log"), EMPTY))
    assert not _gated(evaluate(_shell("cat /var/log/syslog"), EMPTY))


def test_custom_histfile_not_gated():
    assert not _gated(evaluate(_shell("HISTFILE=/tmp/custom_history bash"), EMPTY))


def test_unrelated_shell_not_gated():
    assert not _gated(evaluate(_shell("echo hello world"), EMPTY))
    assert not _gated(evaluate(_shell("ls -la"), EMPTY))


def test_unrelated_edit_not_gated():
    assert not _gated(evaluate(_edit("src/app.py"), EMPTY))


# ---- escape hatches: human-only -------------------------------------------------

def test_human_can_override_with_comment():
    assert not _gated(evaluate(_shell("history -c  # aegis-allow"), EMPTY))


def test_agent_cannot_override_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(_shell("history -c  # aegis-allow"), EMPTY))


def test_env_toggle_allows_shell(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_HISTORY_TAMPER", "1")
    assert not _gated(evaluate(_shell("history -c"), EMPTY))
    assert not _gated(evaluate(_shell("rm ~/.bash_history"), EMPTY))
    assert not _gated(evaluate(_shell("auditctl -e 0"), EMPTY))


# ---- modes: ask (default) / deny / monitor / off --------------------------------

def test_default_mode_is_ask():
    d = evaluate(_shell("history -c"), EMPTY)
    assert d.action == Action.ASK and d.rule == "history-tamper-protect"


def test_deny_mode_hard_blocks():
    d = evaluate(_shell("history -c"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == "history-tamper-protect"


def test_monitor_mode_logs_and_allows():
    pol = Policy(history_tamper={"mode": "monitor"})
    assert not _gated(evaluate(_shell("history -c"), pol))
    assert not _gated(evaluate(_shell("rm ~/.bash_history"), pol))


def test_off_mode_disables_guard():
    pol = Policy(history_tamper={"mode": "off"})
    assert not _gated(evaluate(_shell("history -c"), pol))


def test_mode_off_unquoted_yaml_boolean_disables_guard():
    """YAML 1.1 parses an unquoted `off` as boolean False — the guard must
    still recognize it as 'disabled', the same fix every sibling *_protect
    guard already applies for its own `mode` knob."""
    pol = Policy(history_tamper={"mode": False})
    assert not _gated(evaluate(_shell("history -c"), pol))


def test_policy_allow_regex_exempts_trusted_command():
    pol = Policy(history_tamper={"allow": [r"trusted-log-rotate\.sh"]})
    assert not _gated(evaluate(
        _shell("bash trusted-log-rotate.sh && rm ~/.bash_history"), pol))
    assert _gated(evaluate(_shell("rm ~/.bash_history"), pol))


# ---- performance / ReDoS --------------------------------------------------------

def test_no_quadratic_blowup_on_adversarial_input():
    from aegis import patterns
    adversarial = "history -c " * 8000
    start = time.time()
    patterns.HISTORY_CLEAR_CMD_RE.search(adversarial)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"HISTORY_CLEAR_CMD_RE took {elapsed:.2f}s on adversarial input"

    start = time.time()
    patterns.SHELL_HISTORY_PATH_RE.search(".bash_history " * 8000)
    elapsed2 = time.time() - start
    assert elapsed2 < 1.0, f"SHELL_HISTORY_PATH_RE took {elapsed2:.2f}s on adversarial input"

    start = time.time()
    patterns.AUDIT_LOG_DISABLE_CMD_RE.search("systemctl stop auditd " * 8000)
    elapsed3 = time.time() - start
    assert elapsed3 < 1.0, f"AUDIT_LOG_DISABLE_CMD_RE took {elapsed3:.2f}s on adversarial input"


def test_engine_no_quadratic_blowup():
    cmd = "history -c " * 8000
    start = time.time()
    evaluate(_shell(cmd), EMPTY)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"rule_history_tamper_protect took {elapsed:.2f}s on adversarial input"
