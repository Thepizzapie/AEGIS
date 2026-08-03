"""Environment-variable persistence protection guard — blocks planting/
altering ``/etc/environment``, ``~/.pam_environment``,
``/etc/security/pam_env.conf``, or a systemd ``environment.d`` drop-in
(``~/.config/environment.d/*.conf``, ``/etc/environment.d/*.conf``), and the
``launchctl setenv``/``systemctl set-environment``-style activation commands
that inject a variable straight into a running session/service manager with
no file write at all.

Reached by no existing guard: these files/commands are all read/exported by
PAM's ``pam_env`` module or the systemd user/system manager into EVERY
process started afterward, with no interactive-shell trigger required (unlike
``rule_shell_persist_protect``'s ``.bashrc`` half) — a stock PAM stack applies
``pam_env`` even to a non-interactive ``ssh host cmd``, and ``environment.d``
is read at login by the systemd manager and exported into every unit it
subsequently starts.

Default mode is ``ask`` (not ``deny``) — adding a `JAVA_HOME=`/proxy variable
to ``/etc/environment`` is routine, sanctioned sysadmin work. A dedicated
``mode: deny`` policy is used below to test the stricter posture explicitly.
"""
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                       # default mode: ask
DENY = Policy(env_persist={"mode": "deny"})             # stricter, hard-block posture


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


# ---- target files, via Edit/Write ------------------------------------------

def test_etc_environment_gated():
    d = evaluate(_write("/etc/environment"), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


def test_pam_environment_home_gated():
    d = evaluate(_edit("~/.pam_environment"), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


def test_etc_pam_env_conf_gated():
    d = evaluate(_write("/etc/security/pam_env.conf"), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


def test_user_environment_d_dropin_gated():
    d = evaluate(_write("~/.config/environment.d/10-custom.conf"), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


def test_system_environment_d_dropin_gated():
    d = evaluate(_write("/etc/environment.d/50-evil.conf"), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


# ---- MCP-tool writes ---------------------------------------------------------

def test_mcp_tool_write_to_etc_environment_gated():
    d = evaluate(_mcp_write("/etc/environment"), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


def test_mcp_tool_alternate_path_arg_keys_gated():
    for key in ("target_file", "targetFile", "filename", "file", "uri"):
        d = evaluate(_mcp_write_arg(key, "~/.config/environment.d/10-evil.conf"), EMPTY)
        assert _gated(d) and d.rule == "env-persist-protect", key


# ---- shell-based mutation -----------------------------------------------------

def test_shell_redirect_to_etc_environment_gated():
    assert _gated(evaluate(
        _shell("echo 'LD_PRELOAD=/tmp/evil.so' >> /etc/environment"), EMPTY))
    assert _gated(evaluate(
        _shell("cat evil.conf | tee ~/.config/environment.d/10-evil.conf"), EMPTY))


def test_shell_delete_gated():
    assert _gated(evaluate(_shell("rm /etc/environment"), EMPTY))


def test_shell_inplace_edit_and_copy_gated():
    assert _gated(evaluate(_shell("sed -i 's/x/evil/' /etc/environment"), EMPTY))
    d = evaluate(_shell("cp evil.conf /etc/environment.d/50-evil.conf"), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


def test_shell_read_only_not_gated():
    assert not _gated(evaluate(_shell("cat /etc/environment"), EMPTY))


def test_find_path_indirection_gated():
    assert _gated(evaluate(
        _shell("cp evil.conf $(find / -path '*environment.d*')"), EMPTY))
    assert _gated(evaluate(
        _shell("mv evil $(find ~ -name pam_environment)"), EMPTY))


def test_forced_symlink_swap_gated():
    d = evaluate(_shell("ln -sf /tmp/evil /etc/environment"), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


def test_rsync_to_environment_d_dir_gated():
    d = evaluate(_shell("rsync -a evil/ ~/.config/environment.d/"), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


def test_tar_extract_to_environment_d_dir_gated():
    d = evaluate(_shell("tar xf payload.tar -C /etc/environment.d/"), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


def test_bare_dir_gated_only_with_verb():
    """The bare directory reference alone (no verb) never gates —
    ENV_PERSIST_DIR_RE only matters paired with a write/archive verb."""
    assert not _gated(evaluate(_shell("ls ~/.config/environment.d"), EMPTY))
    d = evaluate(_shell("rsync -a evil/ ~/.config/environment.d"), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


# ---- path-separator / Windows-trim bypass (same class as sibling guards) ----

def test_doubled_separator_does_not_bypass():
    for path in (
        "/etc//environment",
        "/etc/./environment",
        "etc/security//pam_env.conf",
    ):
        d = evaluate(_write(path), EMPTY)
        assert _gated(d) and d.rule == "env-persist-protect", path


def test_etc_doubled_slash_shell_form_does_not_bypass():
    d = evaluate(_shell("echo 'BASH_ENV=/tmp/evil.sh' >> /etc//environment"), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


# ---- activation commands: no file write needed ------------------------------

def test_launchctl_setenv_gated():
    d = evaluate(_shell("launchctl setenv DYLD_INSERT_LIBRARIES /tmp/evil.dylib"), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


def test_systemctl_set_environment_gated():
    d = evaluate(_shell("systemctl set-environment LD_PRELOAD=/tmp/evil.so"), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


def test_systemctl_user_set_environment_gated():
    d = evaluate(_shell("systemctl --user set-environment NODE_OPTIONS=--require=/tmp/evil.js"), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


def test_setx_gated():
    """QA finding (independent adversarial review, round A): the Windows
    analog of launchctl setenv/systemctl set-environment. Unlike `set`,
    `setx` has no in-process-only mode — every invocation writes the
    persistent user/machine registry environment store."""
    d = evaluate(_shell("setx LD_PRELOAD C:\\evil\\hijack.dll"), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


def test_reg_add_environment_key_gated():
    d = evaluate(_shell(
        'reg add "HKCU\\Environment" /v BASH_ENV /t REG_SZ /d C:\\evil.bat /f'), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


def test_reg_add_hklm_environment_key_gated():
    d = evaluate(_shell(
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" '
        '/v NODE_OPTIONS /t REG_SZ /d --require=evil.js /f'), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


def test_powershell_set_environment_variable_user_scope_gated():
    d = evaluate(_shell(
        '[Environment]::SetEnvironmentVariable("LD_PRELOAD", "C:\\evil.dll", "User")'), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


def test_powershell_set_environment_variable_machine_scope_gated():
    d = evaluate(_shell(
        "[Environment]::SetEnvironmentVariable('BASH_ENV', 'C:\\evil.bat', 'Machine')"), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


def test_powershell_set_environment_variable_process_scope_not_gated():
    """The "Process" scope is in-memory-only for the current process tree —
    the harmless, non-persistent inverse, the same "activation, not
    execution" line systemctl unset-environment already sits on."""
    assert not _gated(evaluate(_shell(
        '[Environment]::SetEnvironmentVariable("LD_PRELOAD", "C:\\evil.dll", "Process")'), EMPTY))


def test_launchctl_unsetenv_not_gated():
    """The harmless inverse — removing a variable is not itself a
    persistence-installing action."""
    assert not _gated(evaluate(_shell("launchctl unsetenv LD_PRELOAD"), EMPTY))


def test_systemctl_unset_environment_not_gated():
    assert not _gated(evaluate(_shell("systemctl unset-environment LD_PRELOAD"), EMPTY))
    assert not _gated(evaluate(_shell("systemctl --user unset-environment LD_PRELOAD"), EMPTY))


def test_launchctl_setenv_with_long_flag_gated():
    """Same 200-char scan-gap bound SERVICE_ACTIVATE_CMD_RE/
    DIRENV_ACTIVATE_RE already use — an ordinary intervening flag must not
    push the verb outside the window."""
    d = evaluate(_shell(
        "launchctl asuser 501 /bin/launchctl setenv LD_PRELOAD /tmp/evil.dylib"), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


def test_systemctl_set_environment_with_long_flag_gated():
    d = evaluate(_shell(
        "systemctl --root=/mnt/some/very/long/alternate/rootfs/for/testing "
        "set-environment LD_PRELOAD=/tmp/evil.so"), EMPTY)
    assert _gated(d) and d.rule == "env-persist-protect"


# ---- false-positive guards ---------------------------------------------------

def test_unrelated_environment_source_file_not_gated():
    """An ordinary project's own environment.py/environment.rb carries no
    PAM/systemd-specific signal — the bare word "environment" is deliberately
    excluded from the find-indirection fallback."""
    assert not _gated(evaluate(_write("src/environment.py"), EMPTY))
    assert not _gated(evaluate(_write("config/environment.rb"), EMPTY))


def test_unrelated_edit_allowed():
    assert not _gated(evaluate(_edit("src/app.py"), EMPTY))
    assert not _gated(evaluate(_write("README.md"), EMPTY))


def test_commit_message_mention_not_gated():
    assert not _gated(evaluate(
        _shell('git commit -m "document /etc/environment provisioning"'), EMPTY))


def test_find_fallback_excludes_bare_environment_word():
    from aegis import patterns
    assert not patterns.env_persist_find_hit("find . -name 'environment*'")


# ---- escape hatches: human-only -----------------------------------------------

def test_human_can_override_shell_with_comment():
    assert not _gated(evaluate(
        _shell("systemctl set-environment TRUSTED=1  # aegis-allow"), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(
        _shell("systemctl set-environment LD_PRELOAD=/tmp/evil.so  # aegis-allow"), EMPTY))


def test_env_toggle_allows_edit_and_shell(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_ENV_PERSIST", "1")
    assert not _gated(evaluate(_write("/etc/environment"), EMPTY))
    assert not _gated(evaluate(_shell("launchctl setenv LD_PRELOAD /tmp/evil.dylib"), EMPTY))


# ---- modes: ask (default) / deny / monitor / off ------------------------------

def test_default_mode_is_ask():
    d = evaluate(_write("/etc/environment"), EMPTY)
    assert d.action == Action.ASK and d.rule == "env-persist-protect"
    d2 = evaluate(_shell("launchctl setenv LD_PRELOAD /tmp/evil.dylib"), EMPTY)
    assert d2.action == Action.ASK and d2.rule == "env-persist-protect"


def test_deny_mode_hard_blocks():
    d = evaluate(_write("/etc/environment"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == "env-persist-protect"


def test_monitor_mode_logs_and_allows():
    pol = Policy(env_persist={"mode": "monitor"})
    assert not _gated(evaluate(_write("/etc/environment"), pol))
    assert not _gated(evaluate(_shell("systemctl set-environment X=1"), pol))


def test_off_mode_disables_guard():
    pol = Policy(env_persist={"mode": "off"})
    assert not _gated(evaluate(_write("/etc/environment"), pol))


def test_mode_off_unquoted_yaml_boolean_disables_guard():
    """YAML 1.1 parses an unquoted `off` as boolean False — the guard must
    still recognize it as 'disabled', the same fix every sibling *_protect
    guard already applies for its own `mode` knob."""
    pol = Policy(env_persist={"mode": False})
    assert not _gated(evaluate(_write("/etc/environment"), pol))


def test_policy_allow_regex_exempts_trusted_path():
    pol = Policy(env_persist={"allow": [r"deploy/etc/environment"]})
    assert not _gated(evaluate(_write("deploy/etc/environment"), pol))


def test_policy_allow_regex_exempts_trusted_shell_command():
    """The `allow` list is checked on the shell branch too — via
    `_env_persist_allowed_by_policy(cfg, _cmd(ev))` — not just the Edit/
    Write/MCP branch already covered above."""
    pol = Policy(env_persist={"allow": [r"trusted-provision\.sh"]})
    assert not _gated(evaluate(
        _shell("bash trusted-provision.sh >> /etc/environment"), pol))


def test_loader_reads_env_persist_knob(tmp_path):
    from aegis.loader import load_policy
    (tmp_path / "policy.yaml").write_text(
        "env_persist:\n  mode: deny\n  allow: ['trusted/environment']\n")
    pol = load_policy(tmp_path)
    assert pol.env_persist.get("mode") == "deny"
    assert pol.env_persist.get("allow") == ["trusted/environment"]


# ---- performance / ReDoS -----------------------------------------------------

def test_path_re_no_quadratic_blowup_on_adversarial_input():
    import time
    from aegis import patterns
    adversarial = "/etc/environment" * 8000
    start = time.time()
    patterns.ENV_PERSIST_PATH_RE.search(adversarial)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"ENV_PERSIST_PATH_RE took {elapsed:.2f}s on adversarial input"


def test_activate_re_no_quadratic_blowup():
    import time
    from aegis import patterns
    adversarial = "systemctl " + ("x" * 8000) + " set-environment"
    start = time.time()
    patterns.ENV_PERSIST_ACTIVATE_RE.search(adversarial)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"ENV_PERSIST_ACTIVATE_RE took {elapsed:.2f}s on adversarial input"


def test_find_re_no_quadratic_blowup():
    import time
    from aegis import patterns
    adversarial = "find . -name x " * 8000
    start = time.time()
    patterns.env_persist_find_hit(adversarial)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"env_persist_find_hit took {elapsed:.2f}s on adversarial input"


def test_engine_no_quadratic_blowup():
    import time
    cmd = "find . -name x " * 8000
    start = time.time()
    evaluate(_shell(cmd), EMPTY)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"rule_env_persist_protect took {elapsed:.2f}s on adversarial find input"
