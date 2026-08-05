"""Dynamic-linker preload / search-path hijack protection guard — blocks
planting/altering glibc's dynamic-linker preload list (``/etc/ld.so.preload``)
or its shared-library search-path config (``/etc/ld.so.conf``,
``/etc/ld.so.conf.d/*.conf`` drop-ins).

THREAT MODEL: every shared object listed in ``/etc/ld.so.preload`` is
``dlopen()``'d into EVERY dynamically-linked ELF binary the system execs from
that point on — any user, any binary, no reboot/new-shell/CI trigger needed,
the very next ``exec()`` anywhere on the machine picks it up. The actual
mechanism real Linux userland rootkits (Jynx, Azazel) use to wrap libc calls
process-wide. Nothing in this file covered this surface before this guard —
``rule_service_persist_protect`` covers a different auto-run mechanism
(systemd/launchd process supervision, not the ELF loader), and
``rule_path_hijack_protect`` covers a shadowed $PATH *binary*, not a shared
*library* reached via the loader's own search path.

Default mode is ``ask`` (not ``deny``) — legitimate uses exist (EDR/
observability agents, malloc-debugging libraries deliberately preloaded this
way), same posture as every sibling ``*_protect`` guard. A dedicated
``mode: deny`` policy is used below to test the stricter posture explicitly.
"""
import time

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                        # default mode: ask
DENY = Policy(ld_preload={"mode": "deny"})               # stricter, hard-block posture


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


# ---- /etc/ld.so.preload, via Edit/Write -------------------------------------

def test_ld_so_preload_write_gated():
    d = evaluate(_write("/etc/ld.so.preload"), EMPTY)
    assert _gated(d) and d.rule == "ld-preload-protect"


def test_ld_so_preload_edit_gated():
    d = evaluate(_edit("/etc/ld.so.preload"), EMPTY)
    assert _gated(d) and d.rule == "ld-preload-protect"


def test_relative_ld_so_preload_gated():
    assert _gated(evaluate(_write("etc/ld.so.preload"), EMPTY))


# ---- /etc/ld.so.conf(.d), via Edit/Write ------------------------------------

def test_ld_so_conf_write_gated():
    d = evaluate(_write("/etc/ld.so.conf"), EMPTY)
    assert _gated(d) and d.rule == "ld-preload-protect"


def test_ld_so_conf_d_dropin_gated():
    d = evaluate(_write("/etc/ld.so.conf.d/evil.conf"), EMPTY)
    assert _gated(d) and d.rule == "ld-preload-protect"


# ---- MCP-tool writes ---------------------------------------------------------

def test_mcp_tool_write_to_preload_gated():
    d = evaluate(_mcp_write("/etc/ld.so.preload"), EMPTY)
    assert _gated(d) and d.rule == "ld-preload-protect"


def test_mcp_tool_alternate_path_arg_keys_gated():
    for key in ("target_file", "targetFile", "filename", "file", "uri"):
        d = evaluate(_mcp_write_arg(key, "/etc/ld.so.preload"), EMPTY)
        assert _gated(d) and d.rule == "ld-preload-protect", key


# ---- shell-based mutation -----------------------------------------------------

def test_shell_redirect_to_preload_gated():
    assert _gated(evaluate(_shell("echo '/tmp/evil.so' > /etc/ld.so.preload"), EMPTY))
    assert _gated(evaluate(_shell("echo '/tmp/evil.so' >> /etc/ld.so.preload"), EMPTY))


def test_shell_tee_to_preload_gated():
    d = evaluate(_shell("echo /tmp/evil.so | tee /etc/ld.so.preload"), EMPTY)
    assert _gated(d) and d.rule == "ld-preload-protect"


def test_shell_delete_preload_gated():
    assert _gated(evaluate(_shell("rm /etc/ld.so.preload"), EMPTY))


def test_shell_inplace_edit_and_copy_gated():
    assert _gated(evaluate(_shell("sed -i 's/x/evil.so/' /etc/ld.so.preload"), EMPTY))
    d = evaluate(_shell("cp evil.conf /etc/ld.so.conf.d/evil.conf"), EMPTY)
    assert _gated(d) and d.rule == "ld-preload-protect"


def test_shell_read_only_not_gated():
    assert not _gated(evaluate(_shell("cat /etc/ld.so.preload"), EMPTY))
    assert not _gated(evaluate(_shell("ldconfig -p"), EMPTY))


def test_find_path_indirection_gated():
    assert _gated(evaluate(
        _shell("cp evil.so $(find / -name 'ld.so.preload')"), EMPTY))
    assert _gated(evaluate(
        _shell("mv evil.conf $(find / -path '*ld.so.conf.d*')"), EMPTY))


def test_find_regex_escaped_dots_does_not_bypass():
    """QA finding (independent adversarial review, bypass-hunting round): a
    `find -regex`/`-iregex` value is itself an ERE, and escaping its interior
    literal dots (the textbook-correct way to write one) inserted a literal
    backslash between "ld"/"so"/"preload" in the scanned text, breaking a
    naive substring-adjacency fragment match — reproduced and closed by
    tolerating an optional backslash before each dot in the find-fragment
    pattern itself. See LD_PRELOAD_FIND_RE's own comment in patterns.py."""
    assert _gated(evaluate(
        _shell(r"find / -regex '.*ld\.so\.preload.*' -exec cp evil.so {} \;"), EMPTY))
    assert _gated(evaluate(
        _shell(r"find / -iregex '.*etc/ld\.so\.conf\.d/.*' -exec cp evil.conf {} \;"), EMPTY))


def test_forced_symlink_swap_gated():
    d = evaluate(_shell("ln -sf evil.preload /etc/ld.so.preload"), EMPTY)
    assert _gated(d) and d.rule == "ld-preload-protect"


def test_rsync_to_ld_so_conf_d_dir_gated():
    d = evaluate(_shell("rsync -a evil/ /etc/ld.so.conf.d/"), EMPTY)
    assert _gated(d) and d.rule == "ld-preload-protect"


def test_tar_extract_to_ld_so_conf_d_dir_gated():
    d = evaluate(_shell("tar xf payload.tar -C /etc/ld.so.conf.d/"), EMPTY)
    assert _gated(d) and d.rule == "ld-preload-protect"


def test_bare_dir_gated_only_with_verb():
    """The bare directory reference alone (no verb) never gates —
    LD_PRELOAD_DIR_RE only matters paired with a write/archive verb."""
    assert not _gated(evaluate(_shell("ls /etc/ld.so.conf.d"), EMPTY))
    d = evaluate(_shell("rsync -a evil/ /etc/ld.so.conf.d"), EMPTY)
    assert _gated(d) and d.rule == "ld-preload-protect"


# ---- path-separator / Windows-trim bypass (same class as sibling guards) -----

def test_doubled_separator_does_not_bypass():
    for path in (
        "/etc//ld.so.preload",
        "/etc/./ld.so.preload",
        "etc/ld.so.preload",
    ):
        d = evaluate(_write(path), EMPTY)
        assert _gated(d) and d.rule == "ld-preload-protect", path


def test_etc_doubled_slash_shell_form_does_not_bypass():
    d = evaluate(_shell("echo /tmp/evil.so >> /etc//ld.so.preload"), EMPTY)
    assert _gated(d) and d.rule == "ld-preload-protect"


def test_windows_trailing_dot_does_not_bypass():
    d = evaluate(_write("etc./ld.so.preload"), EMPTY)
    assert _gated(d) and d.rule == "ld-preload-protect"


# ---- false-positive guards ----------------------------------------------------

def test_unrelated_conf_file_not_gated():
    assert not _gated(evaluate(_write("config/app.conf"), EMPTY))


def test_unrelated_etc_path_not_gated():
    assert not _gated(evaluate(_write("/etc/hosts"), EMPTY))
    assert not _gated(evaluate(_write("/etc/nginx/nginx.conf"), EMPTY))


def test_unrelated_edit_allowed():
    assert not _gated(evaluate(_edit("src/app.py"), EMPTY))
    assert not _gated(evaluate(_write("README.md"), EMPTY))


def test_commit_message_mention_not_gated():
    assert not _gated(evaluate(
        _shell('git commit -m "document ld.so.preload debugging notes"'), EMPTY))


def test_bare_etc_find_fragment_excluded():
    """The bare parent directory '/etc' is deliberately excluded from the
    find-indirection fragment list — too generic, the same trade-off
    SHELL_PERSIST_FIND_RE's docstring accepts for "config"/"profile"."""
    from aegis import patterns
    assert not patterns.ld_preload_find_hit("find . -path '*/etc/*'")


# ---- escape hatches: human-only -----------------------------------------------

def test_human_can_override_shell_with_comment():
    assert not _gated(evaluate(
        _shell("echo /opt/edr/agent.so >> /etc/ld.so.preload  # aegis-allow"), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(
        _shell("echo /tmp/evil.so >> /etc/ld.so.preload  # aegis-allow"), EMPTY))


def test_env_toggle_allows_edit_and_shell(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_LD_PRELOAD", "1")
    assert not _gated(evaluate(_write("/etc/ld.so.preload"), EMPTY))
    assert not _gated(evaluate(_shell("echo x >> /etc/ld.so.preload"), EMPTY))


# ---- modes: ask (default) / deny / monitor / off ------------------------------

def test_default_mode_is_ask():
    d = evaluate(_write("/etc/ld.so.preload"), EMPTY)
    assert d.action == Action.ASK and d.rule == "ld-preload-protect"


def test_deny_mode_hard_blocks():
    d = evaluate(_write("/etc/ld.so.preload"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == "ld-preload-protect"


def test_monitor_mode_logs_and_allows():
    pol = Policy(ld_preload={"mode": "monitor"})
    assert not _gated(evaluate(_write("/etc/ld.so.preload"), pol))
    assert not _gated(evaluate(_shell("echo x >> /etc/ld.so.preload"), pol))


def test_off_mode_disables_guard():
    pol = Policy(ld_preload={"mode": "off"})
    assert not _gated(evaluate(_write("/etc/ld.so.preload"), pol))


def test_mode_off_unquoted_yaml_boolean_disables_guard():
    """YAML 1.1 parses an unquoted `off` as boolean False — the guard must
    still recognize it as 'disabled', the same fix every sibling *_protect
    guard already applies for its own `mode` knob."""
    pol = Policy(ld_preload={"mode": False})
    assert not _gated(evaluate(_write("/etc/ld.so.preload"), pol))


def test_policy_allow_regex_exempts_trusted_path():
    pol = Policy(ld_preload={"allow": [r"deploy/ld\.so\.preload"]})
    assert not _gated(evaluate(_write("deploy/ld.so.preload"), pol))
    assert _gated(evaluate(_write("/etc/ld.so.preload"), pol))


def test_policy_allow_regex_exempts_trusted_shell_command():
    pol = Policy(ld_preload={"allow": [r"trusted-edr-deploy\.sh"]})
    assert not _gated(evaluate(
        _shell("bash trusted-edr-deploy.sh && echo x >> /etc/ld.so.preload"), pol))
    assert _gated(evaluate(_shell("echo x >> /etc/ld.so.preload"), pol))


# ---- performance / ReDoS ------------------------------------------------------

def test_no_quadratic_blowup_on_adversarial_input():
    from aegis import patterns
    adversarial = "etc/ld.so.preload" * 8000
    start = time.time()
    patterns.LD_PRELOAD_PATH_RE.search(adversarial)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"LD_PRELOAD_PATH_RE took {elapsed:.2f}s on adversarial input"

    start = time.time()
    patterns.LD_SO_CONF_PATH_RE.search("etc/ld.so.conf.d/x.conf" * 8000)
    elapsed2 = time.time() - start
    assert elapsed2 < 1.0, f"LD_SO_CONF_PATH_RE took {elapsed2:.2f}s on adversarial input"


def test_find_re_no_quadratic_blowup():
    from aegis import patterns
    adversarial = "find . -name x " * 8000
    start = time.time()
    patterns.ld_preload_find_hit(adversarial)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"ld_preload_find_hit took {elapsed:.2f}s on adversarial input"


def test_engine_no_quadratic_blowup():
    cmd = "find . -name x " * 8000
    start = time.time()
    evaluate(_shell(cmd), EMPTY)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"rule_ld_preload_protect took {elapsed:.2f}s on adversarial find input"
