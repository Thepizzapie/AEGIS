"""Interpreter/tool auto-load environment-variable hijack protection guard —
blocks setting ``NODE_OPTIONS``/``BASH_ENV``/``ENV``/``PYTHONSTARTUP``/
``PERL5OPT``/``RUBYOPT``/the ``LD_PRELOAD`` env var/``GIT_SSH_COMMAND`` to a
code-loading value.

THREAT MODEL: each of these variables redirects a specific interpreter/tool's
very NEXT invocation to attacker-chosen code, purely by being set — no config
file, hook, service unit, or reboot needed, and (set from a plain shell
command) it taints every LATER command the same agent session runs before
anything ever touches disk.

Default mode is ``ask`` (not ``deny``) — setting these variables has real,
sanctioned uses. A dedicated ``mode: deny`` policy is used below to test the
stricter posture explicitly.
"""
import time

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                        # default mode: ask
DENY = Policy(env_hijack={"mode": "deny"})               # stricter, hard-block posture


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _write(path, content=None):
    args = {"file_path": path}
    if content is not None:
        args["content"] = content
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write", args=args)


def _edit_content(path, new_string):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                       args={"file_path": path, "new_string": new_string})


def _mcp_edit_edits(path, new_text):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__edit_file",
                       action=ActionClass.MCP,
                       args={"path": path, "edits": [{"oldText": "x", "newText": new_text}]})


def _gated(d) -> bool:
    return d.action != Action.ALLOW


# ---- NODE_OPTIONS -------------------------------------------------------------

def test_node_options_require_flag_gated():
    d = evaluate(_shell('export NODE_OPTIONS="--require=/tmp/evil.js" && node app.js'), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


def test_node_options_loader_flag_gated():
    d = evaluate(_shell("NODE_OPTIONS=--experimental-loader=/tmp/evil.mjs node app.js"), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


def test_node_options_bare_glued_r_flag_gated():
    d = evaluate(_shell("NODE_OPTIONS=-r/tmp/evil.js node app.js"), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


def test_node_options_benign_memory_flag_not_gated():
    """The overwhelmingly common, non-exec use of this variable must not ask
    on every run."""
    assert not _gated(evaluate(
        _shell("NODE_OPTIONS=--max-old-space-size=4096 node app.js"), EMPTY))


# ---- BASH_ENV / ENV -------------------------------------------------------------

def test_bash_env_path_value_gated():
    d = evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


def test_env_var_path_value_gated():
    d = evaluate(_shell("ENV=/tmp/evil.sh sh -c 'echo hi'"), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


def test_env_var_bare_word_not_gated():
    """`ENV=production` is a common deployment-environment-name convention
    with no path shape at all — inert for this mechanism, must not ask."""
    assert not _gated(evaluate(_shell("ENV=production npm start"), EMPTY))


def test_bash_env_home_relative_gated():
    d = evaluate(_shell("export BASH_ENV=~/.evil.sh"), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


# ---- PYTHONSTARTUP --------------------------------------------------------------

def test_pythonstartup_gated():
    d = evaluate(_shell("export PYTHONSTARTUP=/tmp/evil.py"), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


def test_pythonstartup_bare_word_not_gated():
    assert not _gated(evaluate(_shell("PYTHONSTARTUP=default python"), EMPTY))


# ---- PERL5OPT / RUBYOPT ---------------------------------------------------------

def test_perl5opt_any_nonempty_value_gated():
    d = evaluate(_shell("export PERL5OPT=-Mfoo"), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


def test_rubyopt_require_glued_gated():
    d = evaluate(_shell("RUBYOPT=-rfoo ruby x.rb"), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


def test_rubyopt_require_long_form_gated():
    d = evaluate(_shell("RUBYOPT=--require=/tmp/evil.rb bundle exec rake"), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


def test_rubyopt_benign_warning_flag_not_gated():
    assert not _gated(evaluate(_shell("RUBYOPT=-W0 ruby x.rb"), EMPTY))


# ---- LD_PRELOAD (env var, distinct from the /etc file) --------------------------

def test_ld_preload_env_var_gated():
    d = evaluate(_shell("LD_PRELOAD=/tmp/evil.so ./binary"), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


def test_ld_preload_env_var_export_form_gated():
    d = evaluate(_shell("export LD_PRELOAD=/tmp/evil.so"), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


# ---- GIT_SSH_COMMAND --------------------------------------------------------------

def test_git_ssh_command_gated():
    d = evaluate(_shell('export GIT_SSH_COMMAND="/tmp/evil"'), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


def test_git_ssh_command_prefix_form_gated():
    d = evaluate(_shell("GIT_SSH_COMMAND=/tmp/evil git fetch origin"), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


# ---- Windows forms: PowerShell $env: / setx --------------------------------------

def test_powershell_env_assignment_gated():
    d = evaluate(_shell('$env:NODE_OPTIONS = "--require=/tmp/evil.js"'), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


def test_setx_persistent_env_var_gated():
    d = evaluate(_shell(r"setx BASH_ENV C:\tmp\evil.sh"), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


# ---- Edit/Write/MCP content branch ------------------------------------------------

def test_write_content_setting_bash_env_gated():
    """The same shape landing in a shell script about to be run, a CI step,
    or a Dockerfile ENV instruction — not just an interactive shell command."""
    d = evaluate(_write("setup.sh", content="export BASH_ENV=/tmp/evil.sh\n"), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


def test_edit_new_string_setting_node_options_gated():
    d = evaluate(_edit_content("ci/run.sh", "export NODE_OPTIONS=--require=/tmp/evil.js"), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


def test_dockerfile_env_instruction_gated():
    d = evaluate(_write("Dockerfile", content="ENV NODE_OPTIONS=--require=/app/evil.js\n"), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


def test_mcp_tool_edits_shape_gated():
    d = evaluate(_mcp_edit_edits("ci/run.sh", "export GIT_SSH_COMMAND=/tmp/evil"), EMPTY)
    assert _gated(d) and d.rule == "env-hijack-protect"


def test_unrelated_write_not_gated():
    assert not _gated(evaluate(_write("README.md", content="# hello"), EMPTY))


# ---- false-positive guards --------------------------------------------------------

def test_unrelated_shell_command_not_gated():
    assert not _gated(evaluate(_shell("echo hello world"), EMPTY))


def test_commit_message_mention_not_gated():
    d = evaluate(_shell('git commit -m "document NODE_OPTIONS usage in README"'), EMPTY)
    assert not _gated(d)


def test_longer_identifier_suffix_not_gated():
    """`\\b` before the name rejects a longer identifier merely ending in the
    same word — both neighboring characters stay word characters."""
    assert not _gated(evaluate(_shell("MY_NODE_OPTIONS=--require=/tmp/x.js node app.js"), EMPTY))
    assert not _gated(evaluate(_shell("SOME_BASH_ENV=/tmp/x.sh"), EMPTY))


def test_read_only_reference_not_gated():
    assert not _gated(evaluate(_shell("echo $NODE_OPTIONS"), EMPTY))
    assert not _gated(evaluate(_shell("printenv BASH_ENV"), EMPTY))


def test_empty_value_clearing_not_gated():
    assert not _gated(evaluate(_shell("export NODE_OPTIONS="), EMPTY))
    assert not _gated(evaluate(_shell('export BASH_ENV=""'), EMPTY))


# ---- escape hatches: human-only ----------------------------------------------------

def test_human_can_override_shell_with_comment():
    assert not _gated(evaluate(
        _shell("export BASH_ENV=/tmp/evil.sh  # aegis-allow"), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(
        _shell("export BASH_ENV=/tmp/evil.sh  # aegis-allow"), EMPTY))


def test_env_toggle_allows_shell_and_write(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_ENV_HIJACK", "1")
    assert not _gated(evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), EMPTY))
    assert not _gated(evaluate(_write("setup.sh", content="export BASH_ENV=/tmp/evil.sh"), EMPTY))


# ---- modes: ask (default) / deny / monitor / off ------------------------------------

def test_default_mode_is_ask():
    d = evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), EMPTY)
    assert d.action == Action.ASK and d.rule == "env-hijack-protect"


def test_deny_mode_hard_blocks():
    d = evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == "env-hijack-protect"


def test_monitor_mode_logs_and_allows():
    pol = Policy(env_hijack={"mode": "monitor"})
    assert not _gated(evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), pol))
    assert not _gated(evaluate(_write("setup.sh", content="export BASH_ENV=/tmp/evil.sh"), pol))


def test_off_mode_disables_guard():
    pol = Policy(env_hijack={"mode": "off"})
    assert not _gated(evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), pol))


def test_mode_off_unquoted_yaml_boolean_disables_guard():
    """YAML 1.1 parses an unquoted `off` as boolean False — the guard must
    still recognize it as 'disabled', the same fix every sibling *_protect
    guard already applies for its own `mode` knob."""
    pol = Policy(env_hijack={"mode": False})
    assert not _gated(evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), pol))


def test_policy_allow_regex_exempts_trusted_command():
    pol = Policy(env_hijack={"allow": [r"trusted-coverage-harness\.sh"]})
    assert not _gated(evaluate(
        _shell("bash trusted-coverage-harness.sh && export NODE_OPTIONS=--require=/tmp/x.js"), pol))
    assert _gated(evaluate(_shell("export NODE_OPTIONS=--require=/tmp/x.js"), pol))


def test_policy_allow_regex_exempts_trusted_content():
    pol = Policy(env_hijack={"allow": [r"# trusted-ci-bootstrap"]})
    assert not _gated(evaluate(
        _write("setup.sh", content="# trusted-ci-bootstrap\nexport BASH_ENV=/tmp/ok.sh\n"), pol))
    assert _gated(evaluate(_write("setup.sh", content="export BASH_ENV=/tmp/evil.sh\n"), pol))


# ---- performance / ReDoS ------------------------------------------------------------

def test_no_quadratic_blowup_on_adversarial_input():
    from aegis import patterns
    adversarial = "NODE_OPTIONS=x " * 8000
    start = time.time()
    patterns.env_hijack_hit(adversarial)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"env_hijack_hit took {elapsed:.2f}s on adversarial input"


def test_engine_no_quadratic_blowup():
    cmd = "echo hello " * 8000
    start = time.time()
    evaluate(_shell(cmd), EMPTY)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"rule_env_hijack_protect took {elapsed:.2f}s on adversarial input"
