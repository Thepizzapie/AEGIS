"""Interpreter env-var auto-exec hijack protection guard — blocks setting an
environment variable that makes an interpreter/shell auto-load and run a
file, or an attacker-chosen module, on its very next ordinary invocation.

THREAT MODEL: every sibling interpreter-startup guard in this file
(``rule_ld_preload_protect``, ``rule_pysite_protect``, ``rule_conftest_
protect``, ``rule_ipython_startup_protect``) gates a FILE at a fixed,
conventional path the interpreter always checks. This guard covers the
layer above all four: the ENV VAR that tells the interpreter where to look
in the first place, set with nothing more than a bare ``export`` in the
current shell — no file write any other guard recognizes, no reboot, no new
shell, no git/CI trigger. Two severity tiers: ``BASH_ENV``/``PYTHONSTARTUP``
gate on assignment alone (both exist only to source/run a file at startup,
no common benign bare use), while ``NODE_OPTIONS``/``PERL5OPT``/``RUBYOPT``
gate only when the value carries that interpreter's own module-preload/
require flag (each has common, benign uses — heap tuning, warning
suppression — that must not be asked on).

Default mode is ``ask`` (not ``deny``) — the same posture as every sibling
``*_protect`` guard; a dedicated ``mode: deny`` policy tests the stricter
posture explicitly.
"""
import time

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                          # default mode: ask
DENY = Policy(interp_env_exec={"mode": "deny"})            # stricter, hard-block posture


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _edit(path, new_string=None):
    args = {"file_path": path}
    if new_string is not None:
        args["new_string"] = new_string
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit", args=args)


def _write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write",
                       args={"file_path": path, "content": content})


def _mcp_write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                       action=ActionClass.MCP, args={"path": path, "content": content})


def _mcp_nested(content, path=".env"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__edit_file",
                       action=ActionClass.MCP,
                       args={"path": path, "edits": [{"newText": content}]})


def _gated(d) -> bool:
    return d.action != Action.ALLOW


# ---- BASH_ENV / PYTHONSTARTUP: always-gated tier -----------------------------

def test_blocks_bash_env_export():
    d = evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), EMPTY)
    assert _gated(d) and d.rule == "interp-env-protect"


def test_blocks_bash_env_inline_prefix_assignment():
    d = evaluate(_shell("BASH_ENV=/tmp/evil.sh bash script.sh"), EMPTY)
    assert _gated(d) and d.rule == "interp-env-protect"


def test_blocks_bash_env_via_env_command():
    d = evaluate(_shell("env BASH_ENV=/tmp/evil.sh bash script.sh"), EMPTY)
    assert _gated(d)


def test_blocks_bash_env_csh_setenv():
    d = evaluate(_shell("setenv BASH_ENV /tmp/evil.sh"), EMPTY)
    assert _gated(d)


def test_blocks_bash_env_windows_setx():
    d = evaluate(_shell("setx BASH_ENV C:\\evil.sh"), EMPTY)
    assert _gated(d)


def test_blocks_bash_env_powershell_form():
    d = evaluate(_shell('$env:BASH_ENV = "C:\\evil.ps1"'), EMPTY)
    assert _gated(d)


def test_blocks_bash_env_fish_set_dash_x():
    d = evaluate(_shell("set -x BASH_ENV /tmp/evil.sh"), EMPTY)
    assert _gated(d)


def test_blocks_pythonstartup_export():
    d = evaluate(_shell("export PYTHONSTARTUP=/tmp/evil.py"), EMPTY)
    assert _gated(d) and d.rule == "interp-env-protect"


def test_blocks_pythonstartup_dockerfile_env():
    d = evaluate(_write("Dockerfile", "ENV PYTHONSTARTUP /opt/evil.py\n"), EMPTY)
    assert _gated(d)


def test_blocks_bash_env_compose_yaml_block():
    content = "services:\n  app:\n    environment:\n      BASH_ENV: /tmp/evil.sh\n"
    d = evaluate(_write("docker-compose.yml", content), EMPTY)
    assert _gated(d)


def test_blocks_bash_env_compose_list_form():
    content = "services:\n  app:\n    environment:\n      - BASH_ENV=/tmp/evil.sh\n"
    d = evaluate(_write("docker-compose.yml", content), EMPTY)
    assert _gated(d)


def test_blocks_bash_env_via_edit_new_string():
    d = evaluate(_edit(".env", new_string="BASH_ENV=/tmp/evil.sh"), EMPTY)
    assert _gated(d)


def test_blocks_bash_env_via_mcp_write():
    d = evaluate(_mcp_write(".env", "BASH_ENV=/tmp/evil.sh\n"), EMPTY)
    assert _gated(d)


def test_blocks_bash_env_via_mcp_nested_args():
    d = evaluate(_mcp_nested("BASH_ENV=/tmp/evil.sh"), EMPTY)
    assert _gated(d)


def test_blocks_bash_env_wrapper_script():
    d = evaluate(_write("deploy.sh", "export BASH_ENV=/tmp/evil.sh\n"), EMPTY)
    assert _gated(d) and d.rule == "interp-env-protect"


def test_shell_profile_dotfile_still_gated_defense_in_depth():
    # a shell startup/profile dotfile is ALSO covered by the earlier,
    # broader shell-persist guard (any write to it asks, regardless of
    # content) -- that guard wins first in rule order, so the surface stays
    # gated even though this rule's own carrier-path check would also match.
    for path in (".bashrc", ".bash_profile", ".zshrc"):
        d = evaluate(_write(path, "export BASH_ENV=/tmp/evil.sh\n"), EMPTY)
        assert _gated(d), path


# ---- NODE_OPTIONS / PERL5OPT / RUBYOPT: flag-gated tier -----------------------

def test_blocks_node_options_require_equals_form():
    d = evaluate(_shell("export NODE_OPTIONS=--require=/tmp/evil.js"), EMPTY)
    assert _gated(d) and d.rule == "interp-env-protect"


def test_blocks_node_options_require_space_form():
    d = evaluate(_shell('export NODE_OPTIONS="--require /tmp/evil.js"'), EMPTY)
    assert _gated(d)


def test_blocks_node_options_short_r_flag():
    d = evaluate(_shell("NODE_OPTIONS='-r /tmp/evil.js' node app.js"), EMPTY)
    assert _gated(d)


def test_blocks_node_options_loader_flag():
    d = evaluate(_shell("export NODE_OPTIONS=--loader=/tmp/evil.mjs"), EMPTY)
    assert _gated(d)


def test_blocks_node_options_import_flag():
    d = evaluate(_shell("export NODE_OPTIONS=--import=/tmp/evil.mjs"), EMPTY)
    assert _gated(d)


def test_blocks_perl5opt_capital_m():
    d = evaluate(_shell("export PERL5OPT=-Mevil::module"), EMPTY)
    assert _gated(d)


def test_blocks_perl5opt_debugger_module():
    d = evaluate(_shell("export PERL5OPT=-d:evil"), EMPTY)
    assert _gated(d)


def test_blocks_rubyopt_require():
    d = evaluate(_shell("export RUBYOPT=-ropen-uri"), EMPTY)
    assert _gated(d)


def test_blocks_node_options_dockerfile_env_form():
    d = evaluate(_write("Dockerfile", "ENV NODE_OPTIONS --require=/tmp/evil.js\n"), EMPTY)
    assert _gated(d)


def test_blocks_node_options_via_write_content():
    d = evaluate(_write(".env", "NODE_OPTIONS=--require=/tmp/evil.js\n"), EMPTY)
    assert _gated(d)


# ---- false-positive guards: benign, common uses stay allowed ------------------

def test_allows_node_options_heap_tuning():
    assert not evaluate(
        _shell("export NODE_OPTIONS=--max-old-space-size=4096"), EMPTY).blocked
    assert not _gated(evaluate(
        _shell("NODE_OPTIONS=--stack-size=2000 node app.js"), EMPTY))


def test_allows_rubyopt_warning_suppression():
    assert not _gated(evaluate(_shell("export RUBYOPT=-W0"), EMPTY))


def test_allows_posix_env_app_environment_name():
    # ENV=production/staging is an extremely common app-level convention,
    # deliberately NOT gated — see INTERP_ENV_ALWAYS_RE's own comment.
    assert not _gated(evaluate(_shell("ENV=production python manage.py test"), EMPTY))
    assert not _gated(evaluate(_shell("export ENV=staging"), EMPTY))


def test_allows_ordinary_mentions_and_reads():
    assert not _gated(evaluate(_shell("grep BASH_ENV .env"), EMPTY))
    assert not _gated(evaluate(_shell('echo "BASH_ENV is a dangerous env var"'), EMPTY))


def test_allows_unrelated_env_assignment():
    assert not _gated(evaluate(_shell("export PATH=/usr/local/bin:$PATH"), EMPTY))
    assert not _gated(evaluate(_write(".env", "DATABASE_URL=postgres://x\n"), EMPTY))


def test_allows_readme_documentation_with_assignment_example():
    content = (
        "## Troubleshooting\n\nTo debug shell init, run:\n\n"
        "    BASH_ENV=/tmp/trace.sh bash script.sh\n"
    )
    assert not evaluate(_write("docs/TROUBLESHOOTING.md", content), EMPTY).blocked


def test_allows_dotenv_example_template_file():
    assert not evaluate(_write(".env.example", "BASH_ENV=\n"), EMPTY).blocked


def test_allows_non_carrier_source_file_with_assignment_shaped_content():
    assert not evaluate(
        _write("scratch.py", "BASH_ENV=/tmp/evil.sh\n"), EMPTY).blocked


# ---- escape hatches: human-only -----------------------------------------------

def test_human_can_override_shell_with_comment():
    assert not _gated(evaluate(
        _shell("export BASH_ENV=/tmp/trusted-init.sh  # aegis-allow"), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(
        _shell("export BASH_ENV=/tmp/evil.sh  # aegis-allow"), EMPTY))


def test_env_toggle_allows_shell_and_write(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_INTERP_ENV", "1")
    assert not _gated(evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), EMPTY))
    assert not _gated(evaluate(_write(".env", "BASH_ENV=/tmp/evil.sh\n"), EMPTY))


def test_not_escapable_via_unrelated_allow_knob(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_LD_PRELOAD", "1")
    assert _gated(evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), EMPTY))


# ---- modes: ask (default) / deny / monitor / off ------------------------------

def test_default_mode_is_ask():
    d = evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), EMPTY)
    assert d.action == Action.ASK and d.rule == "interp-env-protect"


def test_deny_mode_hard_blocks():
    d = evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == "interp-env-protect"


def test_monitor_mode_logs_and_allows():
    pol = Policy(interp_env_exec={"mode": "monitor"})
    assert not _gated(evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), pol))
    assert not _gated(evaluate(_write(".env", "BASH_ENV=/tmp/evil.sh\n"), pol))


def test_off_mode_disables_guard():
    pol = Policy(interp_env_exec={"mode": "off"})
    assert not _gated(evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), pol))


def test_mode_off_unquoted_yaml_boolean_disables_guard():
    pol = Policy(interp_env_exec={"mode": False})
    assert not _gated(evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), pol))


def test_policy_allow_regex_exempts_trusted_command():
    pol = Policy(interp_env_exec={"allow": [r"test/setup\.js"]})
    assert not _gated(evaluate(
        _shell("export NODE_OPTIONS='--require ./test/setup.js'"), pol))
    assert _gated(evaluate(
        _shell("export NODE_OPTIONS='--require ./evil.js'"), pol))


def test_policy_allow_regex_exempts_trusted_path():
    # the Edit/Write/MCP branch's allow-regex matches the PATH, the same
    # convention rule_cloud_cred_exec_protect/rule_ld_preload_protect's own
    # Edit/Write branches already use.
    pol = Policy(interp_env_exec={"allow": [r"deploy/\.env"]})
    assert not _gated(evaluate(_write("deploy/.env", "BASH_ENV=/opt/agent/init.sh\n"), pol))
    assert _gated(evaluate(_write("scratch/.env", "BASH_ENV=/tmp/evil.sh\n"), pol))


# ---- performance / ReDoS ------------------------------------------------------

def test_no_quadratic_blowup_on_adversarial_input():
    from aegis import patterns

    adversarial = [
        "BASH_ENV" * 20_000,
        "export " * 50_000,
        "NODE_OPTIONS=" * 30_000,
        "environment:\n  - FOO=bar\n" * 20_000,
    ]
    for text in adversarial:
        start = time.time()
        patterns.INTERP_ENV_ALWAYS_RE.search(text)
        patterns.interp_env_flag_hit(text)
        elapsed = time.time() - start
        assert elapsed < 1.0, f"interp-env patterns took {elapsed:.2f}s on adversarial input"

    start = time.time()
    evaluate(_shell("echo x " * 20_000), EMPTY)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"rule_interp_env_protect took {elapsed:.2f}s on adversarial input"
