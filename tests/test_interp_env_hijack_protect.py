"""Interpreter-launch env-var code-injection guard — blocks setting ``BASH_ENV``
(any value) or ``NODE_OPTIONS`` (only when its value also names a module-loading
flag: ``--require``/``-r``/``--loader``/``--experimental-loader``/``--import``)
from a shell command, or by planting the assignment in a file that actually gets
loaded into a process environment (``.env``, a Dockerfile ``ENV`` line, a
``docker-compose.yml``/Kubernetes ``env:`` block, a wrapper script, a shell
profile).

Neither var is reached by any existing guard: ``rule_aegis_env_protect``'s var
list is Aegis's own seven trust-boundary names, not these; ``BASH_ENV`` touches
no file at all, so ``rule_shell_persist_protect``'s path check never sees it.

Default mode is ``ask`` (not ``deny``) — matching ``shell_persist``'s own
default. A dedicated ``mode: deny`` policy is used below to test the stricter
posture explicitly.
"""
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                       # default mode: ask
DENY = Policy(interp_env={"mode": "deny"})              # stricter, hard-block posture
OFF = Policy(interp_env={"mode": "off"})
ALLOWLISTED = Policy(interp_env={"mode": "deny", "allow": [r"trusted-apm-setup\.sh"]})


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _edit(path, new_string=None):
    args = {"file_path": path}
    if new_string is not None:
        args["new_string"] = new_string
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit", args=args)


def _write(path, content=None):
    args = {"file_path": path}
    if content is not None:
        args["content"] = content
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write", args=args)


def _mcp_write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                       action=ActionClass.MCP, args={"path": path, "content": content})


def _gated(d) -> bool:
    return d.action != Action.ALLOW


# ---- BASH_ENV, via shell ------------------------------------------------------

def test_bash_env_export_gated():
    d = evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), DENY)
    assert _gated(d) and d.rule == "interp-env-hijack-protect"
    assert d.action == Action.DENY


def test_bash_env_bare_assignment_gated():
    assert _gated(evaluate(_shell("BASH_ENV=/tmp/evil.sh bash script.sh"), DENY))


def test_bash_env_prefixed_to_bare_command_gated():
    assert _gated(evaluate(_shell("BASH_ENV=/tmp/evil.sh some_command"), DENY))


def test_bash_env_setenv_csh_gated():
    assert _gated(evaluate(_shell("setenv BASH_ENV /tmp/evil.sh"), DENY))


def test_bash_env_fish_set_x_gated():
    assert _gated(evaluate(_shell("set -x BASH_ENV /tmp/evil.sh"), DENY))


def test_bash_env_printf_v_gated():
    assert _gated(evaluate(_shell('printf -v BASH_ENV "%s" /tmp/evil.sh; export BASH_ENV'), DENY))


def test_bash_env_setx_windows_gated():
    assert _gated(evaluate(_shell("setx BASH_ENV C:\\evil.sh"), DENY))


def test_bash_env_default_mode_asks():
    d = evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), EMPTY)
    assert d.action == Action.ASK
    assert d.rule == "interp-env-hijack-protect"


def test_bash_env_unrelated_command_allowed():
    d = evaluate(_shell("echo hello world"), DENY)
    assert d.action == Action.ALLOW


def test_bash_env_mention_only_allowed():
    # A bare mention/doc reference with no assignment syntax is not gated —
    # same "no separate mention-only carve-out" trade-off AEGIS_ENV_BYPASS_RE
    # already makes.
    d = evaluate(_shell("grep -r BASH_ENV /var/log"), DENY)
    assert d.action == Action.ALLOW


# ---- BASH_ENV, via Edit/Write/MCP ----------------------------------------------

def test_bash_env_in_dotenv_gated():
    d = evaluate(_write(".env", content="BASH_ENV=/tmp/evil.sh\n"), DENY)
    assert _gated(d) and d.rule == "interp-env-hijack-protect"


def test_bash_env_in_dockerfile_gated():
    assert _gated(evaluate(_write("Dockerfile", content="ENV BASH_ENV /tmp/evil.sh"), DENY))


def test_bash_env_in_compose_yaml_gated():
    content = "services:\n  app:\n    environment:\n      - BASH_ENV=/tmp/evil.sh\n"
    assert _gated(evaluate(_write("docker-compose.yml", content=content), DENY))


def test_bash_env_in_k8s_manifest_gated():
    content = "env:\n  - name: BASH_ENV\n    value: /tmp/evil.sh\n"
    assert _gated(evaluate(_write("deploy/pod.yaml", content=content), DENY))


def test_bash_env_in_shell_rc_gated():
    # Carrier-path check also matches shell startup/profile files (no
    # recognized extension), same as rule_aegis_env_protect's own fix.
    assert _gated(evaluate(_write("/home/user/.bashrc", content="export BASH_ENV=/tmp/evil.sh"), DENY))


def test_bash_env_via_edit_new_string_gated():
    assert _gated(evaluate(_edit(".env", new_string="BASH_ENV=/tmp/evil.sh"), DENY))


def test_bash_env_via_mcp_write_gated():
    assert _gated(evaluate(_mcp_write(".env", "BASH_ENV=/tmp/evil.sh"), DENY))


def test_bash_env_in_readme_not_gated():
    # Documentation about the var, in a file that never gets loaded into a
    # process environment, must not gate — same false-positive guard
    # rule_aegis_env_protect's own carrier-path check exists for.
    d = evaluate(_write("README.md", content="Set BASH_ENV=/tmp/x.sh to enable tracing."), DENY)
    assert d.action == Action.ALLOW


def test_bash_env_in_env_example_not_gated():
    d = evaluate(_write(".env.example", content="BASH_ENV=/tmp/evil.sh"), DENY)
    assert d.action == Action.ALLOW


# ---- NODE_OPTIONS, via shell ---------------------------------------------------

def test_node_options_require_gated():
    d = evaluate(_shell('export NODE_OPTIONS="--require /tmp/evil.js"'), DENY)
    assert _gated(d) and d.rule == "interp-env-hijack-protect"


def test_node_options_short_r_gated():
    assert _gated(evaluate(_shell('NODE_OPTIONS="-r /tmp/evil.js" npm install'), DENY))


def test_node_options_loader_gated():
    assert _gated(evaluate(_shell('export NODE_OPTIONS="--loader /tmp/evil.mjs"'), DENY))


def test_node_options_import_gated():
    assert _gated(evaluate(_shell('export NODE_OPTIONS="--import /tmp/evil.mjs"'), DENY))


def test_node_options_tuning_only_allowed():
    # No loader flag -- ordinary, benign tuning stays allowed.
    d = evaluate(_shell('export NODE_OPTIONS="--max-old-space-size=4096"'), DENY)
    assert d.action == Action.ALLOW


def test_node_options_in_k8s_manifest_gated():
    content = "env:\n  - name: NODE_OPTIONS\n    value: \"--require /tmp/evil.js\"\n"
    assert _gated(evaluate(_write("deploy/pod.yaml", content=content), DENY))


def test_node_options_in_dotenv_gated():
    assert _gated(evaluate(_write(".env", content='NODE_OPTIONS=--require /tmp/evil.js'), DENY))


def test_node_options_padded_past_old_narrow_window_gated():
    # QA (bypass-hunt round): an earlier 200-char bound let padding push the
    # real flag out of the scanned window even though bash/Node don't care
    # about the extra whitespace at all.
    cmd = 'export NODE_OPTIONS="' + "z" * 220 + ' --require /tmp/evil.js"'
    assert _gated(evaluate(_shell(cmd), DENY))


def test_node_options_k8s_block_scalar_value_gated():
    # QA (bypass-hunt round): the k8s name:/value: alternative excluded
    # newlines from its value-side gap, so an ordinary YAML block-scalar
    # value (`value: |`, flag on the next line) evaded it entirely.
    content = "env:\n  - name: NODE_OPTIONS\n    value: |\n      --require /tmp/evil.js\n"
    assert _gated(evaluate(_write("deploy/pod.yaml", content=content), DENY))


# ---- policy knobs ---------------------------------------------------------------

def test_off_mode_allows():
    d = evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), OFF)
    assert d.action == Action.ALLOW


def test_aegis_allow_override_env_var(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_INTERP_ENV", "1")
    d = evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), DENY)
    assert d.action == Action.ALLOW


def test_policy_allowlist_regex():
    d = evaluate(_shell("export BASH_ENV=/opt/trusted-apm-setup.sh"), ALLOWLISTED)
    assert d.action == Action.ALLOW


def test_human_aegis_allow_comment_escapes():
    d = evaluate(_shell("export BASH_ENV=/tmp/evil.sh  # aegis-allow"), DENY)
    assert d.action == Action.ALLOW


def test_agent_cannot_self_escape_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "worker-1")
    d = evaluate(_shell("export BASH_ENV=/tmp/evil.sh  # aegis-allow"), DENY)
    assert _gated(d)


def test_agent_cannot_self_escape_env_toggle(monkeypatch):
    # A spawned agent cannot set AEGIS_ALLOW_INTERP_ENV for a hook invocation
    # it doesn't control -- but if it somehow did, being an agent alone
    # doesn't add extra restriction on this particular knob (only the shell
    # comment escape is agent-gated); documented here as current behavior.
    monkeypatch.setenv("AEGIS_AGENT_NAME", "worker-1")
    monkeypatch.setenv("AEGIS_ALLOW_INTERP_ENV", "1")
    d = evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), DENY)
    assert d.action == Action.ALLOW


def test_monitor_mode_allows_and_records(tmp_path, monkeypatch):
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AEGIS_AUDIT", str(audit))
    policy = Policy(interp_env={"mode": "monitor"})
    d = evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), policy)
    assert d.action == Action.ALLOW
    assert audit.exists()
    assert "interp-env-hijack-protect-monitor" in audit.read_text()
