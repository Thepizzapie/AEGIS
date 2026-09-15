"""Code-injection environment-variable hijack protection guard — blocks
setting ``LD_PRELOAD``/``DYLD_INSERT_LIBRARIES``, ``BASH_ENV``, ``PERL5OPT``/
``RUBYOPT``, or ``NODE_OPTIONS`` (only when paired with one of its own
code-loading flags) from a shell, or planting the assignment in a file
something actually loads into a process environment.

THREAT MODEL: every sibling ``*_protect`` guard in this file gates a
PERSISTENCE FILE the OS or a tool reads back later (``rule_ld_preload_
protect``'s own ``/etc/ld.so.preload``, ``rule_shell_persist_protect``'s
``~/.bashrc``). These six variables are instead read directly out of the
process ENVIRONMENT — by the dynamic linker, a shell, or a language runtime —
so an ordinary ``export`` in the CURRENT shell is already a live hijack of
every matching subprocess for the rest of the session, no file write, reboot,
or new session needed. ``LD_PRELOAD``/``DYLD_INSERT_LIBRARIES`` are the
env-var form of the exact rootkit primitive ``rule_ld_preload_protect``
covers for the persisted file. ``BASH_ENV`` is sourced for every
*non-interactive* bash invocation (most CI "run a step" shells), a trigger
``rule_shell_persist_protect``'s own ``~/.bashrc`` coverage never reaches —
the documented mechanism behind real CI-secret-exfiltration backdoors.
``PERL5OPT``/``RUBYOPT`` auto-load a module (``-M``/``-r``) on the next
``perl``/``ruby`` invocation. ``NODE_OPTIONS`` does the same via
``--require``/``--loader``/``--experimental-loader``/``--import`` — but
unlike the other five it also has routine, harmless values
(``--max-old-space-size=4096``), so it is content-gated on one of those four
flags rather than the bare assignment.

Default mode is ``ask`` (not ``deny``) — every one of these variables has a
real, sanctioned use (a malloc-debugging library, a documented CI ``BASH_ENV``
bootstrap, a Node ``--require``-based instrumentation loader), same posture
as every sibling ``*_protect`` guard. A dedicated ``mode: deny`` policy is
used below to test the stricter posture explicitly.
"""
import time

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                            # default mode: ask
DENY = Policy(exec_env_hijack={"mode": "deny"})              # stricter, hard-block posture

RULE = "exec-env-hijack-protect"


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


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp_write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                       action=ActionClass.MCP, args={"path": path, "content": content})


def _mcp_nested(content, path=".env"):
    # third-party MCP tool nesting its payload one level deeper than a bare
    # content/new_string key — see _flatten_strings's own docstring.
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__edit_file",
                       action=ActionClass.MCP,
                       args={"path": path, "edits": [{"newText": content}]})


def _gated(d) -> bool:
    return d.action != Action.ALLOW


# ---- LD_PRELOAD / DYLD_INSERT_LIBRARIES: always-dangerous, gated on the
# bare assignment ------------------------------------------------------------

def test_ld_preload_shell_export_gated():
    d = evaluate(_shell("export LD_PRELOAD=/tmp/evil.so"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_ld_preload_shell_bare_assignment_gated():
    d = evaluate(_shell("LD_PRELOAD=/tmp/evil.so ls"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_dyld_insert_libraries_shell_export_gated():
    d = evaluate(_shell("export DYLD_INSERT_LIBRARIES=/tmp/evil.dylib"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_ld_preload_dotenv_write_gated():
    d = evaluate(_write(".env", "LD_PRELOAD=/tmp/evil.so\n"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_ld_preload_dockerfile_env_gated():
    d = evaluate(_write("Dockerfile", "ENV LD_PRELOAD=/tmp/evil.so\n"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_ld_preload_compose_environment_block_gated():
    content = "services:\n  app:\n    environment:\n      LD_PRELOAD: /tmp/evil.so\n"
    d = evaluate(_write("docker-compose.yml", content), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_ld_preload_k8s_split_name_value_gated():
    content = (
        "spec:\n  containers:\n  - name: agent\n    env:\n"
        "    - name: LD_PRELOAD\n      value: /tmp/evil.so\n"
    )
    d = evaluate(_write("k8s/deployment.yaml", content), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_ld_preload_powershell_env_form_gated():
    d = evaluate(_shell('$env:LD_PRELOAD = "/tmp/evil.so"'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_ld_preload_windows_setx_gated():
    d = evaluate(_shell("setx LD_PRELOAD C:\\evil.so"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_ld_preload_fish_set_dash_x_gated():
    d = evaluate(_shell("set -x LD_PRELOAD /tmp/evil.so"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_ld_preload_csh_setenv_gated():
    d = evaluate(_shell("setenv LD_PRELOAD /tmp/evil.so"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_ld_preload_printf_v_gated():
    d = evaluate(_shell('printf -v LD_PRELOAD "%s" /tmp/evil.so; export LD_PRELOAD'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_ld_preload_via_mcp_nested_args():
    d = evaluate(_mcp_nested("LD_PRELOAD=/tmp/evil.so"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_ld_preload_via_edit_new_string():
    d = evaluate(_edit(".env", new_string="LD_PRELOAD=/tmp/evil.so"), EMPTY)
    assert _gated(d) and d.rule == RULE


# ---- BASH_ENV / PERL5OPT / RUBYOPT -----------------------------------------

def test_bash_env_shell_export_gated():
    d = evaluate(_shell("export BASH_ENV=/tmp/evil.sh"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_bash_env_ci_workflow_style_yaml_gated():
    content = "jobs:\n  build:\n    env:\n      BASH_ENV: /tmp/evil.sh\n"
    d = evaluate(_write("deploy/env.yaml", content), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_perl5opt_shell_export_gated():
    d = evaluate(_shell("export PERL5OPT=-Mevil::module"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_rubyopt_shell_export_gated():
    d = evaluate(_shell("export RUBYOPT=-r/tmp/evil.rb"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_rubyopt_dotenv_write_gated():
    d = evaluate(_write(".env", "RUBYOPT=-r/tmp/evil.rb\n"), EMPTY)
    assert _gated(d) and d.rule == RULE


# ---- NODE_OPTIONS: content-gated on a code-loading flag --------------------

def test_node_options_require_gated():
    d = evaluate(_shell("export NODE_OPTIONS='--require /tmp/evil.js'"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_node_options_loader_gated():
    d = evaluate(_shell("export NODE_OPTIONS='--loader /tmp/evil-loader.mjs'"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_node_options_experimental_loader_gated():
    d = evaluate(_write(".env", "NODE_OPTIONS=--experimental-loader=/tmp/evil.mjs\n"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_node_options_import_gated():
    d = evaluate(_shell("export NODE_OPTIONS='--import /tmp/evil.mjs'"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_node_options_short_flag_r_gated():
    d = evaluate(_shell("export NODE_OPTIONS='-r /tmp/evil.js'"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_node_options_harmless_flag_not_gated():
    # the entire reason NODE_OPTIONS is content-gated rather than bare-
    # assignment-gated — this exact shape is routine on containerized deploys.
    assert not evaluate(
        _shell("export NODE_OPTIONS='--max-old-space-size=4096'"), EMPTY).blocked
    assert not evaluate(
        _write(".env", "NODE_OPTIONS=--enable-source-maps --no-warnings\n"), EMPTY).blocked


def test_node_options_dockerfile_require_gated():
    d = evaluate(_write("Dockerfile", 'ENV NODE_OPTIONS="--require /tmp/evil.js"\n'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_node_options_snapshot_blob_gated():
    """QA finding (independent adversarial review, round 1 — reproduced live
    against a real `node` binary): Node accepts `--snapshot-blob=<path>` via
    NODE_OPTIONS and runs whatever `v8.startupSnapshot.
    setDeserializeMainFunction()` callback is baked into the referenced
    (opaque, non-source) blob INSTEAD of the target script — a full
    code-execution primitive that carries no `require`/`import`/`loader`
    keyword anywhere in the command, and originally sailed through the
    four-flag content gate untouched."""
    d = evaluate(_shell("export NODE_OPTIONS='--snapshot-blob=/tmp/evil.blob'"), EMPTY)
    assert _gated(d) and d.rule == RULE


# ---- escape hatches: human-only ---------------------------------------------

def test_human_can_override_shell_with_comment():
    assert not _gated(evaluate(
        _shell("export LD_PRELOAD=/tmp/evil.so  # aegis-allow"), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(
        _shell("export LD_PRELOAD=/tmp/evil.so  # aegis-allow"), EMPTY))


def test_env_toggle_allows_edit_and_shell(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_EXEC_ENV_HIJACK", "1")
    assert not _gated(evaluate(_write(".env", "LD_PRELOAD=/tmp/evil.so\n"), EMPTY))
    assert not _gated(evaluate(_shell("export LD_PRELOAD=/tmp/evil.so"), EMPTY))


# ---- modes: ask (default) / deny / monitor / off ----------------------------

def test_default_mode_is_ask():
    d = evaluate(_shell("export LD_PRELOAD=/tmp/evil.so"), EMPTY)
    assert d.action == Action.ASK and d.rule == RULE


def test_deny_mode_hard_blocks():
    d = evaluate(_shell("export LD_PRELOAD=/tmp/evil.so"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == RULE


def test_monitor_mode_logs_and_allows():
    pol = Policy(exec_env_hijack={"mode": "monitor"})
    assert not _gated(evaluate(_shell("export LD_PRELOAD=/tmp/evil.so"), pol))
    assert not _gated(evaluate(_write(".env", "BASH_ENV=/tmp/evil.sh\n"), pol))


def test_off_mode_disables_guard():
    pol = Policy(exec_env_hijack={"mode": "off"})
    assert not _gated(evaluate(_shell("export LD_PRELOAD=/tmp/evil.so"), pol))


def test_mode_off_unquoted_yaml_boolean_disables_guard():
    """YAML 1.1 parses an unquoted `off` as boolean False — the guard must
    still recognize it as 'disabled', the same fix every sibling *_protect
    guard already applies for its own `mode` knob."""
    pol = Policy(exec_env_hijack={"mode": False})
    assert not _gated(evaluate(_shell("export LD_PRELOAD=/tmp/evil.so"), pol))


def test_policy_allow_regex_exempts_trusted_path():
    pol = Policy(exec_env_hijack={"allow": [r"deploy/trusted\.env"]})
    assert not _gated(evaluate(_write("deploy/trusted.env", "LD_PRELOAD=/opt/edr.so\n"), pol))
    assert _gated(evaluate(_write(".env", "LD_PRELOAD=/opt/edr.so\n"), pol))


def test_policy_allow_regex_exempts_trusted_shell_command():
    pol = Policy(exec_env_hijack={"allow": [r"trusted-profiler\.sh"]})
    assert not _gated(evaluate(
        _shell("bash trusted-profiler.sh && export LD_PRELOAD=/opt/prof.so"), pol))
    assert _gated(evaluate(_shell("export LD_PRELOAD=/opt/prof.so"), pol))


# ---- false-positive guards ---------------------------------------------------

def test_allows_ordinary_mentions_with_no_assignment():
    assert not evaluate(_shell("grep LD_PRELOAD .env"), EMPTY).blocked
    assert not evaluate(_shell('echo "LD_PRELOAD is a dangerous env var"'), EMPTY).blocked
    assert not evaluate(
        _write("notes.md", "LD_PRELOAD lets you inject a shared library."), EMPTY).blocked


def test_allows_unrelated_env_assignment():
    assert not evaluate(_shell("export PATH=/usr/local/bin:$PATH"), EMPTY).blocked
    assert not evaluate(_write(".env", "DATABASE_URL=postgres://x\n"), EMPTY).blocked


def test_allows_unrelated_word_boundary_near_misses():
    # near-miss variable names must not match the strict word-boundary check.
    assert not evaluate(_shell("export BASH_ENVIRONMENT=/tmp/x"), EMPTY).blocked
    assert not evaluate(_shell("export LD_PRELOADED_THING=/tmp/x"), EMPTY).blocked


def test_allows_python_dict_style_access():
    content = 'os.environ["LD_PRELOAD"] = "/tmp/x"\n'
    assert not evaluate(_write("scratch.py", content), EMPTY).blocked


def test_allows_non_carrier_source_file_with_assignment_shaped_content():
    # the exact same dangerous-looking content in a file nothing loads into
    # an environment (a plain .txt) is not gated — only the carrier-path
    # check matters here, not the content shape.
    assert not evaluate(_write("notes.txt", "LD_PRELOAD=/tmp/evil.so\n"), EMPTY).blocked


def test_allows_dotenv_example_template_file():
    assert not evaluate(_write(".env.example", "LD_PRELOAD=\n"), EMPTY).blocked


def test_allows_commented_out_assignment():
    # a documentation/TODO line merely mentioning the shape inside a comment,
    # never actually setting it — the same comment-stripping convention
    # rule_docker_cred_helper_protect/rule_cloud_cred_exec_protect apply.
    content = "# to preload a profiler: LD_PRELOAD=/opt/profiler.so\nDATABASE_URL=x\n"
    assert not evaluate(_write(".env", content), EMPTY).blocked


def test_allows_readme_documentation_with_assignment_example():
    content = (
        "## Profiling\n\nTo preload jemalloc, run:\n\n"
        "    LD_PRELOAD=/usr/lib/libjemalloc.so ./app\n"
    )
    assert not evaluate(_write("docs/PROFILING.md", content), EMPTY).blocked


# ---- carrier-path gating: shell rc/profile dotfiles stay covered -----------

def test_carrier_gate_covers_shell_profile_dotfiles():
    # rule_shell_persist_protect already ASKs on ANY write to these paths
    # (content-independent) and runs earlier in BUILTIN_RULES, so its
    # decision wins first — a STRONGER-or-equal outcome, not a gap, the same
    # "already denied by an earlier guard" precedent
    # test_docker_cred_helper_protect.py documents for containment. What
    # matters here is that the write is still gated, not which of the two
    # equally-escapable ask guards reports it.
    for path in (".bashrc", ".bash_profile", ".profile", ".zshrc"):
        d = evaluate(_write(path, "export LD_PRELOAD=/tmp/evil.so\n"), EMPTY)
        assert _gated(d), path


def test_carrier_gate_covers_wrapper_script():
    d = evaluate(_write("entrypoint.sh", "export BASH_ENV=/tmp/evil.sh\n"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_carrier_gate_covers_makefile_and_justfile():
    """QA finding (independent adversarial review, round 1 — reproduced live
    via evaluate()): a Makefile/justfile recipe line genuinely exports the
    variable into every command that recipe subsequently runs, but had no
    entry at all in the original carrier-path list — one of the single most
    common, routinely-edited project file types there is, sailing through
    to a clean ALLOW with no sibling guard providing a fallback."""
    for path in ("Makefile", "makefile", "GNUmakefile", "build.mk", "justfile"):
        d = evaluate(_write(path, "deploy:\n\texport LD_PRELOAD=/tmp/evil.so\n"), EMPTY)
        assert _gated(d) and d.rule == RULE, path


# ---- performance / ReDoS -----------------------------------------------------

def test_no_catastrophic_backtracking():
    from aegis import patterns

    adversarial = [
        "LD_PRELOAD" * 20_000,
        "ENV " * 50_000 + "LD_PRELOAD",
        "environment:\n  - FOO=bar\n" * 20_000,
        "set -x -y -z " * 20_000,
        "export " * 50_000,
        "NODE_OPTIONS=" * 20_000 + "--require",
    ]
    for text in adversarial:
        start = time.time()
        patterns.exec_env_hijack_hit(text)
        elapsed = time.time() - start
        assert elapsed < 1.0, f"exec_env_hijack_hit took {elapsed:.2f}s on adversarial input"

    start = time.time()
    evaluate(_shell("echo x " * 20_000), EMPTY)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"rule_exec_env_hijack_protect took {elapsed:.2f}s on adversarial input"
