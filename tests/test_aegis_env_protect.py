"""Aegis's own trust-boundary environment variables — never escapable.

THREAT MODEL: every other guard in this file assumes the enforcement engine
itself is intact. Seven env vars are read directly by ``aegis.config`` /
``aegis.engine`` / ``aegis.plugins`` / ``aegis.rules._confine_root`` before
any policy rule ever runs, so setting one bypasses the engine rather than any
one guard inside it: ``AEGIS_NO_BUILTINS`` (skips every built-in rule
outright), ``AEGIS_PLUGINS`` (imports arbitrary Python modules and runs them
as rule functions inside the trusted enforcement process),
``AEGIS_POLICIES``/``AEGIS_HOME`` (relocate the policy directory somewhere
self-protect's own fixed ``.aegis`` path patterns never look),
``AEGIS_AUDIT`` (redirects the audit log — tampering/suppression SECURITY.md
lists as explicitly in scope), and ``AEGIS_PROJECT``/``AEGIS_WORKSPACE``
(widen or relocate the workspace-confinement root ahead of the operator's own
configured path — the same engine-reads-env-first shape, one guard over from
``rule_workspace_confine``, found by independent QA round 2 of this guard).

Unlike most ``*_protect`` guards here, there is no ``mode``, no
``AEGIS_ALLOW_*`` knob, and no ``# aegis-allow`` escape — the same "No, not
even human-only" posture ``rule_containment``/``rule_self_protect`` already
use, because this guard's whole job is keeping those intact. The
Edit/Write/MCP branch additionally requires the target path to look like
something that actually loads into a process environment
(``patterns.env_carrier_path_hit()``) before scanning content — QA round 1
found an earlier, path-unrestricted draft hard-denied ordinary documentation
with no escape hatch at all; the shell branch has no such restriction.
"""
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()  # no config surface at all for this guard — always on


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
    # third-party MCP tool nesting its payload one level deeper than a bare
    # `content`/`new_string` key — see `_flatten_strings`'s own docstring.
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__edit_file",
                       action=ActionClass.MCP,
                       args={"path": path, "edits": [{"newText": content}]})


def _gated(d) -> bool:
    return d.action != Action.ALLOW


# ---- AEGIS_NO_BUILTINS ---------------------------------------------------
def test_blocks_no_builtins_shell_export():
    d = evaluate(_shell("export AEGIS_NO_BUILTINS=1"), EMPTY)
    assert _gated(d) and d.rule == "aegis-env-protect"


def test_blocks_no_builtins_dotenv_write():
    d = evaluate(_write(".env", "AEGIS_NO_BUILTINS=1\n"), EMPTY)
    assert _gated(d) and d.rule == "aegis-env-protect"


# ---- AEGIS_PLUGINS --------------------------------------------------------
def test_blocks_plugins_shell_assignment():
    d = evaluate(_shell("AEGIS_PLUGINS=/tmp/evil_plugin.py python app.py"), EMPTY)
    assert _gated(d)


def test_blocks_plugins_dockerfile_env():
    d = evaluate(_write("Dockerfile", "ENV AEGIS_PLUGINS=/opt/evil_plugin.py\n"), EMPTY)
    assert _gated(d)


def test_blocks_plugins_dockerfile_env_two_token_form():
    # Dockerfile's ENV instruction also accepts a bare space, no '=' at all.
    d = evaluate(_write("Dockerfile", "ENV AEGIS_PLUGINS /opt/evil_plugin.py\n"), EMPTY)
    assert _gated(d)


def test_blocks_plugins_compose_environment_block():
    content = "services:\n  app:\n    environment:\n      AEGIS_PLUGINS: /opt/evil_plugin.py\n"
    d = evaluate(_write("docker-compose.yml", content), EMPTY)
    assert _gated(d)


def test_blocks_plugins_compose_list_form():
    content = "services:\n  app:\n    environment:\n      - AEGIS_PLUGINS=/opt/evil_plugin.py\n"
    d = evaluate(_write("docker-compose.yml", content), EMPTY)
    assert _gated(d)


def test_blocks_plugins_powershell_env_form():
    d = evaluate(_shell('$env:AEGIS_PLUGINS = "C:\\evil_plugin.py"'), EMPTY)
    assert _gated(d)


def test_blocks_plugins_windows_setx():
    d = evaluate(_shell("setx AEGIS_PLUGINS C:\\evil_plugin.py"), EMPTY)
    assert _gated(d)


def test_blocks_plugins_via_edit_new_string():
    d = evaluate(_edit(".env", new_string="AEGIS_PLUGINS=/tmp/evil.py"), EMPTY)
    assert _gated(d)


def test_blocks_plugins_via_mcp_write():
    d = evaluate(_mcp_write(".env", "AEGIS_PLUGINS=/tmp/evil.py\n"), EMPTY)
    assert _gated(d)


def test_blocks_plugins_via_mcp_nested_args():
    # a third-party MCP filesystem server nesting its payload under
    # edits/newText rather than a bare content/new_string key.
    d = evaluate(_mcp_nested("AEGIS_PLUGINS=/tmp/evil.py"), EMPTY)
    assert _gated(d)


# ---- QA round 1 (independent adversarial review): dialects the original
# four assignment shapes missed entirely --------------------------------
def test_blocks_plugins_csh_setenv():
    d = evaluate(_shell("setenv AEGIS_PLUGINS /tmp/evil_plugin.py"), EMPTY)
    assert _gated(d)


def test_blocks_plugins_fish_set_dash_x():
    d = evaluate(_shell("set -x AEGIS_PLUGINS /tmp/evil_plugin.py"), EMPTY)
    assert _gated(d)


def test_blocks_plugins_fish_set_universal_export():
    d = evaluate(_shell("set -Ux AEGIS_PLUGINS /tmp/evil_plugin.py"), EMPTY)
    assert _gated(d)


def test_blocks_bare_export_no_equals():
    # re-exporting a name already assigned some other way — no '=' at all.
    d = evaluate(_shell("declare AEGIS_PLUGINS=/tmp/x; export AEGIS_PLUGINS"), EMPTY)
    assert _gated(d)


def test_blocks_printf_v_builtin():
    d = evaluate(_shell('printf -v AEGIS_PLUGINS "%s" /tmp/evil.py; export AEGIS_PLUGINS'), EMPTY)
    assert _gated(d)


def test_blocks_k8s_split_name_value_block_form():
    content = (
        "spec:\n  containers:\n  - name: agent\n    env:\n"
        "    - name: AEGIS_PLUGINS\n      value: /opt/evil_plugin.py\n"
    )
    d = evaluate(_write("k8s/deployment.yaml", content), EMPTY)
    assert _gated(d)


def test_blocks_k8s_split_name_value_flow_form():
    content = 'env: [{name: AEGIS_PLUGINS, value: "/opt/evil_plugin.py"}]\n'
    d = evaluate(_write("k8s/deployment.yaml", content), EMPTY)
    assert _gated(d)


# ---- AEGIS_POLICIES / AEGIS_HOME / AEGIS_AUDIT ---------------------------
def test_blocks_policies_relocation():
    d = evaluate(_shell("export AEGIS_POLICIES=/tmp/shadow-policies"), EMPTY)
    assert _gated(d)


def test_blocks_home_relocation():
    d = evaluate(_write(".env", "AEGIS_HOME=/tmp/shadow-aegis\n"), EMPTY)
    assert _gated(d)


def test_blocks_audit_redirect():
    d = evaluate(_shell("export AEGIS_AUDIT=/dev/null"), EMPTY)
    assert _gated(d)


# ---- AEGIS_PROJECT / AEGIS_WORKSPACE (QA round 2 finding) -----------------
def test_blocks_project_confinement_override():
    d = evaluate(_shell("export AEGIS_PROJECT=/"), EMPTY)
    assert _gated(d) and d.rule == "aegis-env-protect"


def test_blocks_workspace_confinement_override():
    d = evaluate(_write(".env", "AEGIS_WORKSPACE=/tmp/attacker-controlled\n"), EMPTY)
    assert _gated(d)


# ---- never escapable -------------------------------------------------------
def test_not_escapable_with_override_token():
    d = evaluate(_shell("export AEGIS_PLUGINS=/tmp/evil.py  # aegis-allow"), EMPTY)
    assert _gated(d) and d.rule == "aegis-env-protect"


def test_not_escapable_via_env_allow_knob():
    # unlike ci_workflow/claude_hooks/etc., there is no per-guard AEGIS_ALLOW_*
    # escape hatch for this one at all — setting an unrelated allow flag must
    # not suppress it.
    import os
    os.environ["AEGIS_ALLOW_AEGIS_ENV"] = "1"
    try:
        d = evaluate(_shell("export AEGIS_PLUGINS=/tmp/evil.py"), EMPTY)
        assert _gated(d)
    finally:
        del os.environ["AEGIS_ALLOW_AEGIS_ENV"]


# ---- false-positive guards --------------------------------------------------
def test_allows_ordinary_env_reads_and_mentions():
    # a bare mention/read with no assignment syntax must not be gated — the
    # engine's own source (os.environ.get("AEGIS_PLUGINS")) is exactly this
    # shape, and self-protect (a separate guard) already covers editing it.
    assert not evaluate(_shell("grep AEGIS_PLUGINS .env"), EMPTY).blocked
    assert not evaluate(_shell('echo "AEGIS_PLUGINS is a dangerous env var"'), EMPTY).blocked
    assert not evaluate(
        _write("notes.md", "AEGIS_PLUGINS lets you register custom guard rules."),
        EMPTY,
    ).blocked


def test_allows_python_dict_style_access():
    # os.environ["AEGIS_PLUGINS"] = "x" has no bare `AEGIS_PLUGINS=`/`AEGIS_PLUGINS
    # :` adjacency (the closing bracket/quote sits in between) — this rule
    # deliberately doesn't chase every possible Python spelling (aegis's own
    # source under this exact shape is separately covered by self-protect).
    content = 'os.environ["AEGIS_PLUGINS"] = "x"\n'
    assert not evaluate(_write("scratch.py", content), EMPTY).blocked


def test_allows_unrelated_env_assignment():
    assert not evaluate(_shell("export PATH=/usr/local/bin:$PATH"), EMPTY).blocked
    assert not evaluate(_write(".env", "DATABASE_URL=postgres://x\n"), EMPTY).blocked


def test_allows_unrelated_yaml_env_block():
    content = "services:\n  app:\n    environment:\n      DATABASE_URL: postgres://x\n"
    assert not evaluate(_write("docker-compose.yml", content), EMPTY).blocked


# ---- carrier-path gating (QA round 1 fix: docs get no path-based pass) ----
def test_allows_readme_documentation_with_assignment_example():
    # a README/troubleshooting doc showing the exact assignment shape as an
    # EXAMPLE must not be gated — .md is not a file anything loads into a
    # process environment, and this guard has no escape hatch at all.
    content = (
        "## Troubleshooting\n\nTo temporarily disable built-ins, run:\n\n"
        "    AEGIS_NO_BUILTINS=1 npm test\n"
    )
    assert not evaluate(_write("docs/TROUBLESHOOTING.md", content), EMPTY).blocked


def test_allows_config_docs_with_dotenv_example_in_markdown():
    content = "Example `.env` entry:\n\n```\nAEGIS_PLUGINS=my_org.trusted_rules\n```\n"
    assert not evaluate(_write("docs/CONFIG.md", content), EMPTY).blocked


def test_allows_bulleted_var_description_in_markdown():
    content = "- AEGIS_HOME: the directory Aegis stores its policy and audit log under\n"
    assert not evaluate(_write("docs/ENV_VARS.md", content), EMPTY).blocked


def test_allows_dotenv_example_template_file():
    # a checked-in .env.example/.env.sample/.env.template/.env.dist is a
    # template for humans to copy and hand-edit, never loaded as-is.
    assert not evaluate(_write(".env.example", "AEGIS_PLUGINS=\n"), EMPTY).blocked
    assert not evaluate(_write(".env.sample", "AEGIS_NO_BUILTINS=\n"), EMPTY).blocked


def test_allows_non_carrier_source_file_with_assignment_shaped_content():
    # the exact same dangerous-looking content in a file nothing loads into
    # an environment (a Python scratch file, a plain .txt) is not gated —
    # only the carrier-path check below matters here, not the content shape.
    assert not evaluate(_write("scratch.py", "AEGIS_PLUGINS=/tmp/evil.py\n"), EMPTY).blocked
    assert not evaluate(_write("notes.txt", "AEGIS_NO_BUILTINS=1\n"), EMPTY).blocked


def test_still_blocks_real_carrier_paths_despite_carrier_gate():
    # sanity check the carrier gate doesn't accidentally over-exclude the
    # real vectors it's meant to keep covered.
    assert evaluate(_write(".env", "AEGIS_PLUGINS=/tmp/evil.py\n"), EMPTY).blocked
    assert evaluate(_write("Dockerfile", "ENV AEGIS_PLUGINS=/tmp/evil.py\n"), EMPTY).blocked
    assert evaluate(_write("deploy.sh", "export AEGIS_PLUGINS=/tmp/evil.py\n"), EMPTY).blocked
    assert evaluate(_write("run.ps1", '$env:AEGIS_PLUGINS = "x"\n'), EMPTY).blocked


# ---- QA round 3 (independent verification pass): the carrier-path fix
# itself silently dropped coverage for shell rc/profile dotfiles -----------
def test_carrier_gate_still_covers_shell_profile_dotfiles():
    # a shell startup/profile file has no extension the original carrier
    # list recognized, so it fell through to shell-persist-protect's own
    # human-APPROVABLE `ASK` — a real downgrade of a guard advertised as
    # having no escape hatch at all. Must be a hard `aegis-env-protect` DENY,
    # not merely `.blocked` (which an ASK also satisfies).
    for path in (".bashrc", ".bash_profile", ".profile", ".zshrc", ".cshrc",
                 "Microsoft.PowerShell_profile.ps1"):
        d = evaluate(_write(path, "export AEGIS_PLUGINS=/tmp/evil.py\n"), EMPTY)
        assert _gated(d) and d.rule == "aegis-env-protect", path


def test_carrier_gate_covers_procfile():
    d = evaluate(_write("Procfile", "web: AEGIS_PLUGINS=/tmp/evil.py bundle exec puma\n"), EMPTY)
    assert _gated(d) and d.rule == "aegis-env-protect"


def test_no_catastrophic_backtracking():
    """Every content-scanning regex in this file has had at least one ReDoS
    round (see AEGIS_SOURCE_RE's / EXFIL_RE's own comments) — checked here at
    definition time rather than found later against a crafted input."""
    import time
    from aegis import patterns

    adversarial = [
        "AEGIS_" * 50_000,
        "ENV " * 50_000 + "AEGIS_X",
        "environment:\n  - FOO=bar\n" * 20_000,
        "AEGIS_PLUGINS" * 20_000,
        "name: x\n" * 20_000,
        "set -x -y -z " * 20_000,
        "export " * 50_000,
    ]
    for text in adversarial:
        start = time.time()
        patterns.AEGIS_ENV_BYPASS_RE.search(text)
        elapsed = time.time() - start
        assert elapsed < 1.0, f"AEGIS_ENV_BYPASS_RE took {elapsed:.2f}s on adversarial input"

    start = time.time()
    evaluate(_shell("echo x " * 20_000), EMPTY)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"rule_aegis_env_protect took {elapsed:.2f}s on adversarial input"


def test_allows_designed_allow_star_knobs_untouched():
    # the per-guard AEGIS_ALLOW_* human escape hatches (ci_workflow, mcp_config,
    # claude_hooks, ...) are a DESIGNED surface documented on those guards —
    # this rule must not gate them.
    assert not evaluate(_shell("export AEGIS_ALLOW_CI_WORKFLOW=1"), EMPTY).blocked
    assert not evaluate(_shell("export AEGIS_FAIL_CLOSED=1"), EMPTY).blocked
    assert not evaluate(_shell("export AEGIS_IDENTITY_ENFORCE=1"), EMPTY).blocked
