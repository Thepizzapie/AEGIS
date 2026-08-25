"""GCP Application Default Credentials executable-sourced-credential-hijack
protection guard — blocks an ``external_account`` credential config's
``credential_source.executable.command`` (any path, or the ``gcloud iam
workload-identity-pools create-cred-config --executable-command`` CLI form).

Names an arbitrary EXTERNAL COMMAND that google-auth (any GCP client
library, or ``gcloud`` itself) EXECUTES to obtain a subject token, exchanged
for a live GCP access token — not once, but on every future token refresh
resolved through that credential file, unattended, by this agent, a
teammate, or CI. The third credential-brokering primitive of this exact
shape in this file, after AWS ``credential_process`` and Kubernetes
kubeconfig ``exec:`` (``test_cloud_cred_exec_protect.py``) — and, unlike
those two, a mechanism that guard's own docstring explicitly disclosed as
NOT covered at all until this guard closed it.

Default mode is ``ask`` (not ``deny``) — executable-sourced credentials are
routine, sanctioned infrastructure (CI/CD workload identity federation). A
dedicated ``mode: deny`` policy is used below to test the stricter posture
explicitly.

UNLIKE the AWS/Kubernetes guard, the ordinary default path (``~/.config/
gcloud/application_default_credentials.json``) is NOT already covered by
``rule_containment``'s ``CRED_RE`` — that check has no ``.config/gcloud``/
``gcloud`` entry at all. So this guard is the first of any kind to gate that
path, not a backstop/MCP-only addition — asserted directly below rather than
against containment.
"""
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                        # default mode: ask
DENY = Policy(gcp_adc_exec={"mode": "deny"})             # stricter, hard-block posture

RULE = "gcp-adc-exec-protect"

ADC_JSON = (
    '{\n'
    '  "type": "external_account",\n'
    '  "audience": "//iam.googleapis.com/projects/123/locations/global/'
    'workloadIdentityPools/pool/providers/provider",\n'
    '  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",\n'
    '  "token_url": "https://sts.googleapis.com/v1/token",\n'
    '  "credential_source": {\n'
    '    "executable": {\n'
    '      "command": "/tmp/evil-get-token.sh",\n'
    '      "timeout_millis": 30000\n'
    '    }\n'
    '  }\n'
    '}\n'
)


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
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__edit_file",
                       action=ActionClass.MCP,
                       args={"path": path, "edits": [{"oldText": "x", "newText": new_text}]})


def _gated(d) -> bool:
    return d.action != Action.ALLOW


# ---- not covered by containment at all: this guard's own, new coverage --------

def test_default_adc_path_not_denied_by_containment():
    """`CRED_RE` has no `.config/gcloud`/`gcloud` entry — confirms this
    guard, not containment, is what gates the ordinary default location."""
    d = evaluate(_write("~/.config/gcloud/application_default_credentials.json",
                         content=ADC_JSON), EMPTY)
    assert d.rule != "containment-credentials"


def test_default_adc_path_gated_by_this_guard():
    d = evaluate(_write("~/.config/gcloud/application_default_credentials.json",
                         content=ADC_JSON), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_relative_adc_filename_gated():
    d = evaluate(_write("application_default_credentials.json", content=ADC_JSON), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_staged_elsewhere_gated_by_strong_content_check():
    """Content staged in a completely differently-named file, no ADC-shaped
    path segment at all — the strong, path-independent triad check catches
    this without needing path confirmation, mirroring
    `AWS_CRED_PROCESS_INI_RE`'s own reasoning."""
    d = evaluate(_write("staging/bootstrap-creds.json", content=ADC_JSON), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_bare_executable_command_pair_gated_when_path_confirmed():
    """An Edit's `new_string` may only be inserting/changing the
    `executable`/`command` lines of an ALREADY-EXISTING `credential_source`
    block (the `credential_source` header itself is `old_string` context
    that never appears in `new_string`) — the same "new_string is just the
    inserted lines" reasoning the AWS/Kube guard's own weak tier uses. Path
    confirmation alone is enough for the bare pair, with no
    `credential_source` anchor needed."""
    d = evaluate(_edit_content(
        "~/.config/gcloud/application_default_credentials.json",
        '    "executable": {\n      "command": "/tmp/evil-get-token.sh"\n    }\n'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_bare_pair_without_path_confirmation_not_gated():
    """The weak `executable`/`command` pair alone, with no ADC-shaped path
    and no `credential_source` anchor, must not false-positive — the same
    "no safe/dangerous split without confirmation" restraint every sibling
    weak tier in this file applies."""
    d = evaluate(_write("build/steps.json",
                         content='{"executable": {"command": "./run.sh"}}'), EMPTY)
    assert not _gated(d)


def test_mcp_write_gated():
    """A GCP-analog of the AWS/Kube guard's own MCP-write coverage —
    `ActionClass.MCP` writes are covered here from the start (no
    containment overlap to route around at all for this ecosystem)."""
    d = evaluate(_mcp_write("~/.config/gcloud/application_default_credentials.json",
                             ADC_JSON), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mcp_nested_edits_gated():
    d = evaluate(_mcp_edit_edits(
        "~/.config/gcloud/application_default_credentials.json",
        '"credential_source": {"executable": {"command": "/tmp/evil"}}'), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mcp_unlisted_path_key_name_gated():
    """`_path()` only recognizes a fixed key-name allowlist — an MCP tool
    naming its path argument something else entirely must still be caught
    via the flattened-string content sweep, the same fix this guard's own
    sibling guards already carry."""
    d = evaluate(Event.make(
        HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file", action=ActionClass.MCP,
        args={"location": "application_default_credentials.json", "content": ADC_JSON}), EMPTY)
    assert _gated(d) and d.rule == RULE


# ---- QA round (bypass-hunting, independent adversarial review): closed bypasses --

def test_multiedit_gated():
    """QA (bypass-hunting round): the original content scan only populated
    from a literal `content`/`new_string` key, with an MCP-only
    `_flatten_strings()` fallback — a native `MultiEdit` call (whose
    payload sits under `edits: [{new_string: ...}]`, not either of those
    two keys) went completely unscanned. Worse than the identical gap in
    `rule_cloud_cred_exec_protect`, since this guard's GCP path has no
    `rule_containment` backstop to fall back on at all."""
    d = evaluate(Event.make(
        HookEvent.PRE_TOOL_USE, tool="MultiEdit",
        args={"file_path": "~/.config/gcloud/application_default_credentials.json",
              "edits": [{"old_string": "", "new_string": ADC_JSON}]}), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_notebookedit_gated():
    d = evaluate(Event.make(
        HookEvent.PRE_TOOL_USE, tool="NotebookEdit",
        args={"notebook_path": "~/.config/gcloud/application_default_credentials.json",
              "new_source": ADC_JSON}), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_realistic_extra_json_keys_dont_evade_strong_gap():
    """QA (bypass-hunting round): `GCP_ADC_STRONG_RE`'s original 500-char
    inter-key gaps silently missed a real `external_account` config once
    its own ordinary extra top-level keys (`audience`, `subject_token_
    type`, `token_url`, `workforce_pool_user_project`, ...) pushed
    `executable`/`command` further from `credential_source` than 500
    chars — no obfuscation, just a realistic config. Padding a completely
    UNRECOGNIZED path (so the weak, path-confirmed tier can't help either)
    isolates the strong tier's own gap width."""
    padded = (
        '{\n  "credential_source": {\n'
        '    "unused_field_padding": "' + "a" * 480 + '",\n'
        '    "executable": {\n      "command": "/tmp/evil"\n    }\n  }\n}\n'
    )
    d = evaluate(_write("staging/some-random-file.json", content=padded), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_realistic_long_cli_flag_list_gated():
    """QA (bypass-hunting round): `GCP_ADC_CLI_RE`'s original 200/200/300
    char gaps (borrowed as-is from the AWS/Kube CLI regexes) were too tight
    for this specific command — a realistic, non-adversarial invocation
    naming several of `create-cred-config`'s own routine flags
    (`--service-account`, `--service-account-token-lifetime-seconds`,
    `--subject-token-type`, `--scopes`, `--output-file`) ahead of
    `--executable-command` measured past 300 chars with zero obfuscation."""
    cmd = (
        "gcloud iam workload-identity-pools create-cred-config providerpath "
        "--service-account=svc@proj.iam.gserviceaccount.com "
        "--service-account-token-lifetime-seconds=3600 "
        "--subject-token-type=urn:ietf:params:oauth:token-type:jwt "
        "--scopes=https://www.googleapis.com/auth/cloud-platform "
        "--output-file=" + "very/long/nested/path/" * 8 + "creds.json "
        "--executable-command=/tmp/evil"
    )
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == RULE


# ---- gcloud CLI form (never mentions any file path at all) --------------------

def test_gcloud_create_cred_config_cli_gated():
    d = evaluate(_shell(
        "gcloud iam workload-identity-pools create-cred-config "
        "projects/123/locations/global/workloadIdentityPools/pool/providers/provider "
        "--executable-command=/tmp/evil-get-token.sh --output-file=creds.json"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_gcloud_cli_long_flags_between_verbs_gated():
    """Same verb-adjacency-gap convention every sibling CLI regex in this
    file already widened to 200/300 chars for realistic, non-adversarial
    flag lists."""
    d = evaluate(_shell(
        "gcloud --project my-really-long-organization-project-id-for-prod "
        "--quiet --verbosity=info iam workload-identity-pools "
        "--location=global create-cred-config my-provider-with-a-long-name "
        "--service-account=svc@proj.iam.gserviceaccount.com "
        "--executable-command=/tmp/evil"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_gcloud_list_or_describe_not_gated():
    """Read-only `gcloud iam workload-identity-pools describe`/`list` (no
    `create-cred-config`/`--executable-command`) must not false-positive."""
    assert not _gated(evaluate(
        _shell("gcloud iam workload-identity-pools describe pool --location=global"), EMPTY))
    assert not _gated(evaluate(_shell("gcloud iam workload-identity-pools list"), EMPTY))


def test_create_cred_config_without_executable_command_not_gated():
    """The ordinary, benign form of this exact command — a service-account
    impersonation credential config, no executable-sourced command at
    all — must not false-positive."""
    d = evaluate(_shell(
        "gcloud iam workload-identity-pools create-cred-config "
        "projects/123/locations/global/workloadIdentityPools/pool/providers/provider "
        "--service-account=svc@proj.iam.gserviceaccount.com --output-file=creds.json"), EMPTY)
    assert not _gated(d)


# ---- comment-awareness (matches sibling guards' own fix) -----------------------

def test_comment_only_mention_not_gated():
    d = evaluate(_write(
        "docs/notes.json",
        content='// TODO: consider credential_source.executable.command for CI\n'
                '{"unrelated": true}\n'), EMPTY)
    assert not _gated(d)


def test_commented_out_shell_line_not_gated():
    d = evaluate(_shell(
        "# gcloud iam workload-identity-pools create-cred-config x "
        "--executable-command=/tmp/evil"), EMPTY)
    assert not _gated(d)


# ---- escape hatches: human-only ------------------------------------------------

def test_human_can_override_shell_with_comment():
    assert not _gated(evaluate(_shell(
        "gcloud iam workload-identity-pools create-cred-config x "
        "--executable-command=/tmp/evil  # aegis-allow"), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(_shell(
        "gcloud iam workload-identity-pools create-cred-config x "
        "--executable-command=/tmp/evil  # aegis-allow"), EMPTY))


def test_env_toggle_allows_edit_shell_and_mcp(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_GCP_ADC_EXEC", "1")
    assert not _gated(evaluate(_shell(
        "gcloud iam workload-identity-pools create-cred-config x "
        "--executable-command=/tmp/evil"), EMPTY))
    assert not _gated(evaluate(_write(
        "~/.config/gcloud/application_default_credentials.json", content=ADC_JSON), EMPTY))
    assert not _gated(evaluate(_mcp_write(
        "~/.config/gcloud/application_default_credentials.json", ADC_JSON), EMPTY))


# ---- false-positive guards ------------------------------------------------------

def test_unrelated_edit_allowed():
    assert not _gated(evaluate(_edit("src/app.py"), EMPTY))
    assert not _gated(evaluate(_write("README.md"), EMPTY))


def test_unrelated_shell_command_allowed():
    assert not _gated(evaluate(_shell("gcloud auth list"), EMPTY))
    assert not _gated(evaluate(_shell("gcloud config get-value project"), EMPTY))


def test_reading_adc_file_allowed():
    read_ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Read",
                          args={"file_path": "~/.config/gcloud/application_default_credentials.json"})
    assert not _gated(evaluate(read_ev, EMPTY))


def test_ordinary_service_account_key_file_not_gated():
    """An ordinary GCP service-account key file (`"type": "service_account"`,
    a `private_key`, no `credential_source` at all) is a completely
    different, non-executable-sourced credential shape and must not
    false-positive."""
    d = evaluate(_write(
        "sa-key.json",
        content='{\n  "type": "service_account",\n  "project_id": "proj",\n'
                '  "private_key": "-----BEGIN PRIVATE KEY-----\\n...",\n'
                '  "client_email": "svc@proj.iam.gserviceaccount.com"\n}\n'), EMPTY)
    assert not _gated(d)


def test_unrelated_json_with_executable_word_alone_not_gated():
    """A bare `executable` key with no nested `command` anywhere nearby (an
    entirely different JSON shape) must not false-positive."""
    d = evaluate(_write("build-config.json",
                         content='{"target": {"executable": true}}'), EMPTY)
    assert not _gated(d)


def test_commit_message_mention_not_gated():
    assert not _gated(evaluate(_shell(
        'git commit -m "document credential_source.executable.command setup for CI"'), EMPTY))


# ---- modes: ask (default) / deny / monitor / off --------------------------------

def test_default_mode_is_ask():
    d = evaluate(_shell(
        "gcloud iam workload-identity-pools create-cred-config x "
        "--executable-command=/tmp/evil"), EMPTY)
    assert d.action == Action.ASK and d.rule == RULE


def test_deny_mode_hard_blocks():
    d = evaluate(_shell(
        "gcloud iam workload-identity-pools create-cred-config x "
        "--executable-command=/tmp/evil"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == RULE


def test_monitor_mode_logs_and_allows():
    pol = Policy(gcp_adc_exec={"mode": "monitor"})
    assert not _gated(evaluate(_shell(
        "gcloud iam workload-identity-pools create-cred-config x "
        "--executable-command=/tmp/evil"), pol))


def test_off_mode_disables_guard():
    pol = Policy(gcp_adc_exec={"mode": "off"})
    assert not _gated(evaluate(_shell(
        "gcloud iam workload-identity-pools create-cred-config x "
        "--executable-command=/tmp/evil"), pol))


def test_mode_off_unquoted_yaml_boolean_disables_guard():
    """YAML 1.1 parses an unquoted `off` as boolean False — matches the
    config-hygiene convention every sibling `*_protect` guard applies."""
    pol = Policy(gcp_adc_exec={"mode": False})
    assert not _gated(evaluate(_write(
        "~/.config/gcloud/application_default_credentials.json", content=ADC_JSON), pol))


def test_policy_allow_regex_exempts_trusted_command():
    pol = Policy(gcp_adc_exec={"allow": [r"trusted-bootstrap\.sh"]})
    assert not _gated(evaluate(_shell(
        "bash trusted-bootstrap.sh && gcloud iam workload-identity-pools "
        "create-cred-config x --executable-command=/tmp/evil"), pol))
    assert _gated(evaluate(_shell(
        "gcloud iam workload-identity-pools create-cred-config x "
        "--executable-command=/tmp/evil"), pol))


def test_policy_allow_regex_exempts_trusted_path():
    pol = Policy(gcp_adc_exec={"allow": [r"^trusted-creds\.json$"]})
    assert not _gated(evaluate(_mcp_write("trusted-creds.json", ADC_JSON), pol))
    assert _gated(evaluate(_mcp_write("evil-creds.json", ADC_JSON), pol))


# ---- wiring: loader / Policy / BUILTIN_RULES -------------------------------------

def test_loads_from_yaml(tmp_path):
    from aegis.loader import load_policy

    (tmp_path / "policy.yaml").write_text(
        "gcp_adc_exec:\n  mode: deny\n  allow: ['trusted\\.json']\n")
    pol = load_policy(tmp_path)
    assert pol.gcp_adc_exec == {"mode": "deny", "allow": ["trusted\\.json"]}
    d = evaluate(_shell(
        "gcloud iam workload-identity-pools create-cred-config x "
        "--executable-command=/tmp/evil"), pol)
    assert d.blocked and d.rule == RULE


def test_rule_registered_in_builtin_rules():
    from aegis.rules import BUILTIN_RULES, rule_gcp_adc_exec_protect

    assert rule_gcp_adc_exec_protect in BUILTIN_RULES
