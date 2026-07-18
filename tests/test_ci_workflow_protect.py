"""CI/CD pipeline-definition protection guard — blocks planting/altering a GitHub
Actions workflow/composite action, GitLab CI, CircleCI, Azure Pipelines, Travis,
Jenkinsfile, Drone, Bitbucket Pipelines, Buildkite, Cloud Build, or AppVeyor
config. A step planted there runs on a FUTURE, DIFFERENT machine (the CI runner)
that typically holds more privilege than the current session — a durable,
cross-machine backdoor no shell/network guard in this session ever observes.
"""
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()


def _edit(path, tool="Edit"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args={"file_path": path})


def _write(path):
    return _edit(path, tool="Write")


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp_write(path):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                       args={"path": path})


def _mcp_write_arg(key, path):
    """An MCP filesystem-server tool using a non-Claude-Code arg key for its target."""
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write",
                       action=ActionClass.MCP, args={key: path})


# ---- each provider's canonical path, via Edit/Write --------------------------

def test_github_actions_workflow_blocked():
    d = evaluate(_edit(".github/workflows/ci.yml"), EMPTY)
    assert d.blocked and d.rule == "ci-workflow-protect"


def test_github_actions_workflow_yaml_ext_blocked():
    assert evaluate(_write(".github/workflows/deploy.yaml"), EMPTY).blocked


def test_github_composite_action_blocked():
    assert evaluate(_edit(".github/actions/build/action.yml"), EMPTY).blocked


def test_gitlab_ci_blocked():
    assert evaluate(_write(".gitlab-ci.yml"), EMPTY).blocked


def test_circleci_config_blocked():
    assert evaluate(_edit(".circleci/config.yml"), EMPTY).blocked


def test_azure_pipelines_blocked():
    assert evaluate(_write("azure-pipelines.yml"), EMPTY).blocked


def test_travis_blocked():
    assert evaluate(_edit(".travis.yml"), EMPTY).blocked


def test_jenkinsfile_blocked():
    assert evaluate(_write("Jenkinsfile"), EMPTY).blocked


def test_drone_blocked():
    assert evaluate(_edit(".drone.yml"), EMPTY).blocked


def test_bitbucket_pipelines_blocked():
    assert evaluate(_write("bitbucket-pipelines.yml"), EMPTY).blocked


def test_buildkite_blocked():
    assert evaluate(_edit(".buildkite/pipeline.yml"), EMPTY).blocked


def test_cloudbuild_blocked():
    assert evaluate(_write("cloudbuild.yaml"), EMPTY).blocked


def test_appveyor_blocked():
    assert evaluate(_edit(".appveyor.yml"), EMPTY).blocked


def test_nested_repo_path_blocked():
    assert evaluate(_write("repo/.github/workflows/release.yml"), EMPTY).blocked


# ---- MCP-tool writes (no Edit/Write, no shell) --------------------------------

def test_mcp_tool_write_to_workflow_blocked():
    d = evaluate(_mcp_write(".github/workflows/ci.yml"), EMPTY)
    assert d.blocked and d.rule == "ci-workflow-protect"


def test_mcp_tool_alternate_path_arg_keys_blocked():
    for key in ("target_file", "targetFile", "filename", "file", "uri"):
        d = evaluate(_mcp_write_arg(key, ".github/workflows/ci.yml"), EMPTY)
        assert d.blocked and d.rule == "ci-workflow-protect", key


# ---- shell-based mutation ------------------------------------------------------

def test_shell_redirect_to_workflow_blocked():
    assert evaluate(_shell("echo 'malicious: yaml' > .github/workflows/ci.yml"), EMPTY).blocked
    assert evaluate(_shell("cat evil.yml | tee .gitlab-ci.yml"), EMPTY).blocked
    assert evaluate(_shell("Set-Content azure-pipelines.yml -Value 'x'"), EMPTY).blocked


def test_shell_delete_workflow_blocked():
    assert evaluate(_shell("rm .github/workflows/ci.yml"), EMPTY).blocked


def test_shell_inplace_edit_and_copy_blocked():
    assert evaluate(_shell("sed -i 's/checkout/evil/' .github/workflows/ci.yml"), EMPTY).blocked
    assert evaluate(_shell("perl -i -pe 's/a/b/' .github/workflows/ci.yml"), EMPTY).blocked
    assert evaluate(_shell("cp evil.yml .github/workflows/ci.yml"), EMPTY).blocked
    assert evaluate(_shell("dd if=evil.yml of=.circleci/config.yml"), EMPTY).blocked
    assert evaluate(
        _shell("python3 -c \"open('.github/workflows/ci.yml','w').write(payload)\""),
        EMPTY).blocked


def test_shell_read_only_of_workflow_not_blocked():
    """A read-only command that merely mentions the path (no write verb) is not a
    mutation and must not false-positive."""
    assert not evaluate(_shell("cat .github/workflows/ci.yml"), EMPTY).blocked
    assert not evaluate(_shell("grep run: .github/workflows/ci.yml"), EMPTY).blocked


# ---- escape hatches: human-only ------------------------------------------------

def test_human_can_override_shell_with_comment():
    assert not evaluate(
        _shell("echo trusted >> .github/workflows/ci.yml  # aegis-allow"), EMPTY).blocked


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert evaluate(
        _shell("echo evil >> .github/workflows/ci.yml  # aegis-allow"), EMPTY).blocked


def test_env_toggle_allows_edit_and_shell(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CI_WORKFLOW", "1")
    assert not evaluate(_edit(".github/workflows/ci.yml"), EMPTY).blocked
    assert not evaluate(_shell("echo x >> .github/workflows/ci.yml"), EMPTY).blocked


# ---- false-positive guards -----------------------------------------------------

def test_unrelated_edit_allowed():
    assert not evaluate(_edit("src/app.py"), EMPTY).blocked
    assert not evaluate(_write("README.md"), EMPTY).blocked


def test_unrelated_shell_redirect_allowed():
    assert not evaluate(_shell("echo hello > output.txt"), EMPTY).blocked


def test_reading_workflow_allowed():
    read_ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Read",
                          args={"file_path": ".github/workflows/ci.yml"})
    assert not evaluate(read_ev, EMPTY).blocked


def test_workflow_word_in_unrelated_path_not_blocked():
    """A filename that merely contains 'workflow'/'pipeline' text but isn't one of
    the recognized provider paths must not false-positive."""
    assert not evaluate(_write("src/workflows/README.md"), EMPTY).blocked
    assert not evaluate(_write("docs/pipeline-notes.yml"), EMPTY).blocked


def test_commit_message_mention_not_blocked():
    assert not evaluate(
        _shell('git commit -m "update .github/workflows/ci.yml docs"'), EMPTY).blocked


# ---- modes: ask / monitor / off -------------------------------------------------

def test_ask_mode_surfaces_interactive_approval_instead_of_hard_deny():
    pol = Policy(ci_workflow={"mode": "ask"})
    d = evaluate(_edit(".github/workflows/ci.yml"), pol)
    assert d.action == Action.ASK and d.rule == "ci-workflow-protect"
    d2 = evaluate(_shell("echo x >> .github/workflows/ci.yml"), pol)
    assert d2.action == Action.ASK


def test_monitor_mode_logs_and_allows():
    pol = Policy(ci_workflow={"mode": "monitor"})
    assert not evaluate(_edit(".github/workflows/ci.yml"), pol).blocked
    assert not evaluate(_shell("echo x >> .github/workflows/ci.yml"), pol).blocked


def test_off_mode_disables_guard():
    pol = Policy(ci_workflow={"mode": "off"})
    assert not evaluate(_edit(".github/workflows/ci.yml"), pol).blocked


def test_policy_allow_regex_exempts_trusted_path():
    pol = Policy(ci_workflow={"allow": [r"trusted-repo/\.github/workflows/"]})
    assert not evaluate(_write("trusted-repo/.github/workflows/ci.yml"), pol).blocked
    assert evaluate(_write("other-repo/.github/workflows/ci.yml"), pol).blocked
