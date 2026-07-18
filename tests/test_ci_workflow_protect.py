"""CI/CD pipeline-definition protection guard — blocks planting/altering a GitHub
Actions workflow/composite action, GitLab CI, CircleCI, Azure Pipelines, Travis,
Jenkinsfile, Drone, Bitbucket Pipelines, Buildkite, Cloud Build, or AppVeyor
config. A step planted there runs on a FUTURE, DIFFERENT machine (the CI runner)
that typically holds more privilege than the current session — a durable,
cross-machine backdoor no shell/network guard in this session ever observes.

Default mode is ``ask`` (not ``deny``) — editing a CI workflow is routine dev
work (bumping an action version, adding a matrix entry), unlike planting an MCP
server; ``ask`` keeps a human in the loop on every change without hard-blocking
ordinary work. A dedicated ``mode: deny`` policy is used below to test the
stricter posture explicitly.
"""
import time

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                    # default mode: ask
DENY = Policy(ci_workflow={"mode": "deny"})          # stricter, hard-block posture


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


def _gated(d) -> bool:
    """True if the guard had an opinion at all (ASK or DENY) — robust to which
    mode is configured, unlike .blocked (DENY only)."""
    return d.action != Action.ALLOW


# ---- each provider's canonical path, via Edit/Write --------------------------

def test_github_actions_workflow_gated():
    d = evaluate(_edit(".github/workflows/ci.yml"), EMPTY)
    assert _gated(d) and d.rule == "ci-workflow-protect"


def test_github_actions_workflow_yaml_ext_gated():
    assert _gated(evaluate(_write(".github/workflows/deploy.yaml"), EMPTY))


def test_github_composite_action_gated():
    assert _gated(evaluate(_edit(".github/actions/build/action.yml"), EMPTY))


def test_github_composite_action_nested_dir_gated():
    """A composite action nested under its own subdirectory (not just one level
    deep) must still be recognized."""
    assert _gated(evaluate(_edit(".github/actions/build/nested/action.yaml"), EMPTY))


def test_gitlab_ci_gated():
    assert _gated(evaluate(_write(".gitlab-ci.yml"), EMPTY))


def test_circleci_config_gated():
    assert _gated(evaluate(_edit(".circleci/config.yml"), EMPTY))


def test_azure_pipelines_gated():
    assert _gated(evaluate(_write("azure-pipelines.yml"), EMPTY))


def test_travis_gated():
    assert _gated(evaluate(_edit(".travis.yml"), EMPTY))


def test_jenkinsfile_gated():
    assert _gated(evaluate(_write("Jenkinsfile"), EMPTY))


def test_drone_gated():
    assert _gated(evaluate(_edit(".drone.yml"), EMPTY))


def test_bitbucket_pipelines_gated():
    assert _gated(evaluate(_write("bitbucket-pipelines.yml"), EMPTY))


def test_buildkite_gated():
    assert _gated(evaluate(_edit(".buildkite/pipeline.yml"), EMPTY))


def test_buildkite_nested_gated():
    assert _gated(evaluate(_edit(".buildkite/pipelines/deploy.yml"), EMPTY))


def test_cloudbuild_gated():
    assert _gated(evaluate(_write("cloudbuild.yaml"), EMPTY))


def test_appveyor_gated():
    assert _gated(evaluate(_edit(".appveyor.yml"), EMPTY))


def test_nested_repo_path_gated():
    assert _gated(evaluate(_write("repo/.github/workflows/release.yml"), EMPTY))


# ---- path-separator / Windows-trim bypass (QA round 1) ------------------------

def test_doubled_slash_does_not_bypass():
    """`.github//workflows/ci.yml` resolves to the same file as the single-slash
    form on every OS — an earlier draft's literal `[/\\]` join missed this."""
    assert _gated(evaluate(_write(".github//workflows/ci.yml"), EMPTY))


def test_dot_component_does_not_bypass():
    """`.github/./workflows/ci.yml` is byte-identical to the real path to the OS."""
    assert _gated(evaluate(_write(".github/./workflows/ci.yml"), EMPTY))


def test_windows_trailing_dot_does_not_bypass():
    """Win32 silently strips trailing '.'/space off a path component before
    resolving it, so '.github./workflows/ci.yml' resolves to the real file."""
    assert _gated(evaluate(_write(".github./workflows/ci.yml"), EMPTY))
    assert _gated(evaluate(_write("azure-pipelines.yml."), EMPTY))


# ---- suffix false-positive fix (QA round 1) -----------------------------------

def test_backup_and_disabled_variants_not_gated():
    """A '.bak'/'.orig'/'.disabled' suffix appended AFTER the real extension is a
    different, harmless file (a backup, or a workflow deliberately disabled by
    renaming) — a bare trailing `\\b` used to match these; it must not."""
    assert not _gated(evaluate(_write("azure-pipelines.yml.bak"), EMPTY))
    assert not _gated(evaluate(_write("Jenkinsfile.disabled"), EMPTY))
    assert not _gated(evaluate(_write(".gitlab-ci.yml.orig"), EMPTY))
    assert not _gated(evaluate(_write(".github/workflows/ci.yml.bak"), EMPTY))


# ---- MCP-tool writes (no Edit/Write, no shell) --------------------------------

def test_mcp_tool_write_to_workflow_gated():
    d = evaluate(_mcp_write(".github/workflows/ci.yml"), EMPTY)
    assert _gated(d) and d.rule == "ci-workflow-protect"


def test_mcp_tool_alternate_path_arg_keys_gated():
    for key in ("target_file", "targetFile", "filename", "file", "uri"):
        d = evaluate(_mcp_write_arg(key, ".github/workflows/ci.yml"), EMPTY)
        assert _gated(d) and d.rule == "ci-workflow-protect", key


# ---- shell-based mutation ------------------------------------------------------

def test_shell_redirect_to_workflow_gated():
    assert _gated(evaluate(_shell("echo 'malicious: yaml' > .github/workflows/ci.yml"), EMPTY))
    assert _gated(evaluate(_shell("cat evil.yml | tee .gitlab-ci.yml"), EMPTY))
    assert _gated(evaluate(_shell("Set-Content azure-pipelines.yml -Value 'x'"), EMPTY))


def test_shell_delete_workflow_gated():
    assert _gated(evaluate(_shell("rm .github/workflows/ci.yml"), EMPTY))


def test_shell_inplace_edit_and_copy_gated():
    assert _gated(evaluate(_shell("sed -i 's/checkout/evil/' .github/workflows/ci.yml"), EMPTY))
    assert _gated(evaluate(_shell("perl -i -pe 's/a/b/' .github/workflows/ci.yml"), EMPTY))
    assert _gated(evaluate(_shell("cp evil.yml .github/workflows/ci.yml"), EMPTY))
    assert _gated(evaluate(_shell("dd if=evil.yml of=.circleci/config.yml"), EMPTY))
    assert _gated(evaluate(
        _shell("python3 -c \"open('.github/workflows/ci.yml','w').write(payload)\""),
        EMPTY))


def test_shell_read_only_of_workflow_not_gated():
    """A read-only command that merely mentions the path (no write verb) is not a
    mutation and must not false-positive."""
    assert not _gated(evaluate(_shell("cat .github/workflows/ci.yml"), EMPTY))
    assert not _gated(evaluate(_shell("grep run: .github/workflows/ci.yml"), EMPTY))


# ---- find-indirection and forced-link bypasses (QA round 1) ------------------

def test_find_path_indirection_gated():
    """`find`'s -path/-name/-regex predicates can name a workflow target without
    the command ever containing its path as one contiguous string."""
    assert _gated(evaluate(_shell("rm $(find . -path '*workflows*' -name ci.yml)"), EMPTY))
    assert _gated(evaluate(_shell("cp evil.yml $(find . -path '*workflows*' -name ci.yml)"),
                            EMPTY))
    assert _gated(evaluate(_shell("mv evil.yml $(find . -regex '.*workflows.*ci\\.yml')"),
                            EMPTY))


def test_forced_symlink_swap_gated():
    """`ln -sf`/`ln -f` overwrite the target without any delete/move/redirect/
    in-place-edit verb — a distinct write shape from all four verb checks."""
    assert _gated(evaluate(_shell("ln -sf evil.yml .github/workflows/ci.yml"), EMPTY))
    assert _gated(evaluate(_shell("ln -f evil.yml .github/workflows/ci.yml"), EMPTY))


def test_forced_new_item_gated():
    assert _gated(evaluate(
        _shell("New-Item .github/workflows/ci.yml -ItemType File -Value evil -Force"), EMPTY))


def test_plain_ln_without_force_not_gated():
    """A plain `ln` (no force flag) refuses if the target already exists — not
    itself a dangerous overwrite, and excluding it avoids over-broad matching."""
    assert not _gated(evaluate(_shell("ln evil.yml .github/workflows/new-file.yml"), EMPTY))


# ---- escape hatches: human-only ------------------------------------------------

def test_human_can_override_shell_with_comment():
    assert not _gated(evaluate(
        _shell("echo trusted >> .github/workflows/ci.yml  # aegis-allow"), EMPTY))


def test_agent_cannot_override_shell_with_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert _gated(evaluate(
        _shell("echo evil >> .github/workflows/ci.yml  # aegis-allow"), EMPTY))


def test_env_toggle_allows_edit_and_shell(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CI_WORKFLOW", "1")
    assert not _gated(evaluate(_edit(".github/workflows/ci.yml"), EMPTY))
    assert not _gated(evaluate(_shell("echo x >> .github/workflows/ci.yml"), EMPTY))


# ---- false-positive guards -----------------------------------------------------

def test_unrelated_edit_allowed():
    assert not _gated(evaluate(_edit("src/app.py"), EMPTY))
    assert not _gated(evaluate(_write("README.md"), EMPTY))


def test_unrelated_shell_redirect_allowed():
    assert not _gated(evaluate(_shell("echo hello > output.txt"), EMPTY))


def test_reading_workflow_allowed():
    read_ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Read",
                          args={"file_path": ".github/workflows/ci.yml"})
    assert not _gated(evaluate(read_ev, EMPTY))


def test_workflow_word_in_unrelated_path_not_gated():
    """A filename that merely contains 'workflow'/'pipeline' text but isn't one of
    the recognized provider paths must not false-positive."""
    assert not _gated(evaluate(_write("src/workflows/README.md"), EMPTY))
    assert not _gated(evaluate(_write("docs/pipeline-notes.yml"), EMPTY))


def test_commit_message_mention_not_gated():
    assert not _gated(evaluate(
        _shell('git commit -m "update .github/workflows/ci.yml docs"'), EMPTY))


# ---- ReDoS / performance (QA round 1) ------------------------------------------

def test_no_quadratic_blowup_on_adversarial_input():
    """A crafted string repeating a near-miss prefix with no real match anywhere
    must not force catastrophic/quadratic backtracking — a non-escapable/
    human-only guard hanging is itself a bypass path (fail-open on hook timeout)."""
    from aegis import patterns
    adversarial = ".github/workflows/" * 8000  # ~144KB, no real match at any point
    start = time.time()
    patterns.CI_WORKFLOW_PATH_RE.search(adversarial)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"CI_WORKFLOW_PATH_RE took {elapsed:.2f}s on adversarial input"

    adversarial2 = ".buildkite/x/" * 8000
    start = time.time()
    patterns.CI_WORKFLOW_PATH_RE.search(adversarial2)
    elapsed2 = time.time() - start
    assert elapsed2 < 1.0, f"CI_WORKFLOW_PATH_RE took {elapsed2:.2f}s on adversarial input"


# ---- modes: ask (default) / deny / monitor / off -------------------------------

def test_default_mode_is_ask():
    d = evaluate(_edit(".github/workflows/ci.yml"), EMPTY)
    assert d.action == Action.ASK and d.rule == "ci-workflow-protect"
    d2 = evaluate(_shell("echo x >> .github/workflows/ci.yml"), EMPTY)
    assert d2.action == Action.ASK


def test_deny_mode_hard_blocks():
    d = evaluate(_edit(".github/workflows/ci.yml"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == "ci-workflow-protect"
    d2 = evaluate(_shell("echo x >> .github/workflows/ci.yml"), DENY)
    assert d2.blocked


def test_monitor_mode_logs_and_allows():
    pol = Policy(ci_workflow={"mode": "monitor"})
    assert not _gated(evaluate(_edit(".github/workflows/ci.yml"), pol))
    assert not _gated(evaluate(_shell("echo x >> .github/workflows/ci.yml"), pol))


def test_off_mode_disables_guard():
    pol = Policy(ci_workflow={"mode": "off"})
    assert not _gated(evaluate(_edit(".github/workflows/ci.yml"), pol))


def test_policy_allow_regex_exempts_trusted_path():
    pol = Policy(ci_workflow={"allow": [r"trusted-repo/\.github/workflows/"]})
    assert not _gated(evaluate(_write("trusted-repo/.github/workflows/ci.yml"), pol))
    assert _gated(evaluate(_write("other-repo/.github/workflows/ci.yml"), pol))
