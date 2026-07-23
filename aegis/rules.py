"""Built-in, secure-by-default rules.

Each rule is ``(Event, Policy) -> Decision | None`` (None = no opinion); the engine
runs built-ins, then registered plugin rules, then the user's declarative rules,
first-deny-wins, fail-open per rule. Custom rules (orgs / MCP providers) use the
same signature and read ``policy`` for their own config — see ``aegis.plugins``.

Tiers: rogue-session gate + containment + self-protection are NOT escapable;
destructive git/delete are escapable with an explicit '# aegis-allow'.
"""
from __future__ import annotations

import fnmatch
import os
import re
import subprocess
from typing import Optional

from . import normalize, patterns, review
from .events import ActionClass, Event, HookEvent
from .policy import Action, Decision

_URL_RE = re.compile(r"https?://([^/\s'\"]+)", re.IGNORECASE)


def _cmd(ev: Event) -> str:
    return str((ev.args or {}).get("command") or "")


def _path(ev: Event) -> str:
    a = ev.args or {}
    # Beyond Claude Code's own arg names, cover the common key names third-party
    # MCP filesystem-server tools use for their target path (varies by server —
    # e.g. target_file/filename/file/uri) so path-based guards see MCP-tool writes,
    # not just Edit/Write. Purely additive: widens detection, never narrows it.
    return str(a.get("file_path") or a.get("path") or a.get("notebook_path")
               or a.get("target_file") or a.get("targetFile") or a.get("filename")
               or a.get("file") or a.get("uri") or "")


def _is_shell(ev: Event) -> bool:
    return ev.action == ActionClass.SHELL


def _is_agent() -> bool:
    return bool(os.environ.get("AEGIS_AGENT_NAME"))


def _shell_scan(ev: Event) -> str:
    """De-obfuscated scan surface for a shell command — sees through quoting,
    encoding, and inner interpreters (bash -c / powershell -enc / base64 | sh)."""
    return normalize.scan_surface(_cmd(ev)) if _is_shell(ev) else ""


def _override_allowed(ev: Event, extra: str = "") -> bool:
    """The '# aegis-allow' / '-- aegis-allow' escape — honored ONLY for a human /
    orchestrator. A spawned agent (AEGIS_AGENT_NAME set) cannot wave itself past an
    escapable guard."""
    if _is_agent():
        return False
    return bool(patterns.OVERRIDE_RE.search(_cmd(ev) + " " + (extra or "")))


def _sql_text(ev: Event) -> str:
    """SQL/migration text from a DB tool's args (query/sql/statement/migration) and,
    for a shell call, the de-obfuscated command — so one rule covers psql AND a DB
    MCP tool, even when the SQL is wrapped/encoded."""
    a = ev.args or {}
    parts = [a.get("query"), a.get("sql"), a.get("statement"), a.get("migration")]
    if _is_shell(ev):
        parts.append(_shell_scan(ev))
    return " ".join(str(p) for p in parts if p)


def _flatten_strings(v, _depth: int = 0) -> list:
    """Every string/number leaf inside a (possibly nested) arg value. MCP tool
    args are arbitrary JSON, so a target URL can sit under any key name, at any
    depth (e.g. {"input": {"url": "..."}}) — QA review (independent agent,
    round 1) found a fixed key-name allowlist here was a bypass: any MCP tool
    naming its URL argument something other than the guessed set (url/query/
    uri/endpoint/command) sailed straight through untouched. Depth cap raised
    12 -> deep enough for any realistic tool-arg schema (round 3 QA found the
    original cap of 4 silently dropped a 5-level-deep target) while still
    bounding recursion against a pathological/cyclic payload."""
    if _depth > 12:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return [str(v)]
    if isinstance(v, dict):
        out = []
        for x in v.values():
            out.extend(_flatten_strings(x, _depth + 1))
        return out
    if isinstance(v, (list, tuple)):
        out = []
        for x in v:
            out.extend(_flatten_strings(x, _depth + 1))
        return out
    return []


def _net_text(ev: Event) -> str:
    """All string/number argument content for a network-shaped tool call
    (WebFetch/WebSearch, or an MCP tool that reaches the network) — scans every
    value rather than a fixed set of key names, since the argument that carries
    the target URL varies by tool/server with no fixed convention across MCP
    servers."""
    return " ".join(_flatten_strings(ev.args or {}))


def _egress_host(ev: Event) -> Optional[str]:
    a = ev.args or {}
    for v in (a.get("url"), a.get("command"), a.get("query")):
        if v:
            m = _URL_RE.search(str(v))
            if m:
                return m.group(1).split("@")[-1].split(":")[0].lower()
    return None


# ---- rogue-session gate + honeypot: never escapable ----------------------------
def rule_attest_session(ev: Event, policy=None) -> Optional[Decision]:
    """On SessionStart, a process claiming an agent identity (AEGIS_AGENT_NAME)
    without a valid signed token is rogue. MONITOR by default (log + allow); under
    AEGIS_IDENTITY_ENFORCE the session is REAPED and the honeypot challenge surfaced."""
    if ev.event != HookEvent.SESSION_START:
        return None
    name = os.environ.get("AEGIS_AGENT_NAME")
    if not name:
        return None
    from . import identity
    if identity.current() is not None:
        return None
    from . import attest
    verdict = attest.classify({
        "agent": name,
        "model": os.environ.get("AEGIS_AGENT_MODEL"),
        "operator": os.environ.get("AEGIS_AGENT_OPERATOR"),
        "token": os.environ.get("AEGIS_AGENT_TOKEN"),
    })
    attest.record(verdict, source=os.environ.get("AEGIS_SESSION_ID") or name)
    if not identity.enforce_enabled():
        return None
    from . import reaper
    reaper.kill_session()
    return Decision(Action.DENY, "rogue-agent-reaped",
                    f"Rogue agent session terminated: claims identity '{name}' without a "
                    f"valid signed token. {attest.ATTEST_CHALLENGE}")


# ---- containment: never escapable ----------------------------------------------
def rule_containment(ev: Event, policy=None) -> Optional[Decision]:
    # Cloud-metadata SSRF is checked on a SEPARATE surface from the rest of this
    # function: only actions that actually reach the network (a shell command,
    # a WebFetch, or an MCP tool call) can trigger it. It deliberately does NOT
    # scan Read/Edit/Write path+content like CRED_RE does below — a file that
    # merely MENTIONS the address (docs, a firewall/NetworkPolicy rule that
    # blocks it, this guard's own tests) is not a fetch and must not be denied —
    # QA review (independent agent, round 1) caught this as a false positive
    # that would have made an Aegis-governed agent unable to even write about
    # the address it's supposed to protect against. WebSearch is excluded too
    # (round 2): a search QUERY never makes the agent's own network stack reach
    # an attacker-chosen host — the search provider does the fetching — so
    # "how does the 169.254.169.254 SSRF work" as research is not an attempt to
    # reach it and must not trip a non-escapable guard.
    #
    # The shell branch is a bare substring search (matching every other
    # containment pattern's style) EXCEPT for the narrow, closed-form
    # CLOUD_METADATA_MENTION_ONLY_RE carve-out (grep/git-commit/echo — see its
    # docstring in patterns.py for why a positive fetch-verb requirement was
    # tried and rejected: it under-blocks far worse than this over-blocks).
    # WebFetch/MCP need no carve-out: the tool call itself IS the fetch, so
    # mere presence of the address in its target argument is already the
    # attempt.
    is_shell = _is_shell(ev)
    if is_shell:
        text = _shell_scan(ev)
        metadata_hit = (bool(patterns.CLOUD_METADATA_RE.search(text))
                         and not patterns.CLOUD_METADATA_MENTION_ONLY_RE.search(text))
    elif ev.action == ActionClass.MCP or (
            ev.action == ActionClass.NET and (ev.tool or "").strip().lower() != "websearch"):
        metadata_hit = bool(patterns.CLOUD_METADATA_RE.search(_net_text(ev)))
        text = None  # handled above; not a shell/read/edit/write shape below
    elif ev.action in (ActionClass.READ, ActionClass.EDIT, ActionClass.WRITE):
        text = _path(ev) + " " + str((ev.args or {}).get("content") or "")
        metadata_hit = False
    else:
        return None
    if metadata_hit:
        return Decision(Action.DENY, "containment-cloud-metadata",
                        "Access to the cloud instance-metadata service is blocked — this "
                        "endpoint hands out live IAM/service-account credentials to "
                        "anything on-box, no auth required, and is a classic SSRF-to-"
                        "credential-theft path.")
    if text is None or not text.strip():
        return None
    if patterns.CRED_RE.search(text):
        return Decision(Action.DENY, "containment-credentials",
                        "Access to credential stores (SSH / cloud keys, browser logins, "
                        "OS vault) is blocked.")
    if _is_shell(ev) and patterns.PERSIST_RE.search(text):
        return Decision(Action.DENY, "containment-persistence",
                        "Installing persistence (autorun, scheduled tasks, services, "
                        "startup) is blocked.")
    if _is_shell(ev) and patterns.EXFIL_RE.search(text):
        return Decision(Action.DENY, "containment-exfiltration",
                        "Uploading local files to the network is blocked.")
    if _is_shell(ev) and patterns.CLOUD_EXFIL_RE.search(text):
        return Decision(Action.DENY, "containment-cloud-exfiltration",
                        "Uploading local files to a cloud storage bucket/container "
                        "(aws s3 / gsutil / az storage / rclone) is blocked.")
    if _is_shell(ev) and patterns.ENV_DUMP_EXFIL_RE.search(text):
        return Decision(Action.DENY, "containment-env-exfiltration",
                        "Dumping the process environment (env / printenv / export -p / "
                        "Get-ChildItem Env:) into a network call is blocked — the "
                        "environment routinely holds live secrets (API keys, tokens, "
                        "DATABASE_URL) with no file ever touched.")
    return None


# ---- self-protection: never escapable ----------------------------------------
def rule_self_protect(ev: Event, policy=None) -> Optional[Decision]:
    if _is_shell(ev):
        cmd = _shell_scan(ev)
        if patterns.AEGIS_UNINSTALL_RE.search(cmd):
            return Decision(Action.DENY, "self-protect",
                            "Running `aegis uninstall` is blocked.")
        if patterns.AEGIS_PULL_RE.search(cmd):
            return Decision(Action.DENY, "self-protect",
                            "Running `aegis pull` is blocked — overwriting policy from a "
                            "shell is a self-protect violation.")
        if (patterns.CONFIG_DIR_RE.search(cmd) or patterns.AEGIS_SOURCE_RE.search(cmd)
                # find's -path/-name predicates can name a protected file without the
                # command ever containing its path as one contiguous string — see
                # FIND_PROTECTED_RE's docstring in patterns.py. find_protected_hit(),
                # not a bare .search() on FIND_PROTECTED_RE alone — see FIND_WORD_RE's
                # comment in patterns.py for why this must stay a two-piece check.
                or patterns.find_protected_hit(cmd)) and (
                patterns.DELETE_OR_MOVE_VERB_RE.search(cmd)
                or patterns.DESTRUCTIVE_DELETE_RE.search(cmd)
                or patterns.WRITE_REDIRECT_RE.search(cmd)
                or patterns.COPY_WRITE_VERB_RE.search(cmd)
                # in-place edit (sed -i / perl -i / batch vim/ex) neither deletes,
                # moves, redirects, nor copies-over — it was the one write shape this
                # guard didn't check, letting an agent rewrite policy/settings/source
                # in place without tripping "never escapable" self-protection.
                or patterns.INPLACE_WRITE_RE.search(cmd)):
            return Decision(Action.DENY, "self-protect",
                            "Writing/deleting/moving Aegis's own config, policy, or engine "
                            "source is blocked.")
        return None
    if ev.action in (ActionClass.EDIT, ActionClass.WRITE):
        p = _path(ev)
        if patterns.ENFORCEMENT_PATH_RE.search(p) or patterns.AEGIS_SOURCE_RE.search(p):
            return Decision(Action.DENY, "self-protect",
                            "Editing Aegis's own config or engine source is blocked.")
        if patterns.AEGIS_SKILL_PATH_RE.search(p):
            return Decision(Action.DENY, "self-protect",
                            "Editing Aegis's shipped skills (.claude/skills/aegis-*) is "
                            "blocked — they carry the compliance guidance blocked agents "
                            "are pointed at.")
    return None


# ---- MCP server-config protection: escapable with human confirmation ---------
def _mcp_config_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def rule_mcp_config_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block writes to MCP server-definition config files (``.mcp.json``,
    ``~/.claude.json``'s ``mcpServers``, and the Cursor/VS Code/Windsurf/Claude
    Desktop equivalents) and CLI ``mcp add`` registration.

    A server entry's ``command``/``args``/``url``/``env`` is auto-executed on every
    FUTURE session start. A hijacked or prompt-injected agent that plants or edits
    one plants a durable, cross-session backdoor — via a plain Edit/Write, an MCP
    filesystem tool, a shell redirect/delete/in-place-edit/copy onto the path, or a
    CLI's own ``mcp add`` subcommand (which mutates the config without any file write
    the Edit/Write hook would see). Distinct from self-protect (Aegis's own config)
    and containment/persistence (OS-level only) — neither covers this surface.

    Config (``policy.mcp_config``): ``mode`` (deny|ask|monitor|off, default deny),
    ``allow`` (regexes on the path/command that skip the gate — a repo's own trusted
    setup script, say). ``ask`` surfaces the change to a human for interactive
    approval (like ``install_review``) instead of a hard deny; ``monitor`` logs the
    would-be decision to the audit and allows.

    Escapable only by a human: a trailing '# aegis-allow' on the *shell* form (the
    natural place for it — there's no syntax-safe way to embed a comment inside a
    JSON Edit/Write payload), or the env toggle ``AEGIS_ALLOW_MCP_CONFIG=1`` set by
    the orchestrator/human before launch for the Edit/Write/MCP-tool form. A spawned
    agent cannot set its own env for a hook invocation it doesn't control, so neither
    path is agent-self-escapable."""
    cfg = getattr(policy, "mcp_config", None) or {}
    mode = str(cfg.get("mode", "deny")).lower()
    if mode == "off":
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        if not p or not patterns.MCP_CONFIG_PATH_RE.search(p):
            return None
        if os.environ.get("AEGIS_ALLOW_MCP_CONFIG") or _mcp_config_allowed_by_policy(cfg, p):
            return None
        would = Decision(action, "mcp-config-protect",
                         f"MCP server config '{p}' is being written — a new or "
                         "modified server entry (command/args/url/env) runs "
                         "automatically on every future session, a durable backdoor. "
                         "Review the change, then confirm with "
                         "AEGIS_ALLOW_MCP_CONFIG=1; a spawned agent cannot set this.")
        if mode == "monitor":
            _record_monitor(ev, would, "mcp-config-protect-monitor")
            return None
        return would

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        touches_config = bool(patterns.MCP_CONFIG_PATH_RE.search(cmd)) and (
            patterns.WRITE_REDIRECT_RE.search(cmd)
            or patterns.DELETE_OR_MOVE_VERB_RE.search(cmd)
            or patterns.DESTRUCTIVE_DELETE_RE.search(cmd)
            or patterns.INPLACE_WRITE_RE.search(cmd))
        cli_add = patterns.MCP_CLI_ADD_RE.search(cmd)
        if not (touches_config or cli_add):
            return None
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_MCP_CONFIG")
                or _mcp_config_allowed_by_policy(cfg, _cmd(ev))):
            return None
        would = Decision(action, "mcp-config-protect",
                         "MCP server configuration is being modified from a shell — "
                         "this can register a new tool server that runs "
                         "automatically on every future session. A human may append "
                         "'# aegis-allow', or set AEGIS_ALLOW_MCP_CONFIG=1; a spawned "
                         "agent cannot.")
        if mode == "monitor":
            _record_monitor(ev, would, "mcp-config-protect-monitor")
            return None
        return would
    return None


# ---- CI/CD workflow-definition protection: escapable with human confirmation --
def _ci_workflow_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def rule_ci_workflow_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block planting/altering a CI/CD pipeline-definition file (GitHub Actions
    workflows and composite actions, GitLab CI, CircleCI, Azure Pipelines, Travis,
    Jenkinsfile, Drone, Bitbucket Pipelines, Buildkite, Cloud Build, AppVeyor).

    A pipeline step runs autonomously on a FUTURE, DIFFERENT machine (the CI
    runner) that typically holds MORE privilege than the current session (deploy
    keys, cloud IAM, publish tokens, a write-scoped GITHUB_TOKEN, org secrets). A
    hijacked or prompt-injected agent that plants or edits a step here — a
    secret-exfiltrating `run:` line, a `pull_request_target` trigger over
    untrusted fork code, a step that leaks `${{ secrets.* }}` into a log/artifact
    — plants a backdoor that never executes in THIS guarded session at all (no
    shell/network guard here ever sees it fire) and self-triggers on the next
    push/PR/build with no further agent action needed. Distinct from
    mcp_config_protect (same-machine, next-session auto-exec) and
    self-protect/containment (this session/host only) — neither covers a payload
    that only runs on a remote CI runner later.

    Config (``policy.ci_workflow``): ``mode`` (deny|ask|monitor|off, default ask),
    ``allow`` (regexes on the path/command that skip the gate — a repo's own
    trusted bot-authored dependency-bump PRs, say). Defaults to ``ask`` rather than
    a hard deny (unlike mcp_config_protect, which defaults to deny) because editing
    a CI workflow is routine, common dev work — bumping an action version, adding a
    test-matrix entry — unlike planting an MCP server, which is rare; ``ask`` keeps
    a human in the loop on every change (the agent never decides — see README) with
    no pre-session setup required, the same reasoning ``rule_install_review`` uses
    for defaulting to ``ask`` over ``deny``. ``deny`` is still available for a
    stricter posture; ``monitor`` logs the would-be decision to the audit and
    allows.

    Escapable only by a human: a trailing '# aegis-allow' on the *shell* form, or
    the env toggle ``AEGIS_ALLOW_CI_WORKFLOW=1`` set by the orchestrator/human
    before launch for the Edit/Write/MCP-tool form. A spawned agent cannot set its
    own env for a hook invocation it doesn't control, so neither path is
    agent-self-escapable."""
    cfg = getattr(policy, "ci_workflow", None) or {}
    mode = str(cfg.get("mode", "ask")).lower()
    if mode == "off":
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        if not p or not patterns.CI_WORKFLOW_PATH_RE.search(p):
            return None
        if os.environ.get("AEGIS_ALLOW_CI_WORKFLOW") or _ci_workflow_allowed_by_policy(cfg, p):
            return None
        would = Decision(action, "ci-workflow-protect",
                         f"CI/CD pipeline definition '{p}' is being written — a step "
                         "added here runs on a FUTURE CI run, on a different machine, "
                         "typically with more privilege (deploy keys, cloud IAM, a "
                         "write-scoped GITHUB_TOKEN) than this session. Review the "
                         "change, then confirm with AEGIS_ALLOW_CI_WORKFLOW=1; a "
                         "spawned agent cannot.")
        if mode == "monitor":
            _record_monitor(ev, would, "ci-workflow-protect-monitor")
            return None
        return would

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        # CI_WORKFLOW_FIND_RE catches `find -path/-name/-regex` naming the target
        # without ever writing its path as one contiguous string (same reason
        # rule_self_protect pairs FIND_PROTECTED_RE alongside its own path
        # patterns — see that pattern's docstring). FORCED_LINK_WRITE_RE catches
        # `ln -f`/`New-Item -Force`, a write shape none of the other four verb
        # patterns below recognize (QA finding, round 1).
        names_workflow = bool(patterns.CI_WORKFLOW_PATH_RE.search(cmd)
                               or patterns.ci_workflow_find_hit(cmd))
        touches_workflow = names_workflow and (
            patterns.WRITE_REDIRECT_RE.search(cmd)
            or patterns.DELETE_OR_MOVE_VERB_RE.search(cmd)
            or patterns.DESTRUCTIVE_DELETE_RE.search(cmd)
            or patterns.INPLACE_WRITE_RE.search(cmd)
            or patterns.FORCED_LINK_WRITE_RE.search(cmd))
        if not touches_workflow:
            return None
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_CI_WORKFLOW")
                or _ci_workflow_allowed_by_policy(cfg, _cmd(ev))):
            return None
        would = Decision(action, "ci-workflow-protect",
                         "CI/CD pipeline configuration is being modified from a shell "
                         "— a step added here runs on a future CI run, on a different "
                         "machine, typically with more privilege than this session. A "
                         "human may append '# aegis-allow', or set "
                         "AEGIS_ALLOW_CI_WORKFLOW=1; a spawned agent cannot.")
        if mode == "monitor":
            _record_monitor(ev, would, "ci-workflow-protect-monitor")
            return None
        return would
    return None


# ---- git-hooks protection: escapable with human confirmation -----------------
def _git_hooks_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def rule_git_hooks_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block planting/altering a Git hook (``.git/hooks/pre-commit``, ``pre-push``,
    ``post-checkout``, ...) and redirecting git to an attacker-controlled hooks
    directory via ``core.hooksPath``.

    A hook runs with the invoking user's full privileges on the very next
    matching git operation — the human's next commit/push/checkout, not just
    this session — with no further agent action needed, the same "runs later,
    unattended" shape as ``rule_mcp_config_protect`` (next-session auto-exec) and
    ``rule_ci_workflow_protect`` (next-CI-run auto-exec). Worse than either: a
    file under ``.git/hooks/`` is NEVER tracked by git itself, so it has no diff,
    shows in no ``git status``, and survives no code review — the most invisible
    durable backdoor of the three. ``core.hooksPath`` is a second, independent
    path to the same outcome: it redirects git to run hooks from an arbitrary
    directory the agent staged a script in beforehand, so a bare path check on
    ``.git/hooks/`` alone cannot see it — a ``--global``/``--system`` scoped
    redirect widens the blast radius to every repo the human ever touches.

    Config (``policy.git_hooks``): ``mode`` (deny|ask|monitor|off, default ask),
    ``allow`` (regexes on the path/command that skip the gate — a repo's own
    trusted ``pre-commit install``/husky setup, say). Defaults to ``ask`` for the
    same reason ``rule_ci_workflow_protect`` does: installing a pre-commit/husky
    hook is routine, sanctioned dev work, unlike planting an MCP server.

    Escapable only by a human: a trailing '# aegis-allow' on the *shell* form, or
    the env toggle ``AEGIS_ALLOW_GIT_HOOKS=1`` set by the orchestrator/human
    before launch for the Edit/Write/MCP-tool form. A spawned agent cannot set
    its own env for a hook invocation it doesn't control, so neither path is
    agent-self-escapable.

    Honest scope: this is a path-string match on the standard hook directory
    (including a submodule's real `.git/modules/<name>/hooks/` location) and
    hook names (see ``patterns.py`` for the full githooks(5) list) plus a
    ``core.hooksPath`` command/content match — the same denylist trade-offs as
    every other guard in this file (``find``-indirection, forced-link swaps,
    and archive/sync tools (rsync/tar/unzip/`install -m`) are covered the way
    ``rule_ci_workflow_protect``'s equivalents are). Known residual gaps, same
    spirit as this file's other disclosed denylist limits: a hook name outside
    the standard set; a shell command that computes the hook path indirectly
    across variable assignments; an MCP tool naming its target argument
    outside ``_path()``'s recognized key list; a fully relocated git dir via
    ``--separate-git-dir``/a `.git` pointer file with no "modules" in the
    path; and ``GIT_CONFIG_GLOBAL``/``GIT_CONFIG_SYSTEM`` redirecting to a
    payload staged in an EARLIER, separate tool call (Aegis evaluates each
    call independently — see ``GIT_HOOKS_CONFIG_INI_RE``'s comment in
    ``patterns.py``)."""
    cfg = getattr(policy, "git_hooks", None) or {}
    # YAML 1.1 parses an unquoted `off` as boolean False — accept both
    # spellings, the same fix `rule_failure_loop` already applies for its own
    # `mode` knob (QA finding, independent adversarial review, round 1: this
    # guard silently stayed ACTIVE — fails safe, not open, but still a
    # config-hygiene bug worth closing).
    raw_mode = cfg.get("mode", "ask")
    mode = str(raw_mode).lower()
    if mode in ("off", "false") or raw_mode is False:
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        hook_hit = bool(p and patterns.GIT_HOOKS_PATH_RE.search(p))
        a = ev.args or {}
        content = str(a.get("content") or a.get("new_string") or "")
        config_hit = False
        if content:
            # Path-independent: a full "[core] ... hookspath =" block is
            # high-signal regardless of destination filename — see
            # GIT_HOOKS_CONFIG_INI_RE's comment in patterns.py for why.
            if patterns.GIT_HOOKS_CONFIG_INI_RE.search(content):
                config_hit = True
            elif p and patterns.GIT_CONFIG_FILE_PATH_RE.search(p) and (
                    patterns.GIT_HOOKS_CONFIG_CONTENT_RE.search(content)):
                config_hit = True
        if not (hook_hit or config_hit):
            return None
        if os.environ.get("AEGIS_ALLOW_GIT_HOOKS") or _git_hooks_allowed_by_policy(cfg, p):
            return None
        reason = (f"Git hook '{p}' is being written" if hook_hit
                  else f"'{p}' is being written with a core.hooksPath redirect")
        would = Decision(action, "git-hooks-protect",
                         f"{reason} — a hook script runs automatically, with the "
                         "invoking user's full privileges, on the very next matching "
                         "git operation, and (unlike a tracked file) is invisible to "
                         "`git diff`/`git status`/code review. Review the change, "
                         "then confirm with AEGIS_ALLOW_GIT_HOOKS=1; a spawned agent "
                         "cannot.")
        if mode == "monitor":
            _record_monitor(ev, would, "git-hooks-protect-monitor")
            return None
        return would

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        names_hook = bool(patterns.GIT_HOOKS_PATH_RE.search(cmd)
                           or patterns.GIT_HOOKS_DIR_RE.search(cmd)
                           or patterns.git_hooks_find_hit(cmd))
        touches_hook = names_hook and (
            patterns.WRITE_REDIRECT_RE.search(cmd)
            or patterns.DELETE_OR_MOVE_VERB_RE.search(cmd)
            or patterns.DESTRUCTIVE_DELETE_RE.search(cmd)
            or patterns.INPLACE_WRITE_RE.search(cmd)
            or patterns.FORCED_LINK_WRITE_RE.search(cmd)
            or patterns.GIT_HOOKS_ARCHIVE_VERB_RE.search(cmd))
        config_redirect = bool(patterns.GIT_HOOKS_CONFIG_RE.search(cmd))
        if not (touches_hook or config_redirect):
            return None
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_GIT_HOOKS")
                or _git_hooks_allowed_by_policy(cfg, _cmd(ev))):
            return None
        reason = ("Git hook configuration is being modified from a shell" if touches_hook
                  else "git's hooksPath is being redirected from a shell")
        would = Decision(action, "git-hooks-protect",
                         f"{reason} — a hook script runs automatically, with the "
                         "invoking user's full privileges, on the very next matching "
                         "git operation, and (unlike a tracked file) is invisible to "
                         "`git diff`/`git status`/code review. A human may append "
                         "'# aegis-allow', or set AEGIS_ALLOW_GIT_HOOKS=1; a spawned "
                         "agent cannot.")
        if mode == "monitor":
            _record_monitor(ev, would, "git-hooks-protect-monitor")
            return None
        return would
    return None


# ---- agent-instructions / agent-definition protection: escapable with human --
def _agent_def_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def rule_agent_def_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block planting/altering project instructions (``CLAUDE.md``/``AGENTS.md``,
    including the ``.local`` supplement variants) or a custom agent/command/
    output-style definition (``.claude/agents/*.md``, ``.claude/commands/*.md``,
    ``.claude/output-styles/*.md``, project- or user-scoped).

    ``CLAUDE.md``/``AGENTS.md`` is folded directly into the model's OWN context
    on every FUTURE session start — the same "runs later, unattended" shape as
    ``rule_mcp_config_protect``, except the payload is natural-language
    instructions merged straight into the system prompt rather than a shelled-
    out command, and it persists across every sub-agent spawned in that future
    session too. Its fuse is shorter than ``rule_ci_workflow_protect``'s/
    ``rule_git_hooks_protect``'s: those need an EXTERNAL future trigger (a
    push, a commit) before the payload runs; a nested-directory ``CLAUDE.md``
    can self-trigger WITHIN the same session, the instant the agent's cwd
    moves into that subtree, no human action in between at all. ``ask`` is
    still the right default (below), not ``deny`` — but this asymmetry is
    exactly why it's disclosed here rather than silently inherited. A
    ``.claude/agents/*.md`` sub-agent whose description reads like "use
    PROACTIVELY" is auto-selected by the orchestrator with no explicit
    per-invocation human choice, and routinely carries its own tool allowlist
    (up to ``tools: "*"``) independent of whatever gated the session that
    planted it — privilege escalation via a natural-language file, not code.
    A ``.claude/commands/*.md``/``.claude/output-styles/*.md`` definition only
    takes effect when a human explicitly invokes/selects it, but the human is
    trusting the NAME each time, not re-reading the file's body — the same
    "trusted name, unread body" trap ``rule_ci_workflow_protect``/
    ``rule_git_hooks_protect`` exist for.

    NOT new coverage (QA correction, independent adversarial review, round 1
    — an earlier draft of this docstring overstated this): a shell-based
    delete/redirect/in-place-edit under ``.claude/`` — which includes
    ``.claude/agents/*``/``.claude/commands/*``/``.claude/output-styles/*`` —
    was ALREADY denied, non-escapably, by ``rule_self_protect``'s broad
    ``CONFIG_DIR_RE`` match; this guard's shell branch is a redundant, weaker
    (``ask``, escapable) second layer there, not new ground. What actually IS
    new: (1) a root/nested ``CLAUDE.md``/``AGENTS.md`` in EITHER form (shell
    or Edit/Write) — no ``.claude`` substring, so ``CONFIG_DIR_RE`` never
    fires on it; (2) a plain ``Edit``/``Write``/MCP-tool call (no shell) to
    ANY of these paths — self-protect's own EDIT/WRITE branch checks only
    ``ENFORCEMENT_PATH_RE``/``AEGIS_SOURCE_RE``/``AEGIS_SKILL_PATH_RE``, never
    the broader ``CONFIG_DIR_RE``.

    Config (``policy.agent_def``): ``mode`` (deny|ask|monitor|off, default
    ask), ``allow`` (regexes on the path/command that skip the gate — a
    repo's own CI-authored ``CLAUDE.md`` sync, say). Defaults to ``ask`` for
    the same reason ``rule_ci_workflow_protect``/``rule_git_hooks_protect``
    do: editing project instructions or authoring a custom sub-agent/command
    is routine, sanctioned dev work, unlike e.g. planting an MCP server.

    Escapable only by a human: a trailing '# aegis-allow' on the shell form,
    or the env toggle ``AEGIS_ALLOW_AGENT_DEF=1`` set by the orchestrator/
    human before launch for the Edit/Write/MCP-tool form. A spawned agent
    cannot set its own env for a hook invocation it doesn't control, so
    neither path is agent-self-escapable.

    Honest scope: a path-string match, the same denylist trade-offs as every
    other guard in this file. `AGENT_DEF_DIR_RE` + `ARCHIVE_SYNC_VERB_RE`
    close the archive/sync-tool bypass (`rsync`/`tar`/`unzip`/`install -m`
    placing a file with no verb this guard's other checks recognize, and no
    filename ever named as one contiguous string) the same way
    `GIT_HOOKS_DIR_RE`/`GIT_HOOKS_ARCHIVE_VERB_RE` close it for git hooks —
    a fix that QA (independent adversarial review, round 1) found was never
    carried over from that guard despite this one being modeled on it.
    Known residual gaps, same spirit as every guard in this file: a direct
    fetch-to-file write (`curl -o CLAUDE.md ...`, `wget -O ... `) with no
    verb any of the five write-verb checks (or the archive/sync check)
    recognizes — an inherited gap `rule_ci_workflow_protect`/
    `rule_git_hooks_protect` share too, not new or worse here; a project-
    instructions filename outside the recognized set; an MCP filesystem tool
    naming its target argument outside ``_path()``'s recognized key list;
    nesting past 4 levels under `.claude/agents|commands|output-styles`
    evading the filename form of `AGENT_DEF_PATH_RE` (the bare-directory
    backstop above still catches an archive/sync tool's own target argument
    regardless of nesting); and a shell command that computes the target path
    indirectly across separate variable assignments (the ``find``-indirection
    case is covered; a `for`/`xargs` loop or `basename`/`dirname`
    reconstruction is not, the same disclosed gap
    ``rule_self_protect``/``rule_ci_workflow_protect``/
    ``rule_git_hooks_protect`` already carry)."""
    cfg = getattr(policy, "agent_def", None) or {}
    raw_mode = cfg.get("mode", "ask")
    mode = str(raw_mode).lower()
    if mode in ("off", "false") or raw_mode is False:
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        instr_hit = bool(p and patterns.AGENT_INSTRUCTIONS_PATH_RE.search(p))
        def_hit = bool(p and patterns.AGENT_DEF_PATH_RE.search(p))
        if not (instr_hit or def_hit):
            return None
        if os.environ.get("AEGIS_ALLOW_AGENT_DEF") or _agent_def_allowed_by_policy(cfg, p):
            return None
        reason = (f"Project instructions file '{p}' is being written — its content is "
                   "folded directly into every future session's context, unattended"
                   if instr_hit else
                   f"Agent/command/output-style definition '{p}' is being written — it "
                   "can be auto-selected or invoked in a future session, carrying its "
                   "own tool allowlist")
        would = Decision(action, "agent-def-protect",
                         f"{reason}. Review the change, then confirm with "
                         "AEGIS_ALLOW_AGENT_DEF=1; a spawned agent cannot.")
        if mode == "monitor":
            _record_monitor(ev, would, "agent-def-protect-monitor")
            return None
        return would

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        # AGENT_DEF_DIR_RE catches a bare directory reference (no filename
        # ever named) and ARCHIVE_SYNC_VERB_RE catches the archive/sync verb
        # shape (rsync/tar/unzip/install -m) that places a file without
        # tripping any of the five verb checks below — QA finding
        # (independent adversarial review, round 1): both were missing
        # entirely from the first draft.
        names_target = bool(patterns.AGENT_INSTRUCTIONS_PATH_RE.search(cmd)
                             or patterns.AGENT_DEF_PATH_RE.search(cmd)
                             or patterns.AGENT_DEF_DIR_RE.search(cmd)
                             or patterns.agent_def_find_hit(cmd))
        touches_target = names_target and (
            patterns.WRITE_REDIRECT_RE.search(cmd)
            or patterns.DELETE_OR_MOVE_VERB_RE.search(cmd)
            or patterns.DESTRUCTIVE_DELETE_RE.search(cmd)
            or patterns.INPLACE_WRITE_RE.search(cmd)
            or patterns.FORCED_LINK_WRITE_RE.search(cmd)
            or patterns.ARCHIVE_SYNC_VERB_RE.search(cmd))
        if not touches_target:
            return None
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_AGENT_DEF")
                or _agent_def_allowed_by_policy(cfg, _cmd(ev))):
            return None
        would = Decision(action, "agent-def-protect",
                         "Project instructions or an agent/command/output-style "
                         "definition is being modified from a shell — its content is "
                         "auto-loaded or auto-invoked in a future session with no "
                         "further review. A human may append '# aegis-allow', or set "
                         "AEGIS_ALLOW_AGENT_DEF=1; a spawned agent cannot.")
        if mode == "monitor":
            _record_monitor(ev, would, "agent-def-protect-monitor")
            return None
        return would
    return None


# ---- shell-startup / SSH persistence protection: escapable with human confirm --
def _shell_persist_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def rule_shell_persist_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block planting/altering a shell startup/profile file (``~/.bashrc``,
    ``~/.zshrc``, ``~/.profile``, ``~/.bash_aliases``, ``~/.xprofile``, fish's
    ``config.fish``, ``/etc/profile.d/*.sh``, a PowerShell ``$PROFILE``, ...)
    or an SSH persistence target (``~/.ssh/authorized_keys``, ``~/.ssh/rc``,
    ``~/.ssh/environment``, ``~/.ssh/config``, ``/etc/ssh/sshd_config``,
    ``/etc/ssh/ssh_config``, and their ``Include``d drop-in directories
    ``/etc/ssh/sshd_config.d/*.conf``/``/etc/ssh/ssh_config.d/*.conf``).

    The shell-startup half is reached by no existing guard at all:
    ``rule_mcp_config_protect``/``rule_ci_workflow_protect``/
    ``rule_git_hooks_protect``/``rule_agent_def_protect`` all fire on a session
    start, a CI run, or a git operation — none of them fire on the single most
    common human action there is, opening a new terminal. A shell startup file
    executes arbitrary code, with the human's full privileges, every time they
    open an interactive shell from now on — unlike ``CLAUDE.md`` this isn't
    even specific to an agentic coding session.

    NOT new coverage for most of the SSH half: ``rule_containment``'s
    ``CRED_RE`` already denies, non-escapably, ANY shell/Edit/Write/MCP action
    whose text contains a `.ssh` path segment preceded by a `/`/`\\` — which
    matches ``~/.ssh/authorized_keys``/``~/.ssh/config`` in their ordinary,
    absolute-or-home-relative forms and wins first (containment runs earlier
    in ``BUILTIN_RULES`` and evaluate() is first-deny-wins), so this guard's
    own (weaker, escapable) decision for those two paths never actually
    surfaces in that common case. What IS new: (1) ``/etc/ssh/sshd_config``/
    ``/etc/ssh/ssh_config`` — no dot before "ssh" in that path, so
    ``CRED_RE``'s ``\\.ssh`` alternative never matches it at all; (2) a
    relative reference with NO leading path separator (e.g. the literal
    string ``.ssh/authorized_keys`` as its own shell token, as in
    ``echo x >> .ssh/authorized_keys`` run from ``$HOME``) — ``CRED_RE``
    requires a `/`/`\\` immediately before the dot, but this guard's patterns
    accept whitespace/quote/start-of-string too, so they still catch it where
    containment does not. An appended ``authorized_keys`` entry grants durable
    remote login with no password/agent involvement at all; ``~/.ssh/rc`` runs
    arbitrary shell on every accepted login when sshd's ``PermitUserRC`` is on
    (the common default); a ``ProxyCommand``/``LocalCommand``/
    ``PermitLocalCommand``/``PermitRootLogin`` directive in an SSH config or
    one of its drop-ins runs arbitrary code or grants access on the next
    matching connection — the client/server-side equivalent of a git hook, on
    a different trigger entirely — which is why this guard still declares the
    surface even though containment pre-empts most of the ordinary-path
    traffic through it.

    QA history (independent adversarial review, two parallel rounds): the
    original draft covered only the single top-level ``sshd_config``/
    ``ssh_config`` file, missing the ``Include``d drop-in directories
    (``/etc/ssh/sshd_config.d/*.conf``/``/etc/ssh/ssh_config.d/*.conf``) a
    stock Debian/Ubuntu/RHEL install already assembles its config from —
    fixed by adding both the filename form and a ``SHELL_PERSIST_DIR_RE``
    bare-directory entry for archive/sync-tool coverage. It also missed
    ``~/.ssh/rc``/``~/.ssh/environment`` entirely, the macOS/upstream-zsh
    system file layout (bare ``/etc/zshenv``/``/etc/zprofile``/etc., as
    opposed to the Debian ``/etc/zsh/zshrc`` layout — zsh is the default
    shell on every Mac since Catalina), ``~/.bash_aliases`` (sourced
    unconditionally by a stock Debian/Ubuntu ``.bashrc``, same blast radius as
    editing ``.bashrc`` itself), ``~/.xprofile`` (sourced by lightdm/gdm/sddm
    at the next graphical login), and the PowerShell ISE profile variant —
    all now covered.

    Config (``policy.shell_persist``): ``mode`` (deny|ask|monitor|off, default
    ask), ``allow`` (regexes on the path/command that skip the gate — a repo's
    own trusted dotfile-manager sync, say). Defaults to ``ask`` for the same
    reason ``rule_ci_workflow_protect``/``rule_git_hooks_protect``/
    ``rule_agent_def_protect`` do: editing a shell rc file (a PATH tweak, an
    alias) or an SSH config (adding a Host block) is routine, sanctioned dev
    work, unlike planting an MCP server.

    Escapable only by a human: a trailing '# aegis-allow' on the shell form, or
    the env toggle ``AEGIS_ALLOW_SHELL_PERSIST=1`` set by the orchestrator/
    human before launch for the Edit/Write/MCP-tool form. A spawned agent
    cannot set its own env for a hook invocation it doesn't control, so
    neither path is agent-self-escapable.

    Honest scope: a path-string match, the same denylist trade-offs as every
    other guard in this file. ``SHELL_PERSIST_DIR_RE`` + ``ARCHIVE_SYNC_VERB_RE``
    (reused as-is from ``rule_agent_def_protect`` rather than re-copied — both
    are already generic, path-independent verb patterns with their own ReDoS
    coverage, so reusing them carries less risk than minting a third,
    less-battle-tested copy) close the archive/sync-tool bypass the same way
    they do there. ``SHELL_PERSIST_DIR_RE`` is checked only on the shell
    branch, never the Edit/Write/MCP one — deliberately, matching
    ``GIT_HOOKS_DIR_RE``/``AGENT_DEF_DIR_RE``'s identical precedent: an
    Edit/Write/MCP file-mutation tool always names a specific file, never a
    bare directory, so there is no equivalent of an archive/sync tool's
    directory-only target argument on that branch to catch.

    Known residual gaps, same spirit as every guard in this file: a direct
    fetch-to-file write (``curl -o ~/.ssh/authorized_keys ...``, ``wget -O
    ...``) with no verb any of the five write-verb checks recognizes — the
    same inherited gap ``rule_ci_workflow_protect``/``rule_git_hooks_protect``/
    ``rule_agent_def_protect`` already disclose, not new or worse here; the
    bare filename ``config`` under ``~/.ssh/`` and the bare words
    ``profile``/``profile.ps1``/``rc``/``environment`` are deliberately
    excluded from the ``find``-indirection fallback (too generic — see
    ``patterns.py``'s own note on this guard's patterns); a shell command that
    computes the target path indirectly across separate variable assignments
    (a `for`/`xargs` loop or `basename`/`dirname` reconstruction) is not
    covered, the same disclosed gap every other guard in this file carries;
    an MCP tool naming its target argument outside ``_path()``'s recognized
    key list is missed the same way it is for every other ``_path()``-based
    guard in this file (not unique or worse here — a shared limitation of the
    helper itself, out of this guard's scope to fix); an environment-variable
    override that RELOCATES where a shell looks for its startup file —
    fish's ``$XDG_CONFIG_HOME`` (defaults to ``~/.config``), zsh's
    ``$ZDOTDIR`` (defaults to ``$HOME``) — is not covered when set to a
    directory this guard's patterns don't otherwise recognize (QA finding,
    independent adversarial review, round 2): the actual target file is only
    knowable by resolving an environment variable's value, the same
    "computed indirectly, not a literal path" class of gap every guard in
    this file already accepts for shell-computed paths in general; and, like
    every other guard here, a write-verb only needs to appear ANYWHERE in the
    (de-obfuscated) command alongside the matched path, not adjacent to or
    provably operating on it — a read redirected elsewhere (``cat ~/.bashrc >
    /tmp/backup.txt``) can gate under ``ask`` the same way a real overwrite
    does; the cost is one unnecessary human confirmation, not a missed
    detection, the same accepted direction every sibling guard in this file
    takes.

    QA history (independent adversarial review, round 2 — verification pass
    on the round-1 fixes): confirmed all round-1 fixes correct and regression-
    free, then found a new, systemic bug: every ``/etc/*`` alternative in both
    ``SHELL_RC_PATH_RE`` and ``SSH_PERSIST_PATH_RE`` hardcoded a literal
    single ``/`` between "etc" and the next path component instead of
    ``_SEP`` — so ``/etc//ssh/sshd_config`` (byte-identical to the real path
    as far as the OS is concerned) sailed through every one of them
    undetected, the exact bug class this file's own ``_SEP``/``_WIN_TRIM``
    exist to close elsewhere (``AEGIS_SOURCE_RE``, ``CI_WORKFLOW_PATH_RE``).
    Fixed by routing every ``/etc/*`` alternative through ``_SEP`` instead of
    a literal slash, the same convention those patterns already use — see
    ``patterns.py``'s own comment on this fix for detail."""
    cfg = getattr(policy, "shell_persist", None) or {}
    raw_mode = cfg.get("mode", "ask")
    mode = str(raw_mode).lower()
    if mode in ("off", "false") or raw_mode is False:
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        rc_hit = bool(p and patterns.SHELL_RC_PATH_RE.search(p))
        ssh_hit = bool(p and patterns.SSH_PERSIST_PATH_RE.search(p))
        if not (rc_hit or ssh_hit):
            return None
        if os.environ.get("AEGIS_ALLOW_SHELL_PERSIST") or _shell_persist_allowed_by_policy(cfg, p):
            return None
        reason = (f"Shell startup file '{p}' is being written — it runs "
                   "automatically, with the human's full privileges, the next "
                   "time they open an interactive shell" if rc_hit else
                   f"SSH persistence target '{p}' is being written — an added "
                   "key or ProxyCommand/LocalCommand directive grants durable "
                   "remote access or runs on the next matching ssh invocation")
        would = Decision(action, "shell-persist-protect",
                         f"{reason}. Review the change, then confirm with "
                         "AEGIS_ALLOW_SHELL_PERSIST=1; a spawned agent cannot.")
        if mode == "monitor":
            _record_monitor(ev, would, "shell-persist-protect-monitor")
            return None
        return would

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        names_target = bool(patterns.SHELL_RC_PATH_RE.search(cmd)
                             or patterns.SSH_PERSIST_PATH_RE.search(cmd)
                             or patterns.SHELL_PERSIST_DIR_RE.search(cmd)
                             or patterns.shell_persist_find_hit(cmd))
        touches_target = names_target and (
            patterns.WRITE_REDIRECT_RE.search(cmd)
            or patterns.DELETE_OR_MOVE_VERB_RE.search(cmd)
            or patterns.DESTRUCTIVE_DELETE_RE.search(cmd)
            or patterns.INPLACE_WRITE_RE.search(cmd)
            or patterns.FORCED_LINK_WRITE_RE.search(cmd)
            or patterns.ARCHIVE_SYNC_VERB_RE.search(cmd))
        if not touches_target:
            return None
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_SHELL_PERSIST")
                or _shell_persist_allowed_by_policy(cfg, _cmd(ev))):
            return None
        would = Decision(action, "shell-persist-protect",
                         "A shell startup file or SSH persistence target is "
                         "being modified from a shell — it runs automatically, "
                         "unattended, the next time the human opens a shell or "
                         "connects over SSH. A human may append "
                         "'# aegis-allow', or set AEGIS_ALLOW_SHELL_PERSIST=1; "
                         "a spawned agent cannot.")
        if mode == "monitor":
            _record_monitor(ev, would, "shell-persist-protect-monitor")
            return None
        return would
    return None


# ---- package-manifest lifecycle-script / registry-hijack protection ----------
def _package_manifest_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def rule_package_manifest_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block planting a lifecycle-script hook in a package manifest
    (``package.json``'s ``preinstall``/``install``/``postinstall``/
    ``preuninstall``/``postuninstall``/``prepare``/``prepublish``/
    ``prepublishOnly``, or ``composer.json``'s ``pre-install-cmd``/
    ``post-install-cmd``/``pre-update-cmd``/``post-update-cmd``/
    ``pre-autoload-dump``/``post-autoload-dump``/``pre-package-install``/
    ``post-package-install``/``pre-archive-cmd``/``post-archive-cmd``), or
    redirecting a package registry/index (``.npmrc``, ``.yarnrc``/
    ``.yarnrc.yml``, ``pip.conf``/``pip.ini``, ``.cargo/config.toml``,
    ``pyproject.toml``'s ``[[tool.poetry.source]]``).

    THREAT MODEL: ``rule_install_review`` forces a full read of a manifest
    before an install proceeds — it guards against installing a THIRD PARTY
    package that already carries a malicious lifecycle script. Nothing
    guarded the other direction: an agent (hijacked, prompt-injected, or
    just careless) EDITING a manifest to plant the script itself. A
    lifecycle hook runs with zero confirmation, zero explicit invocation by
    name, on the very next ``npm install``/``npm ci``/``composer install`` —
    by this same agent moments later, a teammate, or an unattended CI
    runner — and reads in a diff as a one-line, routine-looking addition to
    a ``scripts`` object, not as a backdoor. This is the exact mechanism
    behind real supply-chain compromises (eslint-scope, ua-parser-js,
    event-stream all shipped a malicious ``postinstall``). The registry half
    is the same "trusted name, poisoned source" shape ``ci_workflow``/
    ``git_hooks``/``agent_def``/``shell_persist`` all share: silently
    swapping WHERE every future, completely ordinary-looking
    ``npm install lodash`` fetches from.

    Distinct from every other ``*_protect`` guard in this file: those gate
    on PATH alone, because their target files (a CI workflow, a git hook, a
    shell rc file) are rarely touched for benign reasons. ``package.json``/
    ``composer.json``/``pyproject.toml`` are not — they're edited on nearly
    every commit to add a dependency or bump a version. Gating on path alone
    here would fire on almost every routine change and get this guard
    disabled from ask-fatigue, so both the manifest and registry checks also
    require the CONTENT of the edit to name one of a curated, narrow set of
    lifecycle-script/registry keys — names that essentially only ever appear
    in these files for the one reason this guard exists to catch. A benign
    edit adding a "test"/"build"/"start"/"lint" script (requires an explicit
    ``npm run <name>``, never auto-executed) never matches and stays
    allowed.

    Config (``policy.package_manifest``): ``mode`` (deny|ask|monitor|off,
    default ask), ``allow`` (regexes on the path/command that skip the gate
    — a repo's own trusted private-registry setup, say). Defaults to ``ask``
    for the same reason ``ci_workflow``/``git_hooks``/``agent_def``/
    ``shell_persist`` do: a ``postinstall: "patch-package"`` or a private
    Artifactory/Verdaccio registry pin is routine, sanctioned dev work, not
    inherently malicious — it just needs a human to have actually looked at
    it.

    Escapable only by a human: a trailing '# aegis-allow' on the shell form,
    or the env toggle ``AEGIS_ALLOW_PACKAGE_MANIFEST=1`` set by the
    orchestrator/human before launch for the Edit/Write/MCP-tool form. A
    spawned agent cannot set its own env for a hook invocation it doesn't
    control, so neither path is agent-self-escapable.

    QA history (two independent adversarial reviews, run in parallel): both
    rounds confirmed real bypasses, since fixed — ``pnpm pkg set`` (round A;
    ``NPM_PKG_SET_LIFECYCLE_RE`` hardcoded literal ``npm`` only), a
    jq-piped-through-``sponge`` in-place edit and jq's own ``--arg``
    key-indirection form (round A + round B; closed by
    ``JQ_SCRIPTS_LIFECYCLE_RE``, checked unconditionally like
    ``NPM_PKG_SET_LIFECYCLE_RE``/``REGISTRY_HIJACK_CLI_RE``), Yarn Classic's
    real space-delimited ``.yarnrc`` syntax (round B; the guard's own stated
    coverage for that file was dead code against an ``=``-only pattern), a
    reference MCP filesystem server's real ``edit_file`` shape (round A;
    ``{path, edits: [{oldText, newText}]}`` carries no top-level
    content/new_string key, so the original extraction always resolved
    empty), a too-tight ``{0,300}`` bound on the poetry-source content check
    (round A; widened to ``{0,2000}``, matching ``_HOOKSPATH_INI_RE_SRC``'s
    precedent), and thin CLI-only registry-hijack coverage for
    poetry/composer/cargo (round B; now covered by ``REGISTRY_HIJACK_CLI_RE``
    alongside npm/pnpm/yarn/pip).

    Known residual gaps, same spirit as every guard in this file, disclosed
    rather than fixed: a direct fetch-to-file write (``curl -o package.json
    ...``) is caught by none of the shell branch's write-verb checks, the
    same inherited gap every sibling guard already discloses; ``find
    -path``/``-name`` indirection around the manifest/config filename is not
    covered (no ``*_find_hit``-style fallback here, unlike self-protect/
    ci-workflow/git-hooks/agent-def/shell-persist); a value assembled via the
    target language's own string-building (Python ``'post'+'install'``, an
    f-string, ``.join()``) rather than appearing as one contiguous literal in
    the scanned text defeats both content checks — ``normalize.scan_surface``
    de-obfuscates shell-level quoting/encoding, not an embedded interpreter's
    own runtime string construction, the same "computed indirectly" class of
    gap every other guard in this file already accepts for shell-computed
    paths in general (round B, verified, not fixed — solving it in general is
    equivalent to evaluating arbitrary code); a lifecycle-script key split
    across two separate tool calls — an innocuous placeholder value planted
    and approved first, then swapped for the real payload in a second Edit
    whose ``old_string``/``new_string`` never repeats the key name — evades
    detection on the second call, since (like every guard in this file) there
    is no cross-call session state to notice the two edits target the same
    key (round A, verified, not fixed — the same "each tool call is evaluated
    independently" limitation ``git_hooks``' ``GIT_CONFIG_GLOBAL``/
    ``GIT_CONFIG_SYSTEM`` gap and every other guard's split-across-calls gap
    already accept); a commented-out example line in a registry-config file
    (a ``# index-url = ...`` template line, common generated-file boilerplate)
    still matches ``REGISTRY_HIJACK_RE`` and asks unnecessarily (round A,
    verified, not fixed — the accepted false-positive-over-false-negative
    trade-off every guard in this file already takes, and requiring
    line-start-anchoring to exclude it would have broken real detection on
    the shell branch, where a whole multi-clause command is one unbroken
    line with no comment/line-start distinction to anchor on); and, like
    every other guard here, a write-verb only needs to appear ANYWHERE in
    the command alongside the matched path, not adjacent to or provably
    operating on it — the accepted false-positive-over-false-negative
    trade-off every sibling guard in this file already takes."""
    cfg = getattr(policy, "package_manifest", None) or {}
    raw_mode = cfg.get("mode", "ask")
    mode = str(raw_mode).lower()
    if mode in ("off", "false") or raw_mode is False:
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    def _finish(would: Decision) -> Optional[Decision]:
        if mode == "monitor":
            _record_monitor(ev, would, "package-manifest-protect-monitor")
            return None
        return would

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        a = ev.args or {}
        # Claude Code's native Edit/Write always carry the changed text under
        # content/new_string, but a third-party MCP filesystem server's own
        # edit tool doesn't follow that convention — the reference
        # filesystem server's `edit_file`, for one, nests each change as
        # {path, edits: [{oldText, newText}]}, with no top-level content/
        # new_string key at all (QA finding, independent adversarial review,
        # round A): the original `a.get("content") or a.get("new_string")`
        # extraction resolved to "" for that real, common shape, so the
        # guard exited immediately and never saw the planted script. Falling
        # back to every string/number leaf in the MCP call's args (the same
        # `_flatten_strings` helper `_net_text` uses, for the identical
        # "arbitrary JSON shape, no fixed key convention across servers"
        # reason) closes it — Edit/Write keep the precise, narrower
        # extraction since their shape is fixed and known.
        content = str(a.get("content") or a.get("new_string") or "")
        if not content and ev.action == ActionClass.MCP:
            content = " ".join(_flatten_strings(a))
        if not p or not content:
            return None
        script_hit = bool(patterns.PACKAGE_SCRIPTS_PATH_RE.search(p)
                           and patterns.LIFECYCLE_SCRIPT_KEY_RE.search(content))
        registry_hit = bool(patterns.REGISTRY_CONFIG_PATH_RE.search(p)
                             and patterns.REGISTRY_HIJACK_RE.search(content))
        if not (script_hit or registry_hit):
            return None
        if (os.environ.get("AEGIS_ALLOW_PACKAGE_MANIFEST")
                or _package_manifest_allowed_by_policy(cfg, p)):
            return None
        reason = (f"Package manifest '{p}' is being written with a lifecycle-"
                  "script hook — it runs automatically, with no explicit "
                  "invocation, on the next install" if script_hit else
                  f"Package registry config '{p}' is being written — it "
                  "redirects where every future dependency install fetches "
                  "from")
        return _finish(Decision(action, "package-manifest-protect",
                         f"{reason}. Review the change, then confirm with "
                         "AEGIS_ALLOW_PACKAGE_MANIFEST=1; a spawned agent "
                         "cannot set this."))

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        write_verb = bool(patterns.WRITE_REDIRECT_RE.search(cmd)
                           or patterns.DELETE_OR_MOVE_VERB_RE.search(cmd)
                           or patterns.INPLACE_WRITE_RE.search(cmd)
                           or patterns.FORCED_LINK_WRITE_RE.search(cmd))
        script_hit = bool(patterns.NPM_PKG_SET_LIFECYCLE_RE.search(cmd)
                           or patterns.JQ_SCRIPTS_LIFECYCLE_RE.search(cmd)
                           or (write_verb
                               and patterns.PACKAGE_SCRIPTS_PATH_RE.search(cmd)
                               and patterns.LIFECYCLE_SCRIPT_KEY_RE.search(cmd)))
        registry_hit = bool(patterns.REGISTRY_HIJACK_CLI_RE.search(cmd)
                             or (write_verb
                                 and patterns.REGISTRY_CONFIG_PATH_RE.search(cmd)
                                 and patterns.REGISTRY_HIJACK_RE.search(cmd)))
        if not (script_hit or registry_hit):
            return None
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_PACKAGE_MANIFEST")
                or _package_manifest_allowed_by_policy(cfg, _cmd(ev))):
            return None
        reason = ("A lifecycle-script hook is being planted in a package "
                  "manifest from a shell — it runs automatically on the "
                  "next install" if script_hit else
                  "A package registry/index is being redirected from a "
                  "shell — every future dependency install will fetch from "
                  "the new source")
        return _finish(Decision(action, "package-manifest-protect",
                         f"{reason}. A human may append '# aegis-allow', or "
                         "set AEGIS_ALLOW_PACKAGE_MANIFEST=1; a spawned "
                         "agent cannot."))
    return None


# ---- workspace confinement: opt-in, file-mutation tools ----------------------
def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root + os.sep)


def _confine_root(policy):
    """The project root the agent is confined to (file mutations must stay under
    it). Precedence: a VERIFIED token's `project` claim (identity binding) ->
    AEGIS_PROJECT -> policy.workspace.root -> AEGIS_WORKSPACE -> policy.project
    (.aegis default). None -> confinement is off."""
    cfg = getattr(policy, "workspace", None) or {}
    try:
        from . import identity
        claims = identity.current() or {}
    except Exception:
        claims = {}
    return (claims.get("project")
            or os.environ.get("AEGIS_PROJECT")
            or cfg.get("root")
            or os.environ.get("AEGIS_WORKSPACE")
            or getattr(policy, "project", None))


def rule_workspace_confine(ev: Event, policy=None) -> Optional[Decision]:
    """Hard-block file mutations (edit/write) outside the agent's project root.
    The root comes from the identity (token `project` claim / AEGIS_PROJECT) or
    policy (workspace.root / project). Non-escapable: an agent bound to a project
    cannot wander out of it. Reads are unaffected; full SHELL confinement is an OS
    concern (restricted user / container) - see README."""
    if ev.action not in (ActionClass.EDIT, ActionClass.WRITE):
        return None
    root = _confine_root(policy)
    if not root:
        return None
    target = _path(ev)
    if not target:
        return None
    cfg = getattr(policy, "workspace", None) or {}
    base = ev.cwd or os.getcwd()
    ap = os.path.abspath(os.path.join(base, os.path.expanduser(target)))
    roots = [os.path.abspath(os.path.expanduser(root))]
    roots += [os.path.abspath(os.path.expanduser(p)) for p in (cfg.get("allow") or [])]
    if any(_within(ap, r) for r in roots):
        return None
    return Decision(Action.DENY, "workspace-confine",
                    f"Out-of-project write blocked: {ap} is outside the agent's "
                    f"project root {roots[0]}. The identity is confined to its "
                    "project; widen it with workspace.allow or rebind the identity.")


# ---- sub-agent spawn governance: configurable ----------------------------------
def rule_subagent_spawn(ev: Event, policy=None) -> Optional[Decision]:
    """Block programmatic sub-agent fan-out (Agent/Task) for a SPAWNED agent —
    uncontrolled cost / blast radius. Humans/orchestrators may delegate. Override
    with AEGIS_ALLOW_SUBAGENTS=1 (or a declarative allow rule)."""
    if ev.action != ActionClass.SUBAGENT:
        return None
    if os.environ.get("AEGIS_ALLOW_SUBAGENTS"):
        return None
    if not os.environ.get("AEGIS_AGENT_NAME"):
        return None  # a human/orchestrator session may spawn
    return Decision(Action.DENY, "subagent-spawn",
                    "Spawned agents may not spawn sub-agents (Agent/Task) — programmatic "
                    "fan-out is uncontrolled cost/blast-radius. Do the work in this "
                    "session, or set AEGIS_ALLOW_SUBAGENTS=1.")


# ---- network egress governance: policy-driven --------------------------------
def rule_network_egress(ev: Event, policy=None) -> Optional[Decision]:
    """Govern where an agent may reach out. Reads ``policy.egress``:
    {default: allow|deny, allow: [host globs], deny: [host globs]}. No config -> no
    opinion. Covers net tools (url arg) and shell curl/Invoke-WebRequest URLs."""
    cfg = getattr(policy, "egress", None) or {}
    if not cfg:
        return None
    host = _egress_host(ev)
    if not host:
        return None
    deny = cfg.get("deny") or []
    allow = cfg.get("allow") or []
    default = str(cfg.get("default") or "allow").lower()
    if any(fnmatch.fnmatch(host, p) for p in deny):
        return Decision(Action.DENY, "egress", f"Network egress to '{host}' is blocked.")
    if allow and any(fnmatch.fnmatch(host, p) for p in allow):
        return None
    if default == "deny":
        return Decision(Action.DENY, "egress",
                        f"Network egress to '{host}' is not in the allowlist.")
    return None


# ---- migration / destructive-SQL: escapable with '# aegis-allow' / '-- aegis-allow'
def rule_migration_protection(ev: Event, policy=None) -> Optional[Decision]:
    """Block destructive DB ops / migration resets — across shell AND DB MCP tools
    (the tool args carry the SQL even when there is no shell)."""
    text = _sql_text(ev)
    if not text:
        return None
    if not (patterns.DESTRUCTIVE_SQL_RE.search(text)
            or patterns.DESTRUCTIVE_MIGRATION_RE.search(text)):
        return None
    if _override_allowed(ev, text):
        return None
    return Decision(Action.DENY, "destructive-migration",
                    "Destructive database/migration op (DROP / TRUNCATE / ALTER ... DROP "
                    "/ reset / downgrade, or DELETE/UPDATE without WHERE) is blocked. "
                    "Append '# aegis-allow' (or SQL '-- aegis-allow') to confirm intent.")


# ---- destructive git / delete: escapable with '# aegis-allow' ----------------
def rule_destructive_git(ev: Event, policy=None) -> Optional[Decision]:
    if not _is_shell(ev) or not patterns.DESTRUCTIVE_GIT_RE.search(_shell_scan(ev)):
        return None
    if _override_allowed(ev):
        return None
    return Decision(Action.DENY, "destructive-git",
                    "Destructive/history-rewriting git is blocked — append '# aegis-allow' "
                    "to confirm, or use a safe alternative (git revert, git branch -d).")


def rule_destructive_delete(ev: Event, policy=None) -> Optional[Decision]:
    if not _is_shell(ev) or not patterns.DESTRUCTIVE_DELETE_RE.search(_shell_scan(ev)):
        return None
    if _override_allowed(ev):
        return None
    return Decision(Action.DENY, "destructive-delete",
                    "Recursive force delete is blocked. Append '# aegis-allow' to confirm.")


# ---- evasion / obfuscation: deliberately hiding what you run -----------------
def rule_evasion(ev: Event, policy=None) -> Optional[Decision]:
    """Deny obfuscation tells (encoded commands, base64-decode piped to a shell,
    FromBase64String, char-code construction). Deliberately hiding a command from
    the guard IS the signal. Escapable only by a human."""
    if not _is_shell(ev):
        return None
    if not patterns.EVASION_RE.search(_cmd(ev)):
        return None
    if _override_allowed(ev):
        return None
    return Decision(Action.DENY, "evasion",
                    "Obfuscated/encoded command blocked — run it in the clear so the "
                    "policy can see it (encoded commands, base64-piped-to-shell, and "
                    "char-code construction are how guards get bypassed).")


# ---- forced install review: read-before-install, then human ask --------------
def rule_install_review(ev: Event, policy=None) -> Optional[Decision]:
    """Force a full read of an install's manifest, then a human ask.

    A careless agent runs ``pip install -r requirements.txt`` straight from a repo's
    setup notes and never looks at what it pulls in. This gate closes that path:

    1. **Deny until read** — any install whose manifest (``requirements.txt``,
       ``package.json`` + lock, ``pyproject.toml``/``poetry.lock``, …; plus the
       *local* install-time scripts in ``deep`` mode) hasn't been **fully read** this
       session is refused. A skim — a ``Read`` that stops short, or a ``grep``/``head``
       peek — never satisfies coverage (see ``aegis.review``).
    2. **Then ask** — once coverage is satisfied, the install is surfaced to the human
       with a factual digest (dep count, unpinned specs, URL/VCS deps, install
       scripts) instead of running silently.

    Honest scope: this gates the *manifest* and forces a human decision. It does NOT
    inspect a dependency's install-time code (that runs inside the package manager's
    subprocess, below the hook boundary), so it does not by itself stop a clean-repo /
    error-driven attack whose payload is in package code or a later step. ``deep`` mode
    force-reads the *local* setup.py/postinstall (catching a malicious ``pip install
    .``), not a downloaded third-party package's. Pair with egress + OS isolation.

    Config (``policy.install_review``): ``mode`` (off|monitor|ask, default ask;
    monitor logs the would-be decision to the audit and allows), ``deep``,
    ``require_pinned`` (deny unpinned specs), ``allow`` (regex exemptions on the raw
    command). The read-gate is non-escapable by a spawned agent (it cannot
    ``# aegis-allow`` itself); a human may override. No-execute fetches
    (``pip download``, ``npm pack``) and ``AEGIS_ALLOW_INSTALL=1`` bypass the gate.
    Coverage requires the runtime to deliver Read content at PostToolUse (Claude Code
    does); a runtime that doesn't will fail closed — use a human override or monitor."""
    if not _is_shell(ev):
        return None
    text = _shell_scan(ev)
    if not patterns.INSTALL_ANY_RE.search(text):
        return None
    if patterns.NOEXEC_FETCH_RE.search(text):
        return None  # a no-execute fetch (download/pack) is not an install
    if os.environ.get("AEGIS_ALLOW_INSTALL"):
        return None
    cfg = getattr(policy, "install_review", None) or {}
    mode = str(cfg.get("mode", "ask")).lower()
    if mode == "off":
        return None
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), _cmd(ev), re.IGNORECASE):
                return None
        except re.error:
            continue

    cwd = ev.cwd or os.getcwd()
    deep = bool(cfg.get("deep"))
    # Detection runs on the de-obfuscated surface (catches wrapped installs); manifest
    # / package resolution runs on the RAW command — the scan surface duplicates tokens,
    # which would corrupt package-name and path parsing.
    raw_cmd = _cmd(ev)
    manifests = review.resolve_manifests(raw_cmd, cwd, deep=deep)
    session = ev.session_id or os.environ.get("AEGIS_SESSION_ID")
    unread = [m for m in manifests if not review.is_fully_read(session, m, cwd)]
    if _override_allowed(ev):  # human override (a spawned agent can't reach this)
        return None

    # The decision this gate WOULD make (None -> nothing to do / allow).
    would: Optional[Decision] = None
    if unread:
        names = ", ".join(os.path.basename(m) for m in unread)
        what = "install-time script(s)/manifest(s)" if deep else "manifest(s)"
        would = Decision(Action.DENY, "install-review",
                         f"Install blocked — forced dependency review: {names} not fully "
                         f"read this session. Read the entire {what} in full (no "
                         f"limit/offset, no grep/head/tail) so the dependency list is "
                         f"actually in context, then retry. A human may append "
                         f"'# aegis-allow'; a spawned agent cannot.")
    else:
        d = review.digest(manifests, raw_cmd, cwd)
        if cfg.get("require_pinned") and d.get("unpinned"):
            would = Decision(Action.DENY, "install-review",
                             f"Install blocked — {d['unpinned']} unpinned dependency "
                             f"spec(s); the installed set must be pinned (exact '==' / a "
                             f"lockfile) to be reviewable. Pin the versions, or append "
                             f"'# aegis-allow' (human only). [{review.format_digest(d)}]")
        else:
            would = Decision(Action.ASK, "install-review",
                             f"Dependency install — review the dependency list before "
                             f"approving: {review.format_digest(d)}. (The manifest is "
                             f"reviewed; package install-time code is not — see docs.)")

    if mode == "monitor":
        _record_monitor(ev, would)
        return None
    return would


def _record_monitor(ev: Event, would: Decision, rule_note: str = "install-review-monitor") -> None:
    """Monitor mode: record the would-be decision to the audit (so a pilot can measure
    projected denials with `aegis report`) without blocking. Best-effort."""
    try:
        from . import config
        from .audit import write_event
        note = Decision(would.action, rule_note,
                        f"[monitor] would {would.action.value}: {would.message}")
        write_event(ev, note, str(config.audit_path()))
    except Exception:
        pass


# ---- failure-loop: an identical retry of a call that keeps failing -----------
def rule_failure_loop(ev: Event, policy=None) -> Optional[Decision]:
    """Deny the Nth identical retry of a tool call that already failed N times
    this session — the agent-thrash loop. The enforcement point is PreToolUse
    (blockable); the evidence comes from the ``aegis.failures`` ledger, fed by
    PostToolUseFailure (observational). Only an *identical* call (same tool,
    same args — see ``failures.signature``) counts: the deny reason tells the
    model to change approach, and any change starts a fresh signature. A later
    success of the same signature clears its streak.

    Config (``policy.failures``): ``mode`` (deny|ask|monitor|off, default deny),
    ``max_repeats`` (default 3). Escapable by a human only: '# aegis-allow' on a
    shell command, or AEGIS_ALLOW_RETRY=1 set by the orchestrator."""
    if ev.event != HookEvent.PRE_TOOL_USE:
        return None
    cfg = getattr(policy, "failures", None) or {}
    mode = str(cfg.get("mode", "deny")).lower()
    # YAML 1.1 parses an unquoted `off` as boolean False — accept both spellings.
    if mode in ("off", "false") or cfg.get("mode") is False:
        return None
    if os.environ.get("AEGIS_ALLOW_RETRY"):
        return None
    try:
        limit = max(1, int(cfg.get("max_repeats", 3)))
    except (TypeError, ValueError):
        limit = 3
    from . import failures
    session = ev.session_id or os.environ.get("AEGIS_SESSION_ID")
    n = failures.failure_count(session, failures.signature(ev.tool, ev.args))
    if n < limit:
        return None
    if _override_allowed(ev):
        return None
    action = Action.ASK if mode == "ask" else Action.DENY
    would = Decision(action, "failure-loop",
                     f"This exact {ev.tool or 'tool'} call already failed {n} "
                     "time(s) this session — an identical retry is a thrash loop, "
                     "not progress. Read the error, fix the cause or change the "
                     "arguments/approach, then proceed. A human may append "
                     "'# aegis-allow' or set AEGIS_ALLOW_RETRY=1.")
    if mode == "monitor":
        _record_monitor(ev, would, "failure-loop-monitor")
        return None
    return would


# ---- fetch-and-execute / DNS-C2: remote code an agent never read -------------
def rule_remote_exec(ev: Event, policy=None) -> Optional[Decision]:
    """Deny piping a network fetch straight into a shell (``curl … | sh``) and DNS-TXT
    command/payload retrieval — remote code (or a DNS-delivered payload) that was
    never read. This catches the common single-command *shape*; it is not exhaustive
    — fetch-to-temp-then-exec as two statements, or an in-process resolver/HTTP call
    inside an interpreted program, won't surface here (deny-by-default egress is the
    backstop for those). Human-escapable like evasion; a spawned agent cannot."""
    if not _is_shell(ev):
        return None
    text = _shell_scan(ev)
    if not (patterns.PIPE_TO_SHELL_RE.search(text) or patterns.DNS_C2_RE.search(text)):
        return None
    if _override_allowed(ev):
        return None
    return Decision(Action.DENY, "remote-exec",
                    "Fetch-piped-to-shell / DNS-TXT command retrieval is blocked — this "
                    "runs remote code (or a DNS-delivered payload) that was never read. "
                    "Download it, read it in full, then run the local copy. A human may "
                    "append '# aegis-allow'.")


# ---- branch strands: work-loss prevention, escapable ------------------------
def _git_out(cwd, *args) -> str:
    """Run a read-only git command; return stdout or empty. Windowless, time-bounded,
    fail-safe (any error -> '')."""
    try:
        flags = 0x08000000 if os.name == "nt" else 0
        r = subprocess.run(["git", "-C", str(cwd or "."), *args],
                           capture_output=True, text=True, timeout=5,
                           creationflags=flags)
        return (r.stdout or "").strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def _commits_ahead(cwd) -> tuple:
    """(current_branch, n_commits_ahead_of_main). Returns (None, 0) on uncertainty
    so the guard fails OPEN."""
    try:
        cur = _git_out(cwd, "rev-parse", "--abbrev-ref", "HEAD")
        if not cur or cur == "HEAD":
            return (None, 0)
        base = None
        for b in ("main", "master"):
            if _git_out(cwd, "rev-parse", "--verify", "--quiet", b):
                base = b
                break
        if not base or cur == base:
            return (cur, 0)
        n = _git_out(cwd, "rev-list", "--count", f"{base}..HEAD")
        return (cur, int(n) if (n and n.isdigit()) else 0)
    except Exception:
        return (None, 0)


def rule_branch_strands(ev: Event, policy=None) -> Optional[Decision]:
    """Don't create a new branch while the current one has commits not in main —
    that strands the old work. Covers shell ``git checkout -b`` / ``git switch -c``.
    Escapable with ``# aegis-allow`` or ``AEGIS_ALLOW_STRAND=1``. Fail-OPEN."""
    if not _is_shell(ev):
        return None
    if os.environ.get("AEGIS_ALLOW_STRAND"):
        return None
    text = _shell_scan(ev)
    if not patterns.NEW_BRANCH_RE.search(text):
        return None
    if _override_allowed(ev):
        return None
    cwd = ev.cwd or os.getcwd()
    cur, ahead = _commits_ahead(cwd)
    if ahead <= 0:
        return None
    return Decision(Action.DENY, "branch-strand",
                    f"Branch '{cur}' has {ahead} commit(s) not in main. Creating a new "
                    "branch now strands that work. Merge/push/PR the current branch "
                    "first, then create the new one. Append '# aegis-allow' to override, "
                    "or set AEGIS_ALLOW_STRAND=1.")


def _lifecycle_rules() -> tuple:
    """Pull in the lifecycle-hook rules (ConfigChange / SubagentStart / PreCompact /
    PermissionRequest / WorktreeCreate / ...). Imported here (not at top) so the
    dependency stays one-way: lifecycle submodules never import this module.
    Fail-open: a broken lifecycle import must not strip the core guards."""
    try:
        from .lifecycle import lifecycle_rules
        return lifecycle_rules()
    except Exception:
        return ()


_CORE_RULES = (
    rule_attest_session,
    rule_containment,
    rule_self_protect,
    rule_mcp_config_protect,
    rule_ci_workflow_protect,
    rule_git_hooks_protect,
    rule_agent_def_protect,
    rule_shell_persist_protect,
    rule_package_manifest_protect,
    rule_workspace_confine,
    rule_migration_protection,
    rule_subagent_spawn,
    rule_network_egress,
    rule_evasion,
    rule_failure_loop,
    rule_remote_exec,
    rule_destructive_git,
    rule_destructive_delete,
    rule_install_review,
    rule_branch_strands,
)

# Core PreToolUse/shell guards first, then the lifecycle-hook rules that cover the
# rest of the runtime's event surface (config integrity, team/sub-agent, compaction,
# worktree confinement, MCP-input governance).
BUILTIN_RULES = _CORE_RULES + _lifecycle_rules()
