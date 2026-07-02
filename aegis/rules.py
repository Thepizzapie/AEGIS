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
    if _is_shell(ev):
        text = _shell_scan(ev)
    elif ev.action in (ActionClass.READ, ActionClass.EDIT, ActionClass.WRITE):
        text = _path(ev) + " " + str((ev.args or {}).get("content") or "")
    else:
        return None
    if not text.strip():
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
        if (patterns.CONFIG_DIR_RE.search(cmd) or patterns.AEGIS_SOURCE_RE.search(cmd)) and (
                patterns.DELETE_OR_MOVE_VERB_RE.search(cmd)
                or patterns.DESTRUCTIVE_DELETE_RE.search(cmd)
                or patterns.WRITE_REDIRECT_RE.search(cmd)
                or patterns.COPY_WRITE_VERB_RE.search(cmd)):
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
