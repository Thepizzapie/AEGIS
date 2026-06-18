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

from . import normalize, patterns
from .events import ActionClass, Event, HookEvent
from .policy import Action, Decision

_URL_RE = re.compile(r"https?://([^/\s'\"]+)", re.IGNORECASE)


def _cmd(ev: Event) -> str:
    return str((ev.args or {}).get("command") or "")


def _path(ev: Event) -> str:
    a = ev.args or {}
    return str(a.get("file_path") or a.get("path") or a.get("notebook_path") or "")


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
                or patterns.WRITE_REDIRECT_RE.search(cmd)):
            return Decision(Action.DENY, "self-protect",
                            "Writing/deleting/moving Aegis's own config, policy, or engine "
                            "source is blocked.")
        return None
    if ev.action in (ActionClass.EDIT, ActionClass.WRITE):
        p = _path(ev)
        if patterns.ENFORCEMENT_PATH_RE.search(p) or patterns.AEGIS_SOURCE_RE.search(p):
            return Decision(Action.DENY, "self-protect",
                            "Editing Aegis's own config or engine source is blocked.")
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


# ---- bulk dependency install: supply-chain defense, escapable ----------------
def rule_bulk_install(ev: Event, policy=None) -> Optional[Decision]:
    """Block blind / bulk dependency installs — ``npm install``, ``pip install -r``,
    ``poetry install``, ``cargo build``, ``go mod download``, etc. A hijacked agent
    adding a poisoned ``requirements.txt`` or running ``npm install`` in a
    compromised repo is a supply-chain attack vector. Targeted single-package
    installs (``npm install lodash``) are fine. Escapable with ``# aegis-allow``
    or ``AEGIS_ALLOW_INSTALL=1``."""
    if not _is_shell(ev):
        return None
    if os.environ.get("AEGIS_ALLOW_INSTALL"):
        return None
    text = _shell_scan(ev)
    if not patterns.BULK_INSTALL_RE.search(text):
        return None
    if _override_allowed(ev):
        return None
    return Decision(Action.DENY, "bulk-install",
                    "Bulk/blind dependency install is blocked — supply-chain risk. "
                    "If this is intentional, append '# aegis-allow' to the command or "
                    "set AEGIS_ALLOW_INSTALL=1.")


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


BUILTIN_RULES = (
    rule_attest_session,
    rule_containment,
    rule_self_protect,
    rule_workspace_confine,
    rule_migration_protection,
    rule_subagent_spawn,
    rule_network_egress,
    rule_evasion,
    rule_destructive_git,
    rule_destructive_delete,
    rule_bulk_install,
    rule_branch_strands,
)
