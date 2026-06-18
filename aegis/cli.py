"""Aegis CLI (AEGI-2/3): ``aegis hook``, ``aegis install``, ``aegis uninstall``,
``aegis validate``.

``aegis hook`` is the entrypoint the agent runtime's hooks invoke. It reads the
hook JSON on stdin, evaluates policy, writes an audit record, and emits a
Claude-Code decision (deny -> the action is blocked, reason fed to the model).

``aegis install`` wires Aegis into a Claude Code ``settings.json`` by MERGING —
it never clobbers existing hooks or other keys. ``aegis uninstall`` removes only
Aegis's own entries. ``aegis validate`` checks policy YAML.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import adapters, config, identity
from .audit import write_event
from .engine import safe_evaluate
from .events import HookEvent
from .policy import Action, Decision, Policy

HOOK_EVENTS = [e.value for e in HookEvent]
AEGIS_COMMAND_PREFIX = "aegis hook"


# ---------------------------------------------------------------- hook entrypoint
def _read_hook_stdin() -> str:
    """Read the hook payload from stdin as UTF-8, tolerating a leading BOM.

    PowerShell's pipeline prepends a UTF-8 BOM, and reading text-mode under the
    console code page can mis-decode those bytes; either way ``json.loads`` would
    raise and the payload would silently degrade to ``{}`` (-> allow). Decoding
    the raw bytes with ``utf-8-sig`` strips the BOM regardless of code page.
    Falls back to text-mode stdin for embeddings/tests without a buffer.
    """
    stdin = sys.stdin
    if stdin is None or stdin.isatty():
        return ""
    buffer = getattr(stdin, "buffer", None)
    if buffer is not None:
        try:
            return buffer.read().decode("utf-8-sig")
        except Exception:
            pass
    try:
        return stdin.read().lstrip(chr(0xfeff))
    except Exception:
        return ""


def _fail_closed(policy) -> bool:
    """Whether an UNPARSEABLE payload should DENY rather than allow. Default is
    fail-open (don't brick the agent on a one-off bad payload); opt into
    fail-closed with AEGIS_FAIL_CLOSED=1 or a policy `on_error: deny`."""
    if (os.environ.get("AEGIS_FAIL_CLOSED") or "").strip().lower() in ("1", "true", "yes", "on"):
        return True
    return getattr(policy, "on_error", None) == Action.DENY


def _cmd_hook(args) -> int:
    raw = _read_hook_stdin()
    payload, parse_error = {}, None
    if raw.strip():
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            parse_error = str(exc)

    name = args.event or payload.get("hook_event_name") or payload.get("hookEventName")
    if name not in HOOK_EVENTS:
        return 0  # unknown / unsupported event -> never interfere

    payload.setdefault("hook_event_name", name)
    try:
        adapter = adapters.get_adapter(getattr(args, "runtime", None))
    except KeyError as exc:
        print(f"aegis: {exc}", file=sys.stderr)
        return 0  # unknown runtime -> never interfere
    event = adapter.parse_event(payload)
    policy = _load_policy_safe()
    label = getattr(policy, "agent_label", None)

    # Attribution: payload wins, then the spawner's env, then the repo's
    # configured agent_label, then the runtime name -> the audit never records
    # "nothing". session_id is native in Claude Code (other runtimes via
    # AEGIS_SESSION_ID); agent is rarely in the payload, so it falls back through
    # AEGIS_AGENT_NAME and the label so every record says which agent acted.
    runtime = getattr(adapter, "RUNTIME", None) or "agent"
    if not event.agent:
        event.agent = os.environ.get("AEGIS_AGENT_NAME") or label or runtime
    if not event.session_id:
        event.session_id = (os.environ.get("AEGIS_SESSION_ID")
                            or f"{runtime}-{os.getppid()}")

    # RBAC (AEGI-6): resolve caller identity + roles (env -> label -> OS user)
    ident, roles = identity.resolve_identity(payload, label=label)
    if not event.identity:
        event.identity = ident
    if not event.roles:
        event.roles = roles

    if parse_error is not None:
        # A payload we can't parse must not vanish into a silent allow: make it
        # VISIBLE (stderr + audit) and honor fail-closed mode.
        closed = _fail_closed(policy)
        decision = Decision(
            Action.DENY if closed else Action.ALLOW, "payload-parse-error",
            f"Unparseable hook payload ({parse_error}); "
            + ("blocked by fail-closed mode." if closed
               else "allowed (fail-open) - set AEGIS_FAIL_CLOSED=1 or on_error: deny to block."))
        if not closed:
            print(f"[Aegis] warning: could not parse hook payload ({parse_error}); "
                  "allowing (fail-open). Set AEGIS_FAIL_CLOSED=1 to block by default.",
                  file=sys.stderr)
    else:
        decision = safe_evaluate(event, policy)

    try:
        write_event(event, decision, str(config.audit_path()))
    except Exception:
        pass  # audit must never block the action

    code, out, err = adapter.render_decision(event, decision)
    if out:
        sys.stdout.write(out)
    if err:
        sys.stderr.write(err)
    return code


# ---------------------------------------------------------------- install / remove
def _settings_path(args) -> Path:
    if getattr(args, "project", None):
        return Path(args.project) / ".claude" / "settings.json"
    if getattr(args, "glob", False):
        return Path.home() / ".claude" / "settings.json"
    return Path.cwd() / ".claude" / "settings.json"


def install_hooks(settings_path: Path, command: str = AEGIS_COMMAND_PREFIX) -> int:
    """Merge Aegis hook entries into a Claude Code settings.json WITHOUT
    clobbering existing hooks or keys. Idempotent. Returns how many event hooks
    were newly added."""
    settings_path = Path(settings_path)
    data = _read_json(settings_path)
    hooks = data.setdefault("hooks", {})
    added = 0
    for ev in HOOK_EVENTS:
        entries = hooks.setdefault(ev, [])
        if not _has_aegis(entries):
            entries.append({
                "matcher": "*",
                "hooks": [{"type": "command", "command": f"{command} {ev}",
                           "_source": "aegis"}],
            })
            added += 1
    _write_json(settings_path, data)
    return added


def uninstall_hooks(settings_path: Path) -> int:
    """Remove only Aegis's hook entries from a settings.json. Returns count removed."""
    settings_path = Path(settings_path)
    data = _read_json(settings_path)
    hooks = data.get("hooks", {})
    removed = 0
    for ev in list(hooks.keys()):
        kept = []
        for entry in hooks.get(ev, []):
            inner = entry.get("hooks", [])
            pruned = [h for h in inner if not _is_aegis_hook(h)]
            removed += len(inner) - len(pruned)
            if pruned or not inner:
                entry["hooks"] = pruned
                kept.append(entry)
        if kept:
            hooks[ev] = kept
        else:
            hooks.pop(ev, None)
    _write_json(settings_path, data)
    return removed


def _is_aegis_hook(h) -> bool:
    """Recognize an Aegis-installed hook however the command was spelled — bare
    `aegis hook` or an absolute path like `.../aegis.exe hook`. The `_source` tag is
    written at install; the command check covers entries installed before the tag."""
    if h.get("_source") == "aegis":
        return True
    c = str(h.get("command", "")).lower()
    return "aegis" in c and "hook" in c


def _has_aegis(entries) -> bool:
    return any(_is_aegis_hook(h) for entry in entries for h in entry.get("hooks", []))


def _read_json(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _cmd_install(args) -> int:
    target = _settings_path(args)
    n = install_hooks(target, command=args.command or AEGIS_COMMAND_PREFIX)
    print(f"aegis: ensured {len(HOOK_EVENTS)} hook event(s) ({n} newly added) in {target}")
    return 0


def _cmd_uninstall(args) -> int:
    target = _settings_path(args)
    n = uninstall_hooks(target)
    print(f"aegis: removed {n} Aegis hook(s) from {target}")
    return 0


# ---------------------------------------------------------------- validate
def _cmd_validate(args) -> int:
    from .loader import validate_policy
    target = args.dir or str(config.policy_dir())
    errors = validate_policy(target)
    if errors:
        for e in errors:
            print(f"aegis: {e}", file=sys.stderr)
        print(f"aegis: {len(errors)} policy problem(s) in {target}", file=sys.stderr)
        return 1
    print(f"aegis: policy OK — {target}")
    return 0


# ---------------------------------------------------------------- report
def _cmd_report(args) -> int:
    from .accountability import report
    target = args.audit or str(config.audit_path())
    rep = report(target)
    if args.json:
        print(json.dumps(rep, indent=2, default=str))
        return 0
    s = rep["summary"]
    print(f"Aegis accountability — {target}")
    print(f"  events {s['total']} | denied {s['denied']}")
    if s["by_decision"]:
        print(f"  decisions: {s['by_decision']}")
    if s["by_action"]:
        print(f"  actions:   {s['by_action']}")
    if s["top_tools"]:
        print("  top tools: " + ", ".join(f"{t}={n}" for t, n in s["top_tools"]))
    usage = s.get("usage")
    if usage:
        parts = []
        for k in ("input_tokens", "output_tokens", "cache_read_input_tokens",
                   "cache_creation_input_tokens", "num_turns"):
            v = usage.get(k)
            if v is not None:
                parts.append(f"{k}={v:,}" if isinstance(v, int) else f"{k}={v}")
        cost = usage.get("total_cost") or usage.get("cost_usd")
        if cost is not None:
            parts.append(f"cost=${cost:.4f}")
        if parts:
            print("  usage:     " + "  ".join(parts))
    dens = rep["denials"]
    if dens:
        print(f"  denials ({len(dens)}):")
        for d in dens[:20]:
            print(f"    [{d.get('ts', '')}] {d.get('tool')} <{d.get('action')}> "
                  f"rule={d.get('rule')} session={d.get('session_id')}")
    flagged = {sid: v for sid, v in rep.get("verdicts", {}).items() if not v["ok"]}
    if flagged:
        print("  flagged sessions:")
        for sid, v in flagged.items():
            print(f"    {sid}: {', '.join(v['flags'])}")
    # Per-session usage breakdown (only sessions with usage data)
    sessions_with_usage = {sid: s for sid, s in rep.get("sessions", {}).items()
                           if s.get("usage")}
    if sessions_with_usage:
        print("  session usage:")
        for sid, sess in sessions_with_usage.items():
            u = sess["usage"]
            tok_in = u.get("input_tokens", 0)
            tok_out = u.get("output_tokens", 0)
            cost = u.get("total_cost") or u.get("cost_usd")
            agent = sess.get("agent") or ""
            line = f"    {sid}"
            if agent:
                line += f" ({agent})"
            line += f": {sess['total']} calls"
            if tok_in or tok_out:
                line += f", {tok_in:,}+{tok_out:,} tokens"
            if cost:
                line += f", ${cost:.4f}"
            print(line)
    return 0


# ---------------------------------------------------------------- git / CI surface
AEGIS_HOOK_MARKER = "# >>> aegis >>>"


def _load_policy_safe() -> Policy:
    # built-in secure-by-default rules are applied by the engine itself
    # (aegis.rules); this only loads the user's declarative policy.
    try:
        from .loader import load_policy
        return load_policy(config.policy_dir())
    except Exception as exc:  # noqa: BLE001 — a broken policy must not block
        print(f"aegis: failed to load policy ({exc!r}); allowing", file=sys.stderr)
        return Policy()


def _resolve_aegis_command() -> str:
    """Absolute command used to invoke aegis FROM a git hook. Git runs hooks in a
    bare /bin/sh that does NOT have a venv's Scripts/bin on PATH, so a bare ``aegis``
    fails with 'command not found' and blocks every commit for the wrong reason.
    Resolve to the running executable's absolute path (works for pip-editable venvs
    and pipx); fall back to bare PATH only as a last resort."""
    import shutil
    candidates = [os.path.abspath(sys.argv[0])] if (sys.argv and sys.argv[0]) else []
    bindir = os.path.dirname(sys.executable or "")
    if bindir:
        candidates += [os.path.join(bindir, "aegis.exe"), os.path.join(bindir, "aegis")]
    found = shutil.which("aegis")
    if found:
        candidates.append(found)
    for c in candidates:
        if c and os.path.exists(c) and "aegis" in os.path.basename(c).lower():
            c = c.replace("\\", "/")
            return f'"{c}"' if " " in c else c
    return "aegis"  # last resort: rely on PATH (see README install caveat)


def install_git_hooks(repo, command=None) -> int:
    """Write pre-commit + pre-push hooks that call ``aegis git-hook``, appending to
    existing hook scripts without clobbering them. Idempotent. Returns hooks ensured."""
    cmd = command or _resolve_aegis_command()
    hooks_dir = Path(repo) / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    ensured = 0
    for hook, op in (("pre-commit", "commit"), ("pre-push", "push")):
        path = hooks_dir / hook
        block = f"{AEGIS_HOOK_MARKER}\n{cmd} git-hook {op} || exit 1\n# <<< aegis <<<\n"
        if path.exists():
            content = path.read_text(encoding="utf-8")
            if AEGIS_HOOK_MARKER in content:
                continue
            content = content.rstrip("\n") + "\n\n" + block
        else:
            content = "#!/bin/sh\n" + block
        path.write_text(content, encoding="utf-8")
        try:
            os.chmod(path, 0o755)
        except OSError:
            pass
        ensured += 1
    return ensured


def _cmd_git_hook(args) -> int:
    from . import gitsurface
    repo = args.repo or "."
    policy = _load_policy_safe()
    branch = gitsurface.current_branch(repo)
    if args.op == "commit":
        denied = gitsurface.check_commit(policy, gitsurface.staged_files(repo), branch)
        for f, d in denied:
            try:
                write_event(gitsurface.git_event("commit", file=f, branch=branch), d,
                            str(config.audit_path()))
            except Exception:
                pass
            print(f"[Aegis] blocked commit of {f}: {d.message or d.rule}", file=sys.stderr)
        return 1 if denied else 0
    if args.op == "push":
        d = gitsurface.check_push(policy, branch)
        try:
            write_event(gitsurface.git_event("push", branch=branch), d, str(config.audit_path()))
        except Exception:
            pass
        if d.blocked:
            print(f"[Aegis] blocked push on {branch}: {d.message or d.rule}", file=sys.stderr)
            return 1
    return 0


def _cmd_install_git(args) -> int:
    repo = args.repo or "."
    n = install_git_hooks(repo, command=getattr(args, "command", None))
    print(f"aegis: ensured {n} git hook(s) in {Path(repo) / '.git' / 'hooks'}")
    return 0


def _cmd_ci(args) -> int:
    from . import gitsurface
    repo = args.repo or "."
    base = args.base or "origin/main"
    policy = _load_policy_safe()
    files = gitsurface.changed_files(repo, base)
    branch = gitsurface.current_branch(repo)
    denied = gitsurface.check_commit(policy, files, branch)
    for f, d in denied:
        print(f"::error file={f}::[Aegis] {d.message or d.rule}")
    if denied:
        print(f"aegis: {len(denied)} file(s) violate policy ({len(files)} changed)", file=sys.stderr)
        return 1
    print(f"aegis: {len(files)} changed file(s) OK")
    return 0


# ---------------------------------------------------------------- policy distribution
def _cmd_pull(args) -> int:
    from . import distribution
    dest = args.dest or str(config.policy_dir())
    n = distribution.pull_policy(args.source, dest)
    print(f"aegis: pulled {n} policy file(s) into {dest}")
    return 0


def _cmd_adapters(args) -> int:
    print("available runtime adapters: " + ", ".join(adapters.available()))
    return 0


# ---------------------------------------------------------------- identity / honeypot
def _cmd_issue(args) -> int:
    from . import identity
    caps = [c.strip() for c in (args.caps or "").split(",") if c.strip()]
    tok = identity.issue(args.agent, role=args.role, project=args.project, caps=caps or None)
    if not tok:
        print("aegis: could not issue token (is 'cryptography' installed?)", file=sys.stderr)
        return 1
    print(tok)
    return 0


def _cmd_attest(args) -> int:
    from . import attest
    raw = args.json or (sys.stdin.read() if not sys.stdin.isatty() else "")
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        payload = {}
    print(json.dumps(attest.attest(payload, source=os.environ.get("AEGIS_SESSION_ID"))))
    return 0


def _cmd_detections(args) -> int:
    from . import attest
    rows = attest.recent_detections(args.limit)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print("aegis: no rogue-agent detections")
    for r in rows:
        print(f"[{r.get('ts')}] {r.get('class')} src={r.get('source')} {r.get('declared')}")
    return 0


def _cmd_who(args) -> int:
    from .accountability import load_dir, who
    recs = load_dir(args.audit or str(config.audit_path()))
    hits = who(recs, tool=args.tool, path=args.path)
    if args.json:
        print(json.dumps(hits, indent=2, default=str))
        return 0
    if not hits:
        print("aegis: no matching audit rows")
    for h in hits:
        print(f"[{h['ts']}] {h['identity']} session={h['session']} "
              f"{h['tool']} -> {h['decision']}")
    return 0


# ---------------------------------------------------------------- arg parsing
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aegis",
        description="Hooks-based enforcement + accountability for AI agents")
    sub = p.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("hook", help="evaluate a hook event from stdin (called by the runtime)")
    h.add_argument("event", nargs="?", help="hook event name, e.g. PreToolUse")
    h.add_argument("--runtime", help="runtime adapter (default: claude-code; see `aegis adapters`)")
    h.set_defaults(func=_cmd_hook)

    ins = sub.add_parser("install", help="install Aegis hooks into a Claude Code settings.json (merge)")
    ins.add_argument("--global", dest="glob", action="store_true",
                     help="write ~/.claude/settings.json")
    ins.add_argument("--project", help="write <project>/.claude/settings.json")
    ins.add_argument("--command", help="hook command to write (default: 'aegis hook'; "
                                       "use an absolute path for venv/pipx installs)")
    ins.set_defaults(func=_cmd_install)

    un = sub.add_parser("uninstall", help="remove Aegis hooks from a settings.json")
    un.add_argument("--global", dest="glob", action="store_true")
    un.add_argument("--project")
    un.set_defaults(func=_cmd_uninstall)

    val = sub.add_parser("validate", help="validate policy YAML files")
    val.add_argument("-d", "--dir", help="policy dir or file (default: resolved policy dir)")
    val.set_defaults(func=_cmd_validate)

    rep = sub.add_parser("report", help="accountability report (rap sheet) from the audit log")
    rep.add_argument("--audit", help="audit JSONL path (default: resolved audit path)")
    rep.add_argument("--json", action="store_true", help="emit JSON")
    rep.set_defaults(func=_cmd_report)

    gh = sub.add_parser("git-hook", help="evaluate a git op (called by pre-commit/pre-push)")
    gh.add_argument("op", choices=["commit", "push"])
    gh.add_argument("--repo", help="repo path (default: .)")
    gh.set_defaults(func=_cmd_git_hook)

    ig = sub.add_parser("install-git", help="install git pre-commit/pre-push hooks (merge)")
    ig.add_argument("--repo", help="repo path (default: .)")
    ig.add_argument("--command", help="how the hook invokes aegis (default: resolved abs path)")
    ig.set_defaults(func=_cmd_install_git)

    ci = sub.add_parser("ci", help="evaluate changed files vs a base ref (for CI)")
    ci.add_argument("--repo", help="repo path (default: .)")
    ci.add_argument("--base", help="base ref to diff against (default: origin/main)")
    ci.set_defaults(func=_cmd_ci)

    pull = sub.add_parser("pull", help="pull org policy from a dir/file/URL into the policy dir")
    pull.add_argument("source", help="source dir, file, or http(s) URL")
    pull.add_argument("--dest", help="destination policy dir (default: resolved policy dir)")
    pull.set_defaults(func=_cmd_pull)

    ad = sub.add_parser("adapters", help="list available runtime adapters")
    ad.set_defaults(func=_cmd_adapters)

    iss = sub.add_parser("issue", help="issue a signed agent identity token")
    iss.add_argument("agent")
    iss.add_argument("--role")
    iss.add_argument("--project")
    iss.add_argument("--caps", help="comma-separated capabilities/roles")
    iss.set_defaults(func=_cmd_issue)

    att = sub.add_parser("attest", help="submit an agent attestation (honeypot endpoint)")
    att.add_argument("--json", help="attestation JSON (else read stdin)")
    att.set_defaults(func=_cmd_attest)

    det = sub.add_parser("detections", help="list caught rogue-agent detections")
    det.add_argument("--limit", type=int, default=50)
    det.add_argument("--json", action="store_true")
    det.set_defaults(func=_cmd_detections)

    wh = sub.add_parser("who", help="blame: which identities/sessions touched a tool/path")
    wh.add_argument("--tool")
    wh.add_argument("--path")
    wh.add_argument("--audit")
    wh.add_argument("--json", action="store_true")
    wh.set_defaults(func=_cmd_who)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
