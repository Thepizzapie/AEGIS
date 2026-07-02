"""Accountability views over the audit stream (AEGI-4).

Reads the JSONL audit log the hooks write and derives the "rap sheet": who /
which session did what, what was blocked, and the counts. This is the read-side
mirror of enforcement — the engine writes decisions, this reads them back as
judgment.

Git correlation (blame -> commit -> ticket, and did-it-do-the-task verdicts)
layers on top of this same stream and is tracked as a follow-on; the audit
record already carries identity / session / agent / cwd to support it.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path


def load_records(path) -> list:
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def summary(records) -> dict:
    by_decision = Counter(r.get("decision") for r in records)
    by_action = Counter(r.get("action") for r in records)
    by_tool = Counter(r.get("tool") for r in records if r.get("tool"))
    usage: dict = {}
    for r in records:
        _add_usage(usage, r.get("usage"))
    out = {
        "total": len(records),
        "denied": by_decision.get("deny", 0),
        "by_decision": dict(by_decision),
        "by_action": dict(by_action),
        "top_tools": by_tool.most_common(10),
    }
    if usage:
        out["usage"] = usage
    return out


def denials(records) -> list:
    return [r for r in records if r.get("decision") == "deny"]


def _add_usage(accum, usage):
    """Merge a single audit record's ``usage`` dict into *accum* (running sums).
    Non-numeric fields (e.g. ``model``) are kept as last-seen."""
    if not usage:
        return
    for k, v in usage.items():
        if isinstance(v, (int, float)):
            accum[k] = accum.get(k, 0) + v
        else:
            accum[k] = v  # last-seen (e.g. model name)


def by_session(records) -> dict:
    sessions: dict = defaultdict(
        lambda: {"total": 0, "allow": 0, "deny": 0, "ask": 0,
                 "failures": 0, "subagent_starts": 0, "subagent_stops": 0,
                 "agent": None, "tools": Counter(), "usage": {}})
    for r in records:
        sid = r.get("session_id") or "(none)"
        s = sessions[sid]
        s["total"] += 1
        dec = r.get("decision", "allow")
        s[dec] = s.get(dec, 0) + 1
        ev = r.get("event")
        if ev == "PostToolUseFailure":
            s["failures"] += 1
        elif ev == "SubagentStart":
            s["subagent_starts"] += 1
        elif ev == "SubagentStop":
            s["subagent_stops"] += 1
        if r.get("agent"):
            s["agent"] = r["agent"]
        if r.get("tool"):
            s["tools"][r["tool"]] += 1
        _add_usage(s["usage"], r.get("usage"))
    out = {}
    for sid, s in sessions.items():
        s = dict(s)
        s["tools"] = s["tools"].most_common(5)
        out[sid] = s
    return out


def load_dir(path) -> list:
    """Load a single audit file OR aggregate every ``*.jsonl`` under a directory
    (org-wide aggregation across developers / agents / machines)."""
    p = Path(path)
    if p.is_dir():
        recs = []
        for f in sorted(p.glob("*.jsonl")):
            recs.extend(load_records(f))
        return recs
    return load_records(p)


def by_identity(records) -> dict:
    """Roll up by caller identity (verified agent / identity / agent name)."""
    out: dict = defaultdict(
        lambda: {"total": 0, "allow": 0, "deny": 0, "ask": 0,
                 "sessions": set(), "usage": {}})
    for r in records:
        ident = r.get("identity") or r.get("agent") or "(unknown)"
        o = out[ident]
        o["total"] += 1
        dec = r.get("decision", "allow")
        o[dec] = o.get(dec, 0) + 1
        if r.get("session_id"):
            o["sessions"].add(r["session_id"])
        _add_usage(o["usage"], r.get("usage"))
    res = {}
    for k, v in out.items():
        v = dict(v)
        v["sessions"] = sorted(v["sessions"])
        res[k] = v
    return res


def verdict(stats) -> dict:
    """A judgment over a session/identity rollup: flags + ok. The read-side of
    enforcement (the rap-sheet verdict)."""
    flags = []
    deny = stats.get("deny", 0)
    total = stats.get("total", 0) or 1
    if deny >= 3:
        flags.append("many-denials")
    if deny and deny / total > 0.5:
        flags.append("mostly-denied")
    # Reliability flags: a session drowning in tool failures is thrashing (or
    # probing); sub-agents that started but never stopped are unreconciled work
    # whose outcome/usage was never accounted for.
    failures = stats.get("failures", 0)
    if failures >= 3 and failures / total > 0.25:
        flags.append("high-failure-rate")
    if stats.get("subagent_starts", 0) > stats.get("subagent_stops", 0):
        flags.append("orphaned-subagent")
    return {"ok": not flags, "flags": flags}


def who(records, *, tool=None, path=None) -> list:
    """Blame: which identities/sessions touched a tool or a path. Returns matching
    audit rows (newest first)."""
    hits = []
    for r in records:
        if tool and r.get("tool") != tool:
            continue
        if path:
            args = r.get("args") or {}
            target = str(args.get("file_path") or args.get("path") or args.get("command") or "")
            if path not in target:
                continue
        hits.append({"identity": r.get("identity") or r.get("agent"),
                     "session": r.get("session_id"), "tool": r.get("tool"),
                     "decision": r.get("decision"), "ts": r.get("ts")})
    return list(reversed(hits))


def report(path) -> dict:
    """The full rap sheet for an audit log (file) or directory (org-wide): summary +
    denial trail + per-session + per-identity + per-session verdicts."""
    recs = load_dir(path)
    sessions = by_session(recs)
    return {"summary": summary(recs), "denials": denials(recs),
            "sessions": sessions, "identities": by_identity(recs),
            "verdicts": {sid: verdict(s) for sid, s in sessions.items()}}
