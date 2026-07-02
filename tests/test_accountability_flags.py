"""Reliability-flag tests (accountability.by_session counters + verdict flags).

The read-side additions: sessions that thrash on failing tools are flagged
``high-failure-rate``; sub-agents that started but never stopped are flagged
``orphaned-subagent``.
"""
from aegis import accountability


def _rec(event="PreToolUse", session="s1", decision="allow", **kw):
    r = {"session_id": session, "event": event, "decision": decision,
         "tool": "Bash", "action": "shell"}
    r.update(kw)
    return r


def test_by_session_counts_failures_and_subagents():
    recs = [
        _rec(),
        _rec(event="PostToolUseFailure"),
        _rec(event="PostToolUseFailure"),
        _rec(event="SubagentStart"),
        _rec(event="SubagentStop"),
        _rec(event="SubagentStart"),
    ]
    s = accountability.by_session(recs)["s1"]
    assert s["failures"] == 2
    assert s["subagent_starts"] == 2
    assert s["subagent_stops"] == 1


def test_verdict_flags_high_failure_rate():
    stats = {"total": 10, "deny": 0, "failures": 4,
             "subagent_starts": 0, "subagent_stops": 0}
    v = accountability.verdict(stats)
    assert not v["ok"]
    assert "high-failure-rate" in v["flags"]


def test_verdict_tolerates_few_failures_in_a_long_session():
    # 3 failures in 100 events is normal work, not thrash.
    stats = {"total": 100, "deny": 0, "failures": 3,
             "subagent_starts": 0, "subagent_stops": 0}
    assert accountability.verdict(stats)["ok"]


def test_verdict_flags_orphaned_subagent():
    stats = {"total": 5, "deny": 0, "failures": 0,
             "subagent_starts": 2, "subagent_stops": 1}
    v = accountability.verdict(stats)
    assert "orphaned-subagent" in v["flags"]


def test_verdict_ok_when_subagents_reconcile():
    stats = {"total": 5, "deny": 0, "failures": 0,
             "subagent_starts": 2, "subagent_stops": 2}
    assert accountability.verdict(stats)["ok"]


def test_verdict_backward_compatible_with_old_rollups():
    # rollups that predate the counters (no failures/subagent keys) still work.
    assert accountability.verdict({"total": 4, "deny": 0})["ok"]
    v = accountability.verdict({"total": 4, "deny": 3})
    assert "many-denials" in v["flags"]


def test_full_report_carries_the_new_flags(tmp_path):
    import json
    recs = [_rec(event="PostToolUseFailure") for _ in range(4)]
    recs += [_rec() for _ in range(4)]
    p = tmp_path / "audit.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")
    rep = accountability.report(str(p))
    assert "high-failure-rate" in rep["verdicts"]["s1"]["flags"]
