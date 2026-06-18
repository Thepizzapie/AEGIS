"""AEGI-4: accountability views over the audit stream."""
from aegis.events import Event, HookEvent
from aegis.policy import Decision, Action
from aegis.audit import write_event
from aegis.accountability import load_records, summary, denials, by_session, report


def _seed(path):
    def ev(tool, sid, agent=None):
        return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, session_id=sid, agent=agent)
    write_event(ev("Bash", "s1", "claude"), Decision(Action.DENY, "no-shell", "x"), str(path))
    write_event(ev("Read", "s1", "claude"), Decision(Action.ALLOW), str(path))
    write_event(ev("Bash", "s2"), Decision(Action.DENY, "no-shell"), str(path))
    write_event(ev("Write", "s2"), Decision(Action.ASK, "confirm"), str(path))


def test_summary_counts(tmp_path):
    p = tmp_path / "audit.jsonl"
    _seed(p)
    s = summary(load_records(p))
    assert s["total"] == 4
    assert s["denied"] == 2
    assert s["by_decision"]["deny"] == 2
    assert s["by_decision"]["allow"] == 1
    assert s["by_decision"]["ask"] == 1
    assert ("Bash", 2) in s["top_tools"]


def test_denials_only(tmp_path):
    p = tmp_path / "audit.jsonl"
    _seed(p)
    d = denials(load_records(p))
    assert len(d) == 2 and all(x["decision"] == "deny" for x in d)


def test_by_session(tmp_path):
    p = tmp_path / "audit.jsonl"
    _seed(p)
    bs = by_session(load_records(p))
    assert bs["s1"]["total"] == 2 and bs["s1"]["agent"] == "claude"
    assert bs["s2"]["total"] == 2
    assert bs["s2"]["deny"] == 1 and bs["s2"]["ask"] == 1


def test_report_shape(tmp_path):
    p = tmp_path / "audit.jsonl"
    _seed(p)
    rep = report(p)
    assert {"summary", "denials", "sessions", "identities", "verdicts"} <= set(rep)
    assert rep["summary"]["total"] == 4


def test_load_records_missing_file(tmp_path):
    assert load_records(tmp_path / "nope.jsonl") == []
