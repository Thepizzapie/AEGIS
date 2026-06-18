"""Token-usage capture + accountability aggregation tests."""
import json
import os
import tempfile

from aegis.audit import write_event, _extract_usage
from aegis.events import Event, HookEvent, ActionClass
from aegis.policy import Action, Decision
from aegis import accountability


def _ev(raw=None, **kw):
    defaults = dict(event=HookEvent.PRE_TOOL_USE, tool="Bash",
                    action=ActionClass.SHELL, args={"command": "ls"},
                    session_id="s1", identity="alice")
    defaults.update(kw)
    ev = Event(**defaults)
    ev.raw = raw or {}
    return ev


# ---- _extract_usage ----------------------------------------------------------

def test_extract_usage_empty():
    assert _extract_usage(_ev()) == {}


def test_extract_usage_top_level():
    raw = {"input_tokens": 100, "output_tokens": 50, "model": "claude-4"}
    assert _extract_usage(_ev(raw=raw)) == {
        "input_tokens": 100, "output_tokens": 50, "model": "claude-4"}


def test_extract_usage_nested():
    raw = {"usage": {"input_tokens": 200, "output_tokens": 80,
                     "cache_read_input_tokens": 10}}
    u = _extract_usage(_ev(raw=raw))
    assert u["input_tokens"] == 200
    assert u["output_tokens"] == 80
    assert u["cache_read_input_tokens"] == 10


def test_extract_usage_in_tool_result():
    raw = {"tool_result": {"usage": {"input_tokens": 50, "output_tokens": 25}}}
    u = _extract_usage(_ev(raw=raw))
    assert u["input_tokens"] == 50
    assert u["output_tokens"] == 25


def test_extract_usage_top_level_takes_precedence_over_nested_result():
    """Top-level wins for a key; nested fills gaps."""
    raw = {"input_tokens": 300,
           "tool_result": {"usage": {"input_tokens": 50, "output_tokens": 25}}}
    u = _extract_usage(_ev(raw=raw))
    assert u["input_tokens"] == 300    # top-level wins
    assert u["output_tokens"] == 25    # filled from nested


def test_extract_usage_ignores_none():
    raw = {"input_tokens": None, "output_tokens": 50}
    u = _extract_usage(_ev(raw=raw))
    assert "input_tokens" not in u
    assert u["output_tokens"] == 50


def test_extract_usage_num_turns_and_cost():
    raw = {"num_turns": 12, "total_cost": 0.0342, "duration_ms": 15000}
    u = _extract_usage(_ev(raw=raw))
    assert u["num_turns"] == 12
    assert u["total_cost"] == 0.0342
    assert u["duration_ms"] == 15000


# ---- audit record includes usage ---------------------------------------------

def test_audit_record_includes_usage():
    ev = _ev(raw={"input_tokens": 100, "output_tokens": 50})
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        path = f.name
    try:
        rec = write_event(ev, Decision(Action.ALLOW), path)
        assert rec["usage"]["input_tokens"] == 100
        assert rec["usage"]["output_tokens"] == 50
        # verify it's in the persisted JSONL
        lines = open(path).readlines()
        persisted = json.loads(lines[-1])
        assert persisted["usage"]["input_tokens"] == 100
    finally:
        os.unlink(path)


def test_audit_record_omits_usage_when_empty():
    ev = _ev(raw={})
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        path = f.name
    try:
        rec = write_event(ev, Decision(Action.ALLOW), path)
        assert "usage" not in rec
    finally:
        os.unlink(path)


# ---- accountability aggregation ----------------------------------------------

def _records_with_usage():
    return [
        {"session_id": "s1", "identity": "alice", "agent": "bot-a",
         "tool": "Bash", "action": "shell", "decision": "allow",
         "usage": {"input_tokens": 100, "output_tokens": 50}},
        {"session_id": "s1", "identity": "alice", "agent": "bot-a",
         "tool": "Read", "action": "read", "decision": "allow",
         "usage": {"input_tokens": 80, "output_tokens": 30}},
        {"session_id": "s2", "identity": "bob", "agent": "bot-b",
         "tool": "Bash", "action": "shell", "decision": "deny",
         "usage": {"input_tokens": 200, "output_tokens": 100,
                   "total_cost": 0.05}},
        # record with no usage (normal)
        {"session_id": "s2", "identity": "bob", "tool": "Read",
         "action": "read", "decision": "allow"},
    ]


def test_summary_usage():
    s = accountability.summary(_records_with_usage())
    assert s["usage"]["input_tokens"] == 380
    assert s["usage"]["output_tokens"] == 180
    assert s["usage"]["total_cost"] == 0.05


def test_summary_no_usage():
    recs = [{"session_id": "s1", "tool": "Bash", "decision": "allow"}]
    s = accountability.summary(recs)
    assert "usage" not in s


def test_by_session_usage():
    sessions = accountability.by_session(_records_with_usage())
    assert sessions["s1"]["usage"]["input_tokens"] == 180
    assert sessions["s1"]["usage"]["output_tokens"] == 80
    assert sessions["s2"]["usage"]["input_tokens"] == 200
    assert sessions["s2"]["usage"]["total_cost"] == 0.05


def test_by_identity_usage():
    idents = accountability.by_identity(_records_with_usage())
    assert idents["alice"]["usage"]["input_tokens"] == 180
    assert idents["bob"]["usage"]["input_tokens"] == 200
    assert idents["bob"]["usage"]["total_cost"] == 0.05


def test_report_includes_usage():
    """Full report round-trip with usage data."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        for r in _records_with_usage():
            f.write(json.dumps(r) + "\n")
        path = f.name
    try:
        rep = accountability.report(path)
        assert rep["summary"]["usage"]["input_tokens"] == 380
        assert rep["sessions"]["s1"]["usage"]["input_tokens"] == 180
        assert rep["identities"]["bob"]["usage"]["total_cost"] == 0.05
    finally:
        os.unlink(path)
