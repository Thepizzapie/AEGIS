"""AEGI-2: minimal audit sink writes one JSONL record per decision."""
import json

from aegis.events import Event, HookEvent
from aegis.policy import Decision, Action
from aegis.audit import write_event


def test_write_event_appends_jsonl(tmp_path):
    path = tmp_path / "logs" / "audit.jsonl"
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Bash",
                    args={"command": "ls"}, session_id="s1")

    write_event(ev, Decision(action=Action.DENY, rule="no-shell", message="x"), str(path))
    assert path.exists()
    rows = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert len(rows) == 1
    assert rows[0]["tool"] == "Bash"
    assert rows[0]["decision"] == "deny"
    assert rows[0]["rule"] == "no-shell"
    assert rows[0]["action"] == "shell"
    assert rows[0]["session_id"] == "s1"

    write_event(ev, Decision(action=Action.ALLOW), str(path))  # appends, not overwrites
    rows = [x for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert len(rows) == 2


def test_audit_record_includes_denial_message(tmp_path):
    """The human-readable denial reason must be in the audit trail — not just
    the rule name. Without this, `aegis report` shows WHAT was denied but not WHY."""
    path = tmp_path / "audit.jsonl"
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Bash",
                    args={"command": "rm -rf /"}, session_id="s2")
    reason = "Recursive force delete is blocked."
    write_event(ev, Decision(action=Action.DENY, rule="destructive-delete",
                             message=reason), str(path))
    row = json.loads(path.read_text(encoding="utf-8").strip())
    assert row["message"] == reason
