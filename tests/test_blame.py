"""Accountability / blame over the audit stream."""
import json

from aegis.accountability import by_identity, load_dir, report, verdict, who


def _seed(tmp_path):
    p = tmp_path / "a.jsonl"
    rows = [
        {"decision": "deny", "tool": "Bash", "action": "shell", "identity": "scout",
         "session_id": "s1", "args": {"command": "rm -rf /"}},
        {"decision": "deny", "tool": "Bash", "action": "shell", "identity": "scout",
         "session_id": "s1", "args": {"command": "x"}},
        {"decision": "deny", "tool": "Bash", "action": "shell", "identity": "scout",
         "session_id": "s1", "args": {"command": "y"}},
        {"decision": "allow", "tool": "Read", "action": "read", "identity": "alice",
         "session_id": "s2", "args": {"file_path": "/etc/hosts"}},
    ]
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return p


def test_by_identity(tmp_path):
    bi = by_identity(load_dir(_seed(tmp_path)))
    assert bi["scout"]["total"] == 3 and bi["scout"]["deny"] == 3
    assert "s1" in bi["scout"]["sessions"]
    assert bi["alice"]["allow"] == 1


def test_verdict_flags():
    assert verdict({"total": 3, "deny": 3})["flags"]      # many denials -> flagged
    assert verdict({"total": 5, "deny": 0})["ok"]          # clean -> ok
    assert "mostly-denied" in verdict({"total": 2, "deny": 2})["flags"]


def test_who_by_tool(tmp_path):
    hits = who(load_dir(_seed(tmp_path)), tool="Read")
    assert len(hits) == 1 and hits[0]["identity"] == "alice"


def test_who_by_path(tmp_path):
    hits = who(load_dir(_seed(tmp_path)), path="/etc/hosts")
    assert len(hits) == 1 and hits[0]["session"] == "s2"


def test_report_includes_identities_and_verdicts(tmp_path):
    rep = report(_seed(tmp_path))
    assert "identities" in rep and "verdicts" in rep
    assert not rep["verdicts"]["s1"]["ok"]   # 3 denials -> flagged
