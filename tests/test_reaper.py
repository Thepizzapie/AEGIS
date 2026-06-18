"""Session reaper — terminate a rogue agent session (fail-safe)."""
from aegis import reaper


def test_kill_session_issues_kill(monkeypatch):
    called = {}
    monkeypatch.setattr(reaper.subprocess, "run",
                        lambda *a, **k: called.setdefault("run", a))
    monkeypatch.setattr(reaper.os, "kill", lambda *a, **k: called.setdefault("kill", a),
                        raising=False)
    monkeypatch.setattr(reaper.os, "killpg", lambda *a, **k: called.setdefault("killpg", a),
                        raising=False)  # POSIX-only; create on Windows for the test
    monkeypatch.setattr(reaper.os, "getpgid", lambda pid: pid, raising=False)
    assert reaper.kill_session(12345) is True
    assert called  # some kill path was taken


def test_kill_session_rejects_bad_pid():
    assert reaper.kill_session(0) is False
    assert reaper.kill_session(-1) is False


def test_kill_session_failsafe(monkeypatch):
    def boom(*a, **k):
        raise OSError("nope")
    monkeypatch.setattr(reaper.subprocess, "run", boom)
    monkeypatch.setattr(reaper.os, "kill", boom, raising=False)
    monkeypatch.setattr(reaper.os, "killpg", boom, raising=False)
    assert reaper.kill_session(12345) is False  # never raises
