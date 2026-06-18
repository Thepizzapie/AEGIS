"""Rogue-session gate through the engine: MONITOR vs ENFORCE."""
from aegis import attest, identity, reaper
from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Policy


def _start():
    return Event.make(HookEvent.SESSION_START)


def test_no_agent_claim_is_ok(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)
    assert not evaluate(_start(), Policy()).blocked


def test_monitor_logs_but_allows(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    monkeypatch.setenv("AEGIS_AGENT_NAME", "rogue")
    monkeypatch.delenv("AEGIS_AGENT_TOKEN", raising=False)
    monkeypatch.delenv("AEGIS_IDENTITY_ENFORCE", raising=False)
    killed = []
    monkeypatch.setattr(reaper, "kill_session", lambda *a, **k: killed.append(True))
    d = evaluate(_start(), Policy())
    assert not d.blocked          # MONITOR: allowed
    assert not killed             # not reaped
    assert attest.recent_detections()[0]["class"] == attest.UNREGISTERED  # but logged


def test_enforce_reaps_rogue(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    monkeypatch.setenv("AEGIS_AGENT_NAME", "rogue")
    monkeypatch.delenv("AEGIS_AGENT_TOKEN", raising=False)
    monkeypatch.setenv("AEGIS_IDENTITY_ENFORCE", "1")
    killed = []
    monkeypatch.setattr(reaper, "kill_session", lambda *a, **k: (killed.append(True), True)[1])
    d = evaluate(_start(), Policy())
    assert d.blocked and d.rule == "rogue-agent-reaped"
    assert killed                                  # session reaped
    assert "ATTESTATION REQUIRED" in d.message     # honeypot challenge surfaced


def test_valid_token_passes_even_under_enforce(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    monkeypatch.setenv("AEGIS_AGENT_NAME", "scout")
    monkeypatch.setenv("AEGIS_IDENTITY_ENFORCE", "1")
    monkeypatch.setenv("AEGIS_AGENT_TOKEN", identity.issue("scout"))
    killed = []
    monkeypatch.setattr(reaper, "kill_session", lambda *a, **k: killed.append(True))
    assert not evaluate(_start(), Policy()).blocked
    assert not killed
