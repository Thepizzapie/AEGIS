"""Attestation classification + honeypot + detection log."""
from aegis import attest, identity


def test_classify_noise():
    assert attest.classify({})["class"] == attest.NOISE


def test_classify_unregistered():
    assert attest.classify({"agent": "rogue", "model": "x"})["class"] == attest.UNREGISTERED


def test_classify_forged(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    assert attest.classify({"agent": "rogue", "token": "bogus.token"})["class"] == attest.FORGED


def test_classify_verified(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    tok = identity.issue("scout")
    v = attest.classify({"agent": "scout", "token": tok})
    assert v["class"] == attest.VERIFIED and v["identity"]["agent"] == "scout"


def test_challenge_is_honeypot_bait():
    assert "ATTESTATION REQUIRED" in attest.ATTEST_CHALLENGE
    assert "aegis attest" in attest.ATTEST_CHALLENGE


def test_record_logs_and_blocklists(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    attest.record(attest.classify({"agent": "rogue"}), source="sess-1")
    assert attest.is_blocked("sess-1")
    rows = attest.recent_detections()
    assert rows and rows[0]["class"] == attest.UNREGISTERED and rows[0]["source"] == "sess-1"


def test_attest_entrypoint(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    out = attest.attest({"agent": "rogue", "model": "gpt"}, source="x")
    assert out["status"] == attest.UNREGISTERED
