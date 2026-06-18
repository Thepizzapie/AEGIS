"""Cryptographic agent identity (Ed25519 issue/verify)."""
from aegis import identity


def test_issue_verify_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    tok = identity.issue("scout", role="reader", caps=["read"])
    assert tok and "." in tok
    claims = identity.verify(tok)
    assert claims["agent"] == "scout" and claims["role"] == "reader"
    assert "read" in claims["caps"]


def test_verify_rejects_tampered(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    tok = identity.issue("scout")
    payload, sig = tok.split(".", 1)
    forged = payload + "." + ("AAAA" + sig[4:])  # corrupt the signature
    assert identity.verify(forged) is None
    assert identity.verify("garbage") is None
    assert identity.verify("") is None


def test_verify_rejects_expired(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    tok = identity.issue("scout", ttl_seconds=10, now=1000)
    assert identity.verify(tok, now=1005) is not None
    assert identity.verify(tok, now=2000) is None


def test_current_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    monkeypatch.setenv("AEGIS_AGENT_TOKEN", identity.issue("scout"))
    assert identity.current()["agent"] == "scout"
    monkeypatch.setenv("AEGIS_AGENT_TOKEN", "garbage")
    assert identity.current() is None


def test_resolve_identity_prefers_verified_token(tmp_path, monkeypatch):
    # an env role claim must NOT override the signed token's claims (unforgeable RBAC)
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    monkeypatch.setenv("AEGIS_ROLES", "spoofed-admin")
    monkeypatch.setenv("AEGIS_AGENT_TOKEN", identity.issue("scout", role="reader", caps=["read"]))
    ident, roles = identity.resolve_identity()
    assert ident == "scout"
    assert "reader" in roles and "spoofed-admin" not in roles


def test_enforce_flag(monkeypatch):
    monkeypatch.setenv("AEGIS_IDENTITY_ENFORCE", "1")
    assert identity.enforce_enabled()
    monkeypatch.setenv("AEGIS_IDENTITY_ENFORCE", "0")
    assert not identity.enforce_enabled()
