"""Cryptographically-verifiable agent identity.

An agent's identity is normally an env string (AEGIS_AGENT_NAME) — forgeable: any
process sets it and *is* that agent. This issues each agent a SIGNED credential
(Ed25519) bound to {agent, role, session, project, caps, exp}. The hooks verify it
with the PUBLIC key — an agent can't forge one without the issuer private key.

It also resolves the (identity, roles) used for RBAC, preferring a VERIFIED token's
claims (unforgeable) over the env fallback.

Fail-safe throughout: verify() returns None (deny) on anything unexpected.
"""
from __future__ import annotations

import base64
import getpass
import json
import os
import time
from pathlib import Path

_ALG = "ed25519"
_DEFAULT_TTL = 12 * 3600  # 12h


def _keydir() -> Path:
    base = os.environ.get("AEGIS_HOME") or os.path.join(
        os.environ.get("APPDATA") or os.path.expanduser("~"), ".aegis")
    d = Path(base) / "identity"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _priv_path() -> Path:
    return _keydir() / "issuer_ed25519.key"


def _load_or_create():
    """(private_key, public_key_raw_bytes). Generates + persists the issuer keypair
    once. Hardening (v2) = move the private key to a broker process only."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    pk = _priv_path()
    if pk.exists():
        priv = serialization.load_pem_private_key(pk.read_bytes(), password=None)
    else:
        priv = Ed25519PrivateKey.generate()
        pk.write_bytes(priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        try:
            os.chmod(pk, 0o600)
        except OSError:
            pass
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pub_raw


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue(agent, *, role=None, session=None, project=None, caps=None,
          ttl_seconds=_DEFAULT_TTL, now=None):
    """Issue a signed identity token '<b64url(claims)>.<b64url(sig)>'. Fail-safe -> None."""
    try:
        priv, _ = _load_or_create()
        iat = int(now if now is not None else time.time())
        claims = {"agent": agent, "role": role, "session": session,
                  "project": project, "caps": list(caps or []), "iat": iat,
                  "exp": iat + int(ttl_seconds), "alg": _ALG}
        payload = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()
        return _b64u(payload) + "." + _b64u(priv.sign(payload))
    except Exception:
        return None


def verify(token, *, now=None):
    """Verify signature + expiry against the issuer public key. Returns claims, or
    None if missing / forged / tampered / expired. Fail-safe -> None (deny)."""
    if not token or "." not in token:
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        _, pub_raw = _load_or_create()
        pub = Ed25519PublicKey.from_public_bytes(pub_raw)
        p_b64, s_b64 = token.split(".", 1)
        payload = _b64u_dec(p_b64)
        pub.verify(_b64u_dec(s_b64), payload)  # raises on tamper
        claims = json.loads(payload)
        if int(claims.get("exp", 0)) < int(now if now is not None else time.time()):
            return None  # expired
        return claims
    except Exception:
        return None


def current():
    """Verified identity of THIS process (AEGIS_AGENT_TOKEN), or None. A process that
    merely SETS AEGIS_AGENT_NAME without a valid token has NO verified identity."""
    return verify(os.environ.get("AEGIS_AGENT_TOKEN") or "")


def enforce_enabled() -> bool:
    """AEGIS_IDENTITY_ENFORCE truthy -> the gate DENIES + reaps; else MONITOR
    (record + allow), so token issuance can roll out before the gate hardens."""
    return (os.environ.get("AEGIS_IDENTITY_ENFORCE") or "").strip().lower() \
        in ("1", "true", "yes", "on")


def resolve_identity(payload=None, label=None):
    """Return (identity, roles) for RBAC. Precedence: a VERIFIED token's claims
    (unforgeable) -> env (AEGIS_IDENTITY / AEGIS_AGENT_NAME / AEGIS_ROLES) -> payload -> agent_label -> OS user."""
    payload = payload or {}
    claims = current()
    if claims:
        roles = list(claims.get("caps") or [])
        if claims.get("role"):
            roles = [claims["role"], *roles]
        return claims.get("agent") or "agent", roles
    identity = (os.environ.get("AEGIS_IDENTITY")
                or os.environ.get("AEGIS_AGENT_NAME")
                or payload.get("identity") or label or _os_user())
    roles_raw = os.environ.get("AEGIS_ROLES")
    roles = ([r.strip() for r in roles_raw.split(",") if r.strip()]
             if roles_raw else list(payload.get("roles") or []))
    return identity, roles


def _os_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"
