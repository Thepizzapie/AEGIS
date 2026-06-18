"""Config resolution (AEGI-2): where policy + audit live.

Resolution order is env var -> project-local (./.aegis) -> user home (~/.aegis),
so a repo can ship its own guardrails and a user/org can set global defaults.
"""
from __future__ import annotations

import os
from pathlib import Path


def aegis_home() -> Path:
    return Path(os.environ.get("AEGIS_HOME", str(Path.home() / ".aegis")))


def policy_dir() -> Path:
    env = os.environ.get("AEGIS_POLICIES")
    if env:
        return Path(env)
    local = Path.cwd() / ".aegis" / "policies"
    if local.exists():
        return local
    return aegis_home() / "policies"


def audit_path() -> Path:
    env = os.environ.get("AEGIS_AUDIT")
    if env:
        return Path(env)
    return aegis_home() / "audit.jsonl"
