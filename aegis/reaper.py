"""Session reaper — terminate a rogue agent session.

When the attestation gate (aegis.rules.rule_attest_session) catches a rogue session
in ENFORCE mode, it doesn't just deny one tool call — it kills the session. The
hook's parent process IS the agent runtime, so reaping the parent tree ends the
rogue agent.

Windowless + fail-safe: a reap failure never raises into the hook.
"""
from __future__ import annotations

import os
import signal
import subprocess

_CREATE_NO_WINDOW = 0x08000000  # Windows: don't flash a console


def kill_session(pid=None) -> bool:
    """Terminate the agent session — by default the hook's PARENT process tree
    (the agent runtime). Returns True if the kill was issued. Never raises."""
    target = pid if pid is not None else os.getppid()
    if not target or int(target) <= 0:
        return False
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(target)],
                capture_output=True, timeout=10, creationflags=_CREATE_NO_WINDOW)
        else:
            try:
                os.killpg(os.getpgid(target), signal.SIGTERM)
            except Exception:
                os.kill(target, signal.SIGTERM)
        return True
    except Exception:
        return False
