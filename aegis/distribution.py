"""Org policy distribution (AEGI-6).

``pull_policy`` copies policy YAML from a source — a local dir/file or an http(s)
URL — into the local policy dir, so a team authors org policy centrally and each
developer / CI pulls it (e.g. on session start). One policy, many machines.
"""
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse


def pull_policy(source, dest) -> int:
    """Copy policy YAML from ``source`` into ``dest``. Returns files written.
    Rejects plain HTTP (policy must be pulled over TLS). Auto-validates the
    pulled files and raises on invalid YAML so bad policy is never silently
    loaded."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    s = str(source)
    if s.startswith("http://"):
        raise ValueError("Refusing to pull policy over plain HTTP — use HTTPS. "
                         "Policy controls what an agent can do; it must not be "
                         "fetched over an unencrypted channel.")
    if s.startswith("https://"):
        import urllib.request
        name = os.path.basename(urlparse(s).path) or "policy.yaml"
        with urllib.request.urlopen(s, timeout=15) as resp:  # noqa: S310
            (dest / name).write_bytes(resp.read())
        _validate_dir(dest)
        return 1
    src = Path(source)
    files = sorted(src.glob("*.y*ml")) if src.is_dir() else [src]
    written = 0
    for f in files:
        (dest / f.name).write_text(Path(f).read_text(encoding="utf-8"), encoding="utf-8")
        written += 1
    if written:
        _validate_dir(dest)
    return written


def _validate_dir(dest):
    """Validate pulled policy so malformed YAML is caught before it's loaded."""
    from .loader import validate_policy
    errors = validate_policy(str(dest))
    if errors:
        raise ValueError(f"Pulled policy is invalid: {'; '.join(errors[:5])}")
