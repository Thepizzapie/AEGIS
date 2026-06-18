"""De-obfuscation surface for shell-command matching (AEGI-11).

A denylist that scans only the raw command loses to obfuscation: an agent wraps
the command in another interpreter (`bash -c "…"`), encodes it (PowerShell
`-EncodedCommand`), splits tokens (`r"m" -rf`), or pipes base64 into a shell.

``scan_surface`` returns the command PLUS its de-obfuscated / decoded / inner
forms, so the existing pattern guards see through the disguise. Additive and
fail-safe: decoding garbage just adds garbage (no false positive), and any error
is swallowed (the raw command is still scanned).
"""
from __future__ import annotations

import base64
import re

_MAX = 20000  # never spend unbounded effort on a giant blob

_QUOTE_SPLIT_RE = re.compile(r"['\"`^]")
_PS_ENC_RE = re.compile(r"-(?:e|ec|enc|encodedcommand)\b\s+([A-Za-z0-9+/=]{12,})", re.IGNORECASE)
_B64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=]{20,}")
_B64_DECODE_HINT = re.compile(r"base64\s+(?:-d|--decode)|frombase64string", re.IGNORECASE)

_INTERP_RES = (
    re.compile(r"\b(?:bash|sh|zsh|dash)\b\s+-c\s+(['\"])(.+?)\1", re.IGNORECASE | re.DOTALL),
    re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b[^|;&\n]*?-(?:c|command)\s+(['\"])(.+?)\1",
               re.IGNORECASE | re.DOTALL),
    re.compile(r"\bcmd(?:\.exe)?\b\s+/c\s+(.+)$", re.IGNORECASE),
    re.compile(r"\b(?:python|python3|node)\b\s+-[ce]\s+(['\"])(.+?)\1",
               re.IGNORECASE | re.DOTALL),
)


def _b64(s, utf16=False):
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4))
        return raw.decode("utf-16-le" if utf16 else "utf-8", "ignore")
    except Exception:
        return ""


def scan_surface(cmd, _depth=0) -> str:
    """The command plus its de-obfuscated forms, for pattern matching."""
    if not cmd or _depth > 3:
        return cmd or ""
    cmd = str(cmd)[:_MAX]
    parts = [cmd, _QUOTE_SPLIT_RE.sub("", cmd)]  # raw + token-split-stripped
    for m in _PS_ENC_RE.finditer(cmd):           # PowerShell encoded command
        dec = _b64(m.group(1), utf16=True) or _b64(m.group(1))
        if dec:
            parts.append(scan_surface(dec, _depth + 1))
    if _B64_DECODE_HINT.search(cmd):             # base64 -d / FromBase64String pipelines
        for tok in _B64_TOKEN_RE.findall(cmd):
            dec = _b64(tok)
            if dec:
                parts.append(scan_surface(dec, _depth + 1))
    for rx in _INTERP_RES:                        # inner interpreter code
        for m in rx.finditer(cmd):
            inner = m.group(m.lastindex)
            if inner:
                parts.append(scan_surface(inner, _depth + 1))
    return " ".join(p for p in parts if p)
