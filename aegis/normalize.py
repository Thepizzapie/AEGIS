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

_LINE_CONT_RE = re.compile(r"\\\s*\r?\n")  # bash/PowerShell backslash-newline continuation
# A '$' immediately before a quote is bash ANSI-C/locale quoting ($'...'/$"...")
# — bash expands it to the SAME literal text a plain '...'/"..." would, so
# stripping the '$' too (not just the quote char below) makes `/dev/$'tcp'/...`
# normalize identically to `/dev/tcp/...`. Found by QA (round 7) on the
# cloud-metadata guard: `echo ... > /dev/$'tcp'/169.254.169.254/80` opens the
# same real socket as the unquoted form and slipped past every pattern in this
# file that matches on a literal substring, since none of them ever saw a
# contiguous "tcp"/".ssh"/"aegis"/etc. once the '$' broke the adjacency.
_ANSIC_QUOTE_RE = re.compile(r"\$(?=['\"])")
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
    cmd = _LINE_CONT_RE.sub(" ", cmd)  # join a continued line before any pattern scans it
    stripped = _QUOTE_SPLIT_RE.sub("", _ANSIC_QUOTE_RE.sub("", cmd))
    parts = [cmd, stripped]  # raw + token-split-stripped (quotes, and $'...'/$"..." ANSI-C quoting)
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
