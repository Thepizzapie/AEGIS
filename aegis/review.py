"""Forced install review — the read-coverage ledger (AEGI-review).

The 0DIN "clean repo" attack rides an *unread* install: the agent runs
``pip install -r requirements.txt`` straight from setup notes, never looking at
what it pulls in, and a malicious package three indirection steps later spawns a
reverse shell. This module is the spine of the defense — it records which files
have been **fully read** in a session (full reads, not skims) so the install
guard (``rules.rule_install_review``) can refuse to install a manifest the agent
hasn't actually looked at, then force a human ask with a real digest.

Two pieces:

- **Coverage ledger** — every ``Read`` (observed at PostToolUse) is recorded as a
  covered line interval, keyed by the file's content hash. ``is_fully_read``
  unions the intervals and checks they span the whole file *at its current hash*
  (so editing a file after reading it re-arms the gate). A ``Read`` with a
  ``limit`` / non-zero ``offset`` that stops short, or a ``grep``/``head`` shell
  peek, simply never produces full coverage — that is the "not a skim" property.

- **Manifest resolution + digest** — from an install command we resolve the
  manifest set that determines what gets installed (``requirements.txt``,
  ``package.json`` + lock, ``pyproject.toml``/``poetry.lock``, …) and summarize it
  (dep count, unpinned specs, URL/VCS/local deps, install-time scripts) so the
  human ask is fact-based, not blind.

Everything here is best-effort and fail-safe: any error degrades to "not read"
(the gate stays closed) for coverage, and to an empty/partial digest for the
summary — it never raises into the hook.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import time
from typing import List, Optional

from . import config
from .events import ActionClass, Event, HookEvent

_MAX_BYTES = 5_000_000  # don't hash/scan absurdly large files


# ---------------------------------------------------------------- ledger storage
def _review_dir():
    d = config.aegis_home() / "review"
    return d


def _ledger_path(session: Optional[str]):
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", str(session or "nosession"))[:120]
    return _review_dir() / f"{safe}.jsonl"


def _abspath(path: str, cwd: Optional[str]) -> str:
    base = cwd or os.getcwd()
    return os.path.abspath(os.path.join(base, os.path.expanduser(str(path))))


def _sha256(path: str) -> Optional[str]:
    try:
        if os.path.getsize(path) > _MAX_BYTES:
            return None
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except Exception:
        return None


def _line_count(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return sum(1 for _ in fh)
    except Exception:
        return 0


def _append(session: Optional[str], record: dict) -> None:
    try:
        d = _review_dir()
        d.mkdir(parents=True, exist_ok=True)
        with open(_ledger_path(session), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception:
        pass  # the ledger is advisory; a write failure must never block the agent


def _read_records(session: Optional[str]) -> List[dict]:
    try:
        p = _ledger_path(session)
        if not p.exists():
            return []
        out = []
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
        return out
    except Exception:
        return []


# ---------------------------------------------------------------- read capture
def _extract_text(resp) -> Optional[str]:
    """Pull the textual content out of a runtime's tool_response, however it's
    shaped (string, {file:{content,...}}, {text}, {content}, list of blocks)."""
    if resp is None:
        return None
    if isinstance(resp, str):
        return resp
    if isinstance(resp, list):
        parts = [_extract_text(x) for x in resp]
        return "\n".join(p for p in parts if p) or None
    if isinstance(resp, dict):
        f = resp.get("file")
        if isinstance(f, dict) and f.get("content") is not None:
            return str(f.get("content"))
        for k in ("content", "text", "output", "stdout", "result"):
            v = resp.get(k)
            if isinstance(v, str):
                return v
        try:
            return json.dumps(resp)
        except Exception:
            return None
    return str(resp)


def record_read(session: Optional[str], file_path: str, args: dict,
                content: Optional[str], cwd: Optional[str]) -> None:
    """Record the line interval a Read covered, keyed by the file's current hash.

    Coverage is derived, in order of reliability: from the returned content's line
    count (most reliable — it's exactly what entered the model's context); else
    from an explicit ``limit``; else assumed-to-EOF for a bare full read.
    """
    ap = _abspath(file_path, cwd)
    sha = _sha256(ap)
    if not sha:
        return
    total = _line_count(ap)
    args = args or {}
    try:
        offset = int(args.get("offset") or 1)
    except (TypeError, ValueError):
        offset = 1
    if offset < 1:
        offset = 1

    n = None
    if content is not None:
        n = len(str(content).splitlines())
        if n == 0 and str(content):
            n = 1
    if n is not None:
        end = offset + n - 1
    elif args.get("limit"):
        try:
            end = offset + int(args["limit"]) - 1
        except (TypeError, ValueError):
            end = total
    else:
        end = total  # bare full read -> assume to EOF
    if total:
        end = min(end, total)
    if end < offset:
        end = offset
    _append(session, {"path": ap, "sha": sha, "start": offset, "end": end,
                      "ts": _now()})


def _now() -> str:
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return ""


def observe(event: Event) -> None:
    """PostToolUse side effect: if this was a file Read, record its coverage. No-op
    for anything else. Called from the CLI hook path."""
    if event.event != HookEvent.POST_TOOL_USE:
        return
    if event.action != ActionClass.READ:
        return
    if (event.tool or "").strip().lower() not in ("read", "notebookread"):
        return
    a = event.args or {}
    path = a.get("file_path") or a.get("path") or a.get("notebook_path")
    if not path:
        return
    raw = event.raw or {}
    content = _extract_text(raw.get("tool_response") or raw.get("output")
                            or raw.get("result"))
    record_read(event.session_id, str(path), a, content, event.cwd)


# ---------------------------------------------------------------- coverage query
def is_fully_read(session: Optional[str], file_path: str, cwd: Optional[str]) -> bool:
    """True iff the file's entire current content has been covered by Read(s) in
    this session. False on any uncertainty (missing file, hash drift, partial
    coverage) so the gate fails CLOSED — an unread manifest is never installable."""
    ap = _abspath(file_path, cwd)
    sha = _sha256(ap)
    if not sha:
        return False
    total = _line_count(ap)
    intervals = [(r.get("start", 1), r.get("end", 0)) for r in _read_records(session)
                 if r.get("path") == ap and r.get("sha") == sha]
    if not intervals:
        return False
    if total <= 0:
        return True  # empty file, and at least one matching-hash read exists
    return _covers(intervals, total)


def _covers(intervals, total: int) -> bool:
    """Do the (possibly overlapping) intervals cover [1, total] with no gap?"""
    merged = []
    for start, end in sorted(intervals):
        try:
            start, end = int(start), int(end)
        except (TypeError, ValueError):
            continue
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return bool(merged) and merged[0][0] <= 1 and merged[0][1] >= total


# ---------------------------------------------------------------- manifest resolve
# install command family -> (manifest, lockfile-ish companions) relative to cwd
_MANIFESTS = {
    "npm": ["package.json", "package-lock.json"],
    "pnpm": ["package.json", "pnpm-lock.yaml"],
    "yarn": ["package.json", "yarn.lock"],
    "bun": ["package.json", "bun.lockb"],
    "poetry": ["pyproject.toml", "poetry.lock"],
    "pipenv": ["Pipfile", "Pipfile.lock"],
    "bundle": ["Gemfile", "Gemfile.lock"],
    "gem": ["Gemfile"],
    "cargo": ["Cargo.toml", "Cargo.lock"],
    "go": ["go.mod", "go.sum"],
}
# install-time scripts a deep review must cover (where install hooks run)
_DEEP_SCRIPTS = ["setup.py", "setup.cfg", "pyproject.toml", "package.json",
                 "binding.gyp", "Makefile"]

_TOOL_RE = re.compile(
    r"\b(npm|pnpm|yarn|bun|pip3?|poetry|pipenv|bundle|gem|cargo|go)\b", re.IGNORECASE)
_PIP_REQ_RE = re.compile(r"(?:-r|--requirement)\s+(\S+)", re.IGNORECASE)


def resolve_manifests(cmd_text: str, cwd: Optional[str], deep: bool = False) -> List[str]:
    """The manifest files (that exist on disk) which determine what this install
    pulls in — and, in deep mode, the install-time scripts that run package code.

    A *targeted* install of named third-party packages (``pip install requests``,
    ``npm install lodash``) has no manifest to read — the named packages are reviewed
    via the digest instead — so only ``-r``/explicit files apply. A *manifest-driven*
    install (bare ``npm install``, ``poetry install``, ``pip install .``) pulls the
    whole manifest, so the manifest + lockfile must be fully read."""
    cwd = cwd or os.getcwd()
    found: List[str] = []

    def add(rel: str):
        ap = _abspath(rel, cwd)
        if os.path.isfile(ap) and ap not in found:
            found.append(ap)

    # pip -r <file> (possibly several) — the explicit manifest always applies
    for m in _PIP_REQ_RE.finditer(cmd_text):
        add(m.group(1))

    pkgs = package_args(cmd_text)
    third_party = [p for p in pkgs
                   if p not in (".", "..") and not p.startswith((".", "/", "~"))
                   and "://" not in p]

    m = _TOOL_RE.search(cmd_text)
    tool = (m.group(1).lower() if m else "")
    if not third_party:  # manifest-driven: the whole manifest is installed
        if tool.startswith("pip"):
            add("pyproject.toml")
            add("setup.py")
        for rel in _MANIFESTS.get(tool, []):
            add(rel)

    if deep:  # also force-read the install-time scripts that run package code
        for rel in _DEEP_SCRIPTS:
            add(rel)
    return found


def package_args(cmd_text: str) -> List[str]:
    """Best-effort list of explicitly named packages in a targeted install
    (``pip install requests flask`` -> ['requests', 'flask']). Flags and the
    install verbs are stripped; empty for a manifest-driven install."""
    try:
        toks = shlex.split(cmd_text, comments=True)
    except Exception:
        toks = cmd_text.split()
    verbs = {"install", "add", "i", "ci", "get"}
    skip_tools = {"npm", "pnpm", "yarn", "bun", "pip", "pip3", "poetry", "pipenv",
                  "bundle", "gem", "cargo", "go", "python", "python3", "-m", "pip"}
    pkgs = []
    seen_verb = False
    skip_next = False
    for t in toks:
        if skip_next:
            skip_next = False
            continue
        low = t.lower()
        if low in verbs:
            seen_verb = True
            continue
        if low in skip_tools:
            continue
        if t.startswith("-"):
            if low in ("-r", "--requirement", "-c", "--constraint", "-e", "--editable"):
                skip_next = True
            continue
        if seen_verb:
            pkgs.append(t)
    return pkgs


# ---------------------------------------------------------------- digest
_PIN_RE = re.compile(r"==|@\d|@\^|@~")


def digest(manifests: List[str], cmd_text: str, cwd: Optional[str]) -> dict:
    """A short, factual summary of what the install brings in, for the human ask."""
    out = {"deps": 0, "unpinned": 0, "remote": 0, "scripts": False,
           "manifests": [os.path.basename(m) for m in manifests], "packages": []}
    for m in manifests:
        base = os.path.basename(m).lower()
        try:
            text = open(m, "r", encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        if base == "package.json":
            _digest_package_json(text, out)
        elif base in ("requirements.txt",) or base.endswith(".txt"):
            _digest_requirements(text, out)
        elif base == "pyproject.toml":
            out["scripts"] = out["scripts"] or ("build-system" in text or "[tool.poetry]" in text)
        elif base in ("setup.py", "setup.cfg", "binding.gyp", "makefile"):
            out["scripts"] = True
    # targeted, manifest-less install: summarize the named packages
    pkgs = package_args(cmd_text)
    if pkgs:
        out["packages"] = pkgs
        out["deps"] += len(pkgs)
        out["unpinned"] += sum(1 for p in pkgs if not _PIN_RE.search(p))
    return out


def _digest_requirements(text: str, out: dict) -> None:
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        out["deps"] += 1
        if "://" in line or line.startswith(("git+", "./", "/", "..")):
            out["remote"] += 1
        elif "==" not in line and not re.search(r"@\s*[0-9a-f]{7,}", line):
            out["unpinned"] += 1


def _digest_package_json(text: str, out: dict) -> None:
    try:
        data = json.loads(text)
    except Exception:
        return
    scripts = data.get("scripts") or {}
    if any(k in scripts for k in ("preinstall", "install", "postinstall", "prepare")):
        out["scripts"] = True
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(field) or {}
        for name, ver in deps.items():
            out["deps"] += 1
            v = str(ver)
            if "://" in v or v.startswith(("git", "file:", "github:")):
                out["remote"] += 1
            elif any(c in v for c in "^~*") or v in ("latest", "", "*"):
                out["unpinned"] += 1


def format_digest(d: dict) -> str:
    bits = []
    if d.get("manifests"):
        bits.append(", ".join(d["manifests"]))
    if d.get("packages"):
        bits.append("pkgs: " + " ".join(d["packages"][:8]))
    bits.append(f"{d.get('deps', 0)} dep(s)")
    if d.get("unpinned"):
        bits.append(f"{d['unpinned']} UNPINNED")
    if d.get("remote"):
        bits.append(f"{d['remote']} URL/VCS/local")
    if d.get("scripts"):
        bits.append("install-time scripts present")
    return " · ".join(bits)
