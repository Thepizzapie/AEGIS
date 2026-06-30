"""Forced install review — the read-coverage ledger (AEGI-review).

A common careless path to compromise is an *unread* install: the agent runs
``pip install -r requirements.txt`` straight from a repo's setup notes, never
looking at what it pulls in. This module records which files have been **fully
read** in a session (full reads, not skims) so the install guard
(``rules.rule_install_review``) can refuse to install a manifest the agent hasn't
actually looked at, then force a human ask with a factual digest.

Scope, stated honestly: this proves the manifest's bytes *entered context* and
puts a human in the loop — it does not prove the reader comprehended them, and it
does not inspect a dependency's install-time code (that runs inside the package
manager's subprocess, below the hook boundary — Aegis is not a sandbox). It raises
the cost of the *poisoned-manifest / blind-install* variant; it is not, by itself,
a complete defense against an attack whose payload lives in package code or a
later step. Pair it with deny-by-default egress and OS isolation. See the README
"Forced install review" section for the precise kill-chain coverage.

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

_MAX_BYTES = 50_000_000  # don't hash/scan absurdly large files (big lockfiles fit)


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
    """Significant line count — trailing blank lines don't count toward coverage, so a
    full read whose content the runtime returns without the file's trailing newline(s)
    still satisfies the gate (a common, maddening false-deny otherwise)."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.read().splitlines()
    except Exception:
        return 0
    while lines and not lines[-1].strip():
        lines.pop()
    return len(lines)


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
    """Record the line interval a Read *actually* covered, keyed by the file's hash.

    Coverage is derived ONLY from positive evidence — the returned content's line
    count, i.e. exactly the bytes the runtime delivered into context. A read with no
    content (an unrecognized/empty ``tool_response``, or a runtime that doesn't carry
    Read output) records **nothing**: the gate fails closed, because an unread
    manifest must never become installable. We deliberately do NOT infer coverage
    from a ``limit`` (a request ceiling, not proof) or assume-to-EOF for a bare read
    (that was the fail-open). This trusts the runtime to deliver a faithful
    ``tool_response`` — the same trust the hook boundary itself rests on; it does not
    defend against a caller that forges its own hook payloads (see README: the hook
    can be skipped, the import-level gate cannot)."""
    if content is None:
        return  # no proof of any line read -> record nothing (fail closed)
    n = len(str(content).splitlines())
    if n == 0:
        if not str(content):
            return  # empty response -> zero lines proven
        n = 1
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
    end = offset + n - 1
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


def _is_local_path(p: str) -> bool:
    return p in (".", "..") or p.startswith((".", "/", "~"))


def resolve_manifests(cmd_text: str, cwd: Optional[str], deep: bool = False) -> List[str]:
    """The manifest files (that exist on disk) which determine what this install
    pulls in — and, in deep mode, the install-time scripts that run package code.

    A *targeted* install of named third-party packages (``pip install requests``,
    ``npm install lodash``, ``pip install --upgrade pip``) has no manifest to read —
    the named packages are reviewed via the digest instead. An *explicit manifest*
    install (``pip install -r requirements.txt``) gates exactly the named file(s)
    (and any nested ``-r``/``-c`` includes) — not unrelated project files. A
    *manifest-driven* install (bare ``npm install``, ``poetry install``) gates the
    tool's manifest + lockfile. A *local-path* install (``pip install ./pkg``) gates
    the build files of THAT directory, where its install hooks live."""
    cwd = cwd or os.getcwd()
    found: List[str] = []

    def add(rel: str, base: Optional[str] = None):
        ap = _abspath(rel, base or cwd)
        if os.path.isfile(ap) and ap not in found:
            found.append(ap)

    # pip -r/-c <file> (possibly several), plus their nested includes — always apply
    req_files = [m.group(1) for m in _PIP_REQ_RE.finditer(cmd_text)]
    for rel in req_files:
        add(rel)
        _expand_requirement_includes(_abspath(rel, cwd), found)

    pkgs = package_args(cmd_text)
    third_party = [p for p in pkgs if not _is_local_path(p) and "://" not in p]
    local_paths = [p for p in pkgs if _is_local_path(p)]

    m = _TOOL_RE.search(cmd_text)
    tool = (m.group(1).lower() if m else "")

    if not third_party:
        if tool.startswith("pip"):
            # only a local-path target drags in build files — and from THAT dir,
            # not the cwd. A bare `-r` install gates just the requirement file(s).
            for b in local_paths:
                bp = _abspath(b, cwd)
                root = bp if os.path.isdir(bp) else os.path.dirname(bp)
                add("pyproject.toml", root)
                add("setup.py", root)
        else:
            for rel in _MANIFESTS.get(tool, []):
                add(rel)

    if deep:  # also force-read the local install-time scripts that run package code
        roots = [cwd] + [(_abspath(b, cwd) if os.path.isdir(_abspath(b, cwd))
                          else os.path.dirname(_abspath(b, cwd))) for b in local_paths]
        for root in roots:
            for rel in _DEEP_SCRIPTS:
                add(rel, root)
    return found


def _expand_requirement_includes(path: str, acc: List[str], depth: int = 0) -> None:
    """Resolve nested ``-r``/``-c`` includes inside a requirements file (pip resolves
    them relative to the including file), so a manifest can't launder its real
    contents through an include the gate never force-reads."""
    if depth > 5:
        return
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                s = line.split("#", 1)[0].strip()
                m = re.match(r"(?:-r|--requirement|-c|--constraint)[\s=]+(\S+)", s)
                if not m:
                    continue
                inc = _abspath(m.group(1), os.path.dirname(path))
                if os.path.isfile(inc) and inc not in acc:
                    acc.append(inc)
                    _expand_requirement_includes(inc, acc, depth + 1)
    except Exception:
        pass


def package_args(cmd_text: str) -> List[str]:
    """Best-effort list of explicitly named packages in a targeted install
    (``pip install requests flask`` -> ['requests', 'flask']). Flags and the
    install verbs are stripped; empty for a manifest-driven install."""
    try:
        toks = shlex.split(cmd_text, comments=True)
    except Exception:
        toks = cmd_text.split()
    verbs = {"install", "add", "i", "ci", "get", "sync"}
    # tool words to ignore when they appear BEFORE the verb. Note: pip/setuptools/
    # wheel are intentionally NOT here, so `pip install --upgrade pip` registers
    # `pip` as a named (targeted) package rather than a manifest-driven install.
    skip_tools = {"npm", "pnpm", "yarn", "bun", "poetry", "pipenv", "uv", "pipx",
                  "bundle", "gem", "cargo", "go", "conda", "mamba", "micromamba",
                  "python", "python3", "-m"}
    # options that consume the FOLLOWING token as their value (not a package)
    val_opts = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable",
                "-i", "--index-url", "--extra-index-url", "-f", "--find-links",
                "--trusted-host", "-t", "--target", "--platform", "--python-version",
                "--no-binary", "--only-binary", "--prefix", "--root"}
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
            if low in val_opts:
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
