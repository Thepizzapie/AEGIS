"""Forced install review — deny-until-fully-read, then human ask.

Defends the 0DIN "clean repo" reverse-shell attack at its foothold: an install
cannot run until the manifest that determines what it pulls in has been *fully
read* this session (a skim never counts), and even then it surfaces a human ask.
"""
import os

import pytest

from aegis import review
from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()


@pytest.fixture(autouse=True)
def isolate_home(tmp_path, monkeypatch):
    """Point the review ledger at a throwaway home so tests don't see each other."""
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "aegishome"))
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)
    monkeypatch.delenv("AEGIS_ALLOW_INSTALL", raising=False)


def _shell(cmd, cwd, session="s"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash",
                      args={"command": cmd}, session_id=session, cwd=str(cwd))


def _full_read(path, cwd, session="s", offset=1, content=None):
    """Simulate the PostToolUse of a Read covering the file (or a slice of it)."""
    if content is None:
        content = open(os.path.join(str(cwd), path), encoding="utf-8").read()
    ev = Event.make(HookEvent.POST_TOOL_USE, tool="Read",
                    args={"file_path": path, "offset": offset},
                    session_id=session, cwd=str(cwd),
                    raw={"tool_response": {"file": {"content": content}}})
    review.observe(ev)


def _reqs(tmp_path, *lines):
    p = tmp_path / "requirements.txt"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


# --------------------------------------------------------------- the core gate
def test_install_blocked_until_manifest_read(tmp_path):
    _reqs(tmp_path, "requests==2.0", "flask==3.0")
    d = evaluate(_shell("pip install -r requirements.txt", tmp_path), EMPTY)
    assert d.action == Action.DENY and d.rule == "install-review"


def test_install_asks_after_full_read(tmp_path):
    _reqs(tmp_path, "requests==2.0", "flask==3.0")
    _full_read("requirements.txt", tmp_path)
    d = evaluate(_shell("pip install -r requirements.txt", tmp_path), EMPTY)
    assert d.action == Action.ASK and d.rule == "install-review"


def test_no_content_response_does_not_satisfy(tmp_path):
    """CRITICAL: a Read whose tool_response carries no content proves nothing read ->
    the gate must stay closed (no assume-to-EOF fail-open)."""
    _reqs(tmp_path, *[f"pkg{i}==1.0" for i in range(20)])
    ev = Event.make(HookEvent.POST_TOOL_USE, tool="Read",
                    args={"file_path": "requirements.txt"}, session_id="s",
                    cwd=str(tmp_path), raw={"tool_response": None})
    review.observe(ev)
    assert evaluate(_shell("pip install -r requirements.txt", tmp_path), EMPTY).action == Action.DENY


def test_empty_content_does_not_satisfy(tmp_path):
    _reqs(tmp_path, *[f"pkg{i}==1.0" for i in range(20)])
    _full_read("requirements.txt", tmp_path, content="")
    assert evaluate(_shell("pip install -r requirements.txt", tmp_path), EMPTY).action == Action.DENY


def test_trailing_blank_lines_still_fully_read(tmp_path):
    """File ends with blank lines but the runtime returns content without them ->
    must still count as fully read."""
    (tmp_path / "requirements.txt").write_text("requests==2.0\nflask==3.0\n\n\n", encoding="utf-8")
    _full_read("requirements.txt", tmp_path, content="requests==2.0\nflask==3.0")
    assert evaluate(_shell("pip install -r requirements.txt", tmp_path), EMPTY).action == Action.ASK


def test_monitor_mode_records_would_be_denial(tmp_path, monkeypatch):
    """Monitor mode allows but writes the projected decision to the audit log."""
    import json
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AEGIS_AUDIT", str(audit))
    _reqs(tmp_path, "requests==2.0")
    pol = Policy(install_review={"mode": "monitor"})
    assert evaluate(_shell("pip install -r requirements.txt", tmp_path), pol).action == Action.ALLOW
    rows = [json.loads(l) for l in audit.read_text().splitlines() if l.strip()]
    monitor = [r for r in rows if r.get("rule") == "install-review-monitor"]
    assert monitor and monitor[0]["decision"] == "deny"


def test_skim_does_not_satisfy(tmp_path):
    """A partial read (limit/offset that stops short) must NOT count as review."""
    _reqs(tmp_path, *[f"pkg{i}==1.0" for i in range(10)])
    # only the first 3 of 10 lines
    _full_read("requirements.txt", tmp_path, content="pkg0==1.0\npkg1==1.0\npkg2==1.0")
    d = evaluate(_shell("pip install -r requirements.txt", tmp_path), EMPTY)
    assert d.action == Action.DENY


def test_edit_after_read_rearms_gate(tmp_path):
    p = _reqs(tmp_path, "requests==2.0")
    _full_read("requirements.txt", tmp_path)
    assert evaluate(_shell("pip install -r requirements.txt", tmp_path), EMPTY).action == Action.ASK
    p.write_text("requests==2.0\nevil==6.6.6\n", encoding="utf-8")  # content drift
    assert evaluate(_shell("pip install -r requirements.txt", tmp_path), EMPTY).action == Action.DENY


def test_paginated_full_read_satisfies(tmp_path):
    """A large file read in chunks that together cover it counts as fully read."""
    _reqs(tmp_path, *[f"pkg{i}==1.0" for i in range(6)])
    _full_read("requirements.txt", tmp_path, offset=1, content="pkg0==1.0\npkg1==1.0\npkg2==1.0")
    _full_read("requirements.txt", tmp_path, offset=4, content="pkg3==1.0\npkg4==1.0\npkg5==1.0")
    assert evaluate(_shell("pip install -r requirements.txt", tmp_path), EMPTY).action == Action.ASK


# --------------------------------------------------------------- escape hatches
def test_agent_cannot_self_escape_read_gate(tmp_path, monkeypatch):
    _reqs(tmp_path, "requests==2.0")
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    d = evaluate(_shell("pip install -r requirements.txt  # aegis-allow", tmp_path), EMPTY)
    assert d.action == Action.DENY


def test_human_override_skips_gate(tmp_path):
    _reqs(tmp_path, "requests==2.0")
    d = evaluate(_shell("pip install -r requirements.txt  # aegis-allow", tmp_path), EMPTY)
    assert d.action == Action.ALLOW


def test_env_allow_install_bypass(tmp_path, monkeypatch):
    _reqs(tmp_path, "requests==2.0")
    monkeypatch.setenv("AEGIS_ALLOW_INSTALL", "1")
    d = evaluate(_shell("pip install -r requirements.txt", tmp_path), EMPTY)
    assert d.action == Action.ALLOW


def test_mode_off(tmp_path):
    _reqs(tmp_path, "requests==2.0")
    pol = Policy(install_review={"mode": "off"})
    assert evaluate(_shell("pip install -r requirements.txt", tmp_path), pol).action == Action.ALLOW


def test_mode_monitor_allows_but_is_not_ask(tmp_path):
    _reqs(tmp_path, "requests==2.0")
    pol = Policy(install_review={"mode": "monitor"})
    assert evaluate(_shell("pip install -r requirements.txt", tmp_path), pol).action == Action.ALLOW


# --------------------------------------------------------------- scope: all installs
def test_targeted_install_asks_not_denied(tmp_path):
    """A targeted named-package install has no manifest to read -> straight to ask."""
    d = evaluate(_shell("pip install requests", tmp_path), EMPTY)
    assert d.action == Action.ASK
    assert evaluate(_shell("npm install lodash", tmp_path), EMPTY).action == Action.ASK


def test_bare_npm_install_requires_package_json(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"left-pad":"^1.0.0"}}', encoding="utf-8")
    assert evaluate(_shell("npm install", tmp_path), EMPTY).action == Action.DENY
    _full_read("package.json", tmp_path)
    assert evaluate(_shell("npm install", tmp_path), EMPTY).action == Action.ASK


def test_noexec_fetch_not_gated(tmp_path):
    _reqs(tmp_path, "requests==2.0")
    # a download/pack is not an install (no package code runs / nothing placed)
    assert evaluate(_shell("pip download -r requirements.txt", tmp_path), EMPTY).action == Action.ALLOW
    assert evaluate(_shell("npm pack", tmp_path), EMPTY).action == Action.ALLOW


def test_ignore_scripts_still_gated(tmp_path):
    """`npm install --ignore-scripts` still PLACES the package -> stays gated."""
    (tmp_path / "package.json").write_text('{"dependencies":{}}', encoding="utf-8")
    assert evaluate(_shell("npm install --ignore-scripts", tmp_path), EMPTY).action == Action.DENY


def test_non_install_shell_untouched(tmp_path):
    assert evaluate(_shell("echo hello", tmp_path), EMPTY).action == Action.ALLOW
    assert evaluate(_shell("python script.py", tmp_path), EMPTY).action == Action.ALLOW
    # yarn build/test are scripts, not installs — must NOT gate
    assert evaluate(_shell("yarn build", tmp_path), EMPTY).action == Action.ALLOW
    assert evaluate(_shell("yarn test", tmp_path), EMPTY).action == Action.ALLOW


def test_toolchain_upgrade_is_targeted_not_manifest(tmp_path):
    """`pip install --upgrade pip` must NOT be blocked against the project manifest."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    (tmp_path / "setup.py").write_text("setup()\n", encoding="utf-8")
    d = evaluate(_shell("pip install --upgrade pip", tmp_path), EMPTY)
    assert d.action == Action.ASK  # targeted -> ask, never deny-until-read


def test_explicit_requirements_does_not_drag_pyproject(tmp_path):
    """`pip install -r requirements.txt` gates ONLY the requirements file."""
    _reqs(tmp_path, "requests==2.0")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    (tmp_path / "setup.py").write_text("setup()\n", encoding="utf-8")
    _full_read("requirements.txt", tmp_path)  # only the requirements file
    assert evaluate(_shell("pip install -r requirements.txt", tmp_path), EMPTY).action == Action.ASK


def test_modern_installers_gated(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    assert evaluate(_shell("uv add requests", tmp_path), EMPTY).action == Action.ASK   # targeted
    assert evaluate(_shell("pipx install black", tmp_path), EMPTY).action == Action.ASK
    # path-qualified pip is still recognized
    _reqs(tmp_path, "requests==2.0")
    assert evaluate(_shell("./venv/bin/pip install -r requirements.txt", tmp_path), EMPTY).action == Action.DENY


def test_local_path_install_resolves_target_dir(tmp_path):
    """`pip install ./evil` must gate ./evil/setup.py, not the benign cwd setup.py."""
    (tmp_path / "setup.py").write_text("# benign cwd\nsetup()\n", encoding="utf-8")
    evil = tmp_path / "evil"
    evil.mkdir()
    (evil / "setup.py").write_text("# malicious\nimport os\n", encoding="utf-8")
    # reading the cwd setup.py must NOT satisfy the gate for ./evil
    _full_read("setup.py", tmp_path)
    assert evaluate(_shell("pip install ./evil", tmp_path), EMPTY).action == Action.DENY
    _full_read("evil/setup.py", tmp_path)
    assert evaluate(_shell("pip install ./evil", tmp_path), EMPTY).action == Action.ASK


# --------------------------------------------------------------- config knobs
def test_require_pinned_denies_unpinned(tmp_path):
    _reqs(tmp_path, "requests==2.0", "flask")  # flask is unpinned
    _full_read("requirements.txt", tmp_path)
    pol = Policy(install_review={"require_pinned": True})
    d = evaluate(_shell("pip install -r requirements.txt", tmp_path), pol)
    assert d.action == Action.DENY and "unpinned" in (d.message or "").lower()


def test_require_pinned_allows_fully_pinned(tmp_path):
    _reqs(tmp_path, "requests==2.0", "flask==3.0")
    _full_read("requirements.txt", tmp_path)
    pol = Policy(install_review={"require_pinned": True})
    assert evaluate(_shell("pip install -r requirements.txt", tmp_path), pol).action == Action.ASK


def test_deep_mode_requires_reading_setup_script(tmp_path):
    _reqs(tmp_path, "requests==2.0")
    (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup()\n", encoding="utf-8")
    _full_read("requirements.txt", tmp_path)
    pol = Policy(install_review={"deep": True})
    # setup.py still unread -> blocked
    assert evaluate(_shell("pip install -r requirements.txt", tmp_path), pol).action == Action.DENY
    _full_read("setup.py", tmp_path)
    assert evaluate(_shell("pip install -r requirements.txt", tmp_path), pol).action == Action.ASK


def test_allow_regex_exemption(tmp_path):
    _reqs(tmp_path, "requests==2.0")
    pol = Policy(install_review={"allow": [r"requirements\.txt"]})
    assert evaluate(_shell("pip install -r requirements.txt", tmp_path), pol).action == Action.ALLOW


# --------------------------------------------------------------- digest
def test_digest_counts_and_flags(tmp_path):
    _reqs(tmp_path, "requests==2.0", "flask", "git+https://x/y.git")
    d = review.digest([str(tmp_path / "requirements.txt")], "pip install -r requirements.txt", str(tmp_path))
    assert d["deps"] == 3
    assert d["unpinned"] == 1   # flask
    assert d["remote"] == 1     # git+https
