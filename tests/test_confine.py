"""Workspace confinement + protecting Aegis's own engine source."""
import os

from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Policy


def _edit(path, cwd=None):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit", args={"file_path": path}, cwd=cwd)


def test_no_workspace_no_opinion():
    assert not evaluate(_edit("/anywhere/x.py"), Policy()).blocked


def test_confine_blocks_outside(tmp_path):
    root = str(tmp_path / "proj")
    os.makedirs(root, exist_ok=True)
    pol = Policy(workspace={"root": root})
    assert not evaluate(_edit(os.path.join(root, "app.py")), pol).blocked
    assert evaluate(_edit(str(tmp_path / "other" / "x.py")), pol).blocked


def test_confine_allow_list(tmp_path):
    root = str(tmp_path / "proj")
    extra = str(tmp_path / "shared")
    os.makedirs(root, exist_ok=True)
    os.makedirs(extra, exist_ok=True)
    pol = Policy(workspace={"root": root, "allow": [extra]})
    assert not evaluate(_edit(os.path.join(extra, "lib.py")), pol).blocked
    assert evaluate(_edit(str(tmp_path / "elsewhere" / "x.py")), pol).blocked


def test_confine_relative_resolved_against_cwd(tmp_path):
    root = str(tmp_path / "proj")
    os.makedirs(root, exist_ok=True)
    pol = Policy(workspace={"root": root})
    assert not evaluate(_edit("sub/app.py", cwd=root), pol).blocked
    assert evaluate(_edit("../escape.py", cwd=root), pol).blocked   # .. escape


def test_protect_aegis_engine_source(monkeypatch):
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)
    d = evaluate(_edit("/opt/venv/lib/python3.12/site-packages/aegis/rules.py"), Policy())
    assert d.blocked and d.rule == "self-protect"
    assert evaluate(_edit("some/proj/aegis/patterns.py"), Policy()).blocked
    assert evaluate(_edit("aegis/adapters/claude_code.py"), Policy()).blocked
    # a normal source file is fine
    assert not evaluate(_edit("src/app.py"), Policy()).blocked


# --- identity-bound confinement (fix/attribution): the project comes from the
#     agent's IDENTITY (token `project` claim / AEGIS_PROJECT), not just policy ---
def _w(path, cwd=None, tool="Write"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args={"file_path": path}, cwd=cwd)


def test_confine_via_aegis_project_env(monkeypatch, tmp_path):
    proj = str(tmp_path / "proj")
    os.makedirs(proj, exist_ok=True)
    monkeypatch.delenv("AEGIS_AGENT_TOKEN", raising=False)
    monkeypatch.setenv("AEGIS_PROJECT", proj)
    assert not evaluate(_w(os.path.join(proj, "a.py"), cwd=proj), Policy()).blocked
    d = evaluate(_w(str(tmp_path / "evil.py"), cwd=proj), Policy())
    assert d.blocked and d.rule == "workspace-confine"


def test_reads_outside_project_are_not_confined(monkeypatch, tmp_path):
    monkeypatch.delenv("AEGIS_AGENT_TOKEN", raising=False)
    monkeypatch.setenv("AEGIS_PROJECT", str(tmp_path / "proj"))
    assert not evaluate(_w(str(tmp_path / "out.txt"), cwd=str(tmp_path), tool="Read"), Policy()).blocked


def test_confine_via_policy_project_field(monkeypatch, tmp_path):
    for v in ("AEGIS_PROJECT", "AEGIS_WORKSPACE", "AEGIS_AGENT_TOKEN"):
        monkeypatch.delenv(v, raising=False)
    pol = Policy(project=str(tmp_path / "proj"))
    assert evaluate(_w(str(tmp_path / "x.py"), cwd=str(tmp_path)), pol).blocked


def test_confine_via_token_project_claim(monkeypatch, tmp_path):
    # The headline: a signed token's `project` claim binds the agent. No
    # AEGIS_PROJECT / policy set -> the confinement root comes purely from identity.
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "home"))
    for v in ("AEGIS_PROJECT", "AEGIS_WORKSPACE"):
        monkeypatch.delenv(v, raising=False)
    from aegis import identity
    proj = str(tmp_path / "proj")
    os.makedirs(proj, exist_ok=True)
    tok = identity.issue("bot", project=proj)
    assert tok, "cryptography unavailable - cannot issue token"
    monkeypatch.setenv("AEGIS_AGENT_TOKEN", tok)
    d = evaluate(_w(str(tmp_path / "outside.py"), cwd=proj), Policy())
    assert d.blocked and d.rule == "workspace-confine"
    assert not evaluate(_w(os.path.join(proj, "ok.py"), cwd=proj), Policy()).blocked
