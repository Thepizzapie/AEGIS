"""AEGI-6: RBAC identity resolution, policy distribution, org audit aggregation."""
import json

from aegis import identity, distribution
from aegis.accountability import report, load_dir
from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Policy, Rule, Action


def test_identity_from_env(monkeypatch):
    monkeypatch.setenv("AEGIS_IDENTITY", "alice")
    monkeypatch.setenv("AEGIS_ROLES", "admin, dev")
    ident, roles = identity.resolve_identity({})
    assert ident == "alice"
    assert roles == ["admin", "dev"]


def test_identity_payload_fallback(monkeypatch):
    monkeypatch.delenv("AEGIS_IDENTITY", raising=False)
    monkeypatch.delenv("AEGIS_ROLES", raising=False)
    ident, roles = identity.resolve_identity({"identity": "bob", "roles": ["viewer"]})
    assert ident == "bob" and roles == ["viewer"]


def test_rbac_admin_bypass():
    pol = Policy(rules=[
        Rule(name="admin-allow", action=Action.ALLOW, actions=["shell"],
             roles=["admin"], priority=100),
        Rule(name="deny-shell", action=Action.DENY, actions=["shell"]),
    ])
    admin = Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", roles=["admin"])
    dev = Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", roles=["dev"])
    assert not evaluate(admin, pol).blocked
    assert evaluate(dev, pol).blocked


def test_pull_policy_from_local_dir(tmp_path):
    src = tmp_path / "org"
    src.mkdir()
    (src / "a.yaml").write_text("rules: []\n", encoding="utf-8")
    (src / "b.yml").write_text("rules: []\n", encoding="utf-8")
    (src / "ignore.txt").write_text("nope", encoding="utf-8")
    dest = tmp_path / "policies"

    n = distribution.pull_policy(str(src), str(dest))
    assert n == 2
    assert (dest / "a.yaml").exists() and (dest / "b.yml").exists()
    assert not (dest / "ignore.txt").exists()


def test_pull_policy_rejects_plain_http():
    """Policy must not be pulled over unencrypted HTTP."""
    import pytest
    with pytest.raises(ValueError, match="plain HTTP"):
        distribution.pull_policy("http://evil.test/policy.yaml", "/tmp/dest")


def test_org_audit_aggregation(tmp_path):
    d = tmp_path / "audits"
    d.mkdir()
    (d / "dev1.jsonl").write_text(
        json.dumps({"decision": "deny", "tool": "Bash", "action": "shell"}) + "\n",
        encoding="utf-8")
    (d / "dev2.jsonl").write_text(
        json.dumps({"decision": "allow", "tool": "Read", "action": "read"}) + "\n"
        + json.dumps({"decision": "deny", "tool": "Bash", "action": "shell"}) + "\n",
        encoding="utf-8")

    assert len(load_dir(d)) == 3
    rep = report(d)
    assert rep["summary"]["total"] == 3
    assert rep["summary"]["denied"] == 2
