"""Server-side identity gate + MCP integration."""
import pytest

from aegis import gate, identity, mcp


def test_human_is_trusted(monkeypatch):
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)
    assert gate.caller_is_trusted()
    assert gate.gate("write") is None


def test_untokened_agent_monitor_allows(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    monkeypatch.setenv("AEGIS_AGENT_NAME", "rogue")
    monkeypatch.delenv("AEGIS_AGENT_TOKEN", raising=False)
    monkeypatch.delenv("AEGIS_IDENTITY_ENFORCE", raising=False)
    assert not gate.caller_is_trusted()
    assert gate.gate("write") is None  # MONITOR: recorded but allowed


def test_untokened_agent_enforce_refuses(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    monkeypatch.setenv("AEGIS_AGENT_NAME", "rogue")
    monkeypatch.delenv("AEGIS_AGENT_TOKEN", raising=False)
    monkeypatch.setenv("AEGIS_IDENTITY_ENFORCE", "1")
    assert "refused" in gate.gate("vault:get")
    with pytest.raises(gate.Refused):
        gate.require("vault:get")


def test_valid_token_is_trusted(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    monkeypatch.setenv("AEGIS_AGENT_NAME", "scout")
    monkeypatch.setenv("AEGIS_IDENTITY_ENFORCE", "1")
    monkeypatch.setenv("AEGIS_AGENT_TOKEN", identity.issue("scout"))
    assert gate.caller_is_trusted()
    assert gate.gate("vault:get") is None


def test_mcp_check_refuses_untokened_under_enforce(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    monkeypatch.setenv("AEGIS_POLICIES", str(tmp_path / "none"))
    monkeypatch.setenv("AEGIS_AGENT_NAME", "rogue")
    monkeypatch.delenv("AEGIS_AGENT_TOKEN", raising=False)
    monkeypatch.setenv("AEGIS_IDENTITY_ENFORCE", "1")
    d = mcp.check("Read", {"file_path": "x"})
    assert d.blocked and d.rule == "identity-gate"
