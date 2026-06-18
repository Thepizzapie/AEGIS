"""Embed-in-your-MCP guard: check / guard / @guarded."""
import pytest

from aegis import mcp


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    monkeypatch.setenv("AEGIS_POLICIES", str(tmp_path / "none"))  # empty -> built-ins only


def test_check_blocks_dangerous(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert mcp.check("Bash", {"command": "rm -rf /"}).blocked


def test_check_allows_normal(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert not mcp.check("Read", {"file_path": "README.md"}).blocked


def test_guard_raises_denied(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    with pytest.raises(mcp.Denied):
        mcp.guard("Bash", {"command": "cat ~/.ssh/id_rsa"})


def test_guarded_decorator(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)

    @mcp.guarded(tool_name="vault_get")
    def vault_get(key=None):
        return f"secret:{key}"

    assert vault_get(key="ok") == "secret:ok"  # allowed (no rule matches)
