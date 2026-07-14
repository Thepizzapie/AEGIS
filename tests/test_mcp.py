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


def test_bare_named_mcp_tool_gets_containment_scanning(tmp_path, monkeypatch):
    # QA review (independent agent, round 8): an MCP server's OWN tool name
    # (e.g. "read_file", not the "mcp__server__tool" shape Claude Code's hook
    # adapter uses) classified as ActionClass.OTHER and got NO containment
    # scanning at all through this embed-in-your-own-server API — silently,
    # for every server using this module as documented. `check`/`guard`/
    # `guarded` now default an unrecognized tool name to ActionClass.MCP.
    _isolate(tmp_path, monkeypatch)
    assert mcp.check("read_file", {"path": "/home/user/.ssh/id_rsa"}).blocked
    assert mcp.check("create_task",
                      {"command": "schtasks /create /tn x /tr y.exe"}).blocked
    assert not mcp.check("read_file", {"path": "src/app.py"}).blocked

    @mcp.guarded
    def read_file(path):
        return f"CONTENTS OF {path}"

    with pytest.raises(mcp.Denied):
        read_file(path="/home/user/.ssh/id_rsa")


def test_native_tool_name_reuse_still_uses_its_own_action_class(tmp_path, monkeypatch):
    # A caller may still deliberately pass a Claude-native tool NAME ("Bash",
    # "Read") to reuse its matching shell/file guards (test_check_blocks_
    # dangerous/test_check_allows_normal above do exactly this) — the
    # round-8 fix must only fill in the MCP default for names classify()
    # can't already place, not override an already-specific classification.
    _isolate(tmp_path, monkeypatch)
    assert mcp.check("Bash", {"command": "rm -rf /"}).blocked
    assert not mcp.check("Read", {"file_path": "README.md"}).blocked
