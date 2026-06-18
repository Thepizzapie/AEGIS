"""Attribution + BOM regression tests (fix/attribution).

Pins the wiring behind the README "Agent environment" table: AEGIS_AGENT_NAME and
AEGIS_SESSION_ID must reach the audit record. Previously parse_event read identity
only from the hook payload and resolve_identity looked at AEGIS_IDENTITY (not the
documented AEGIS_AGENT_NAME), so every record collapsed to the OS user.

The BOM test feeds real bytes through a fake stdin.buffer so it covers the actual
decode path (PowerShell prepends a UTF-8 BOM that text-mode reads mis-decode).
"""
import json

from aegis import cli, identity


class _FakeBuffer:
    def __init__(self, data: bytes):
        self._data = data

    def read(self) -> bytes:
        return self._data


class _FakeStdin:
    """Mimics a real piped stdin: bytes via .buffer, not a tty."""

    def __init__(self, data: bytes):
        self.buffer = _FakeBuffer(data)

    def isatty(self) -> bool:
        return False


class _Args:
    def __init__(self, event):
        self.event = event
        self.runtime = None


def _fire(monkeypatch, tmp_path, payload_bytes):
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AEGIS_AUDIT", str(audit))
    monkeypatch.setenv("AEGIS_POLICIES", str(tmp_path))  # no rules -> default allow
    monkeypatch.setattr("sys.stdin", _FakeStdin(payload_bytes))
    rc = cli._cmd_hook(_Args("PreToolUse"))
    line = audit.read_text(encoding="utf-8").splitlines()[-1]
    return rc, json.loads(line)


READ_README = b'{"tool_name":"Read","tool_input":{"file_path":"README.md"}}'


def test_resolve_identity_prefers_agent_name(monkeypatch):
    monkeypatch.delenv("AEGIS_AGENT_TOKEN", raising=False)
    monkeypatch.delenv("AEGIS_IDENTITY", raising=False)
    monkeypatch.setenv("AEGIS_AGENT_NAME", "claude-test")
    ident, _roles = identity.resolve_identity({})
    assert ident == "claude-test"


def test_hook_record_carries_agent_and_session(monkeypatch, tmp_path):
    monkeypatch.delenv("AEGIS_AGENT_TOKEN", raising=False)
    monkeypatch.delenv("AEGIS_IDENTITY", raising=False)
    monkeypatch.setenv("AEGIS_AGENT_NAME", "claude-test")
    monkeypatch.setenv("AEGIS_SESSION_ID", "sess-abc123")
    rc, rec = _fire(monkeypatch, tmp_path, READ_README)
    assert rc == 0
    assert rec["agent"] == "claude-test"
    assert rec["session_id"] == "sess-abc123"
    assert rec["identity"] == "claude-test"


def test_payload_identity_beats_env(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_SESSION_ID", "env-session")
    payload = b'{"tool_name":"Read","tool_input":{"file_path":"x"},"session_id":"payload-session"}'
    _rc, rec = _fire(monkeypatch, tmp_path, payload)
    assert rec["session_id"] == "payload-session"


def test_stdin_utf8_bom_is_tolerated(monkeypatch, tmp_path):
    # PowerShell prepends a UTF-8 BOM (EF BB BF). utf-8-sig must strip it so the
    # payload parses instead of degrading to {} (-> allow).
    _rc, rec = _fire(monkeypatch, tmp_path, b"\xef\xbb\xbf" + READ_README)
    assert rec["tool"] == "Read"


def test_defaults_to_runtime_when_unconfigured(monkeypatch, tmp_path):
    # A vanilla install with nothing configured must still attribute the record:
    # agent -> the runtime name, session_id -> a non-null per-process fallback.
    for v in ("AEGIS_AGENT_NAME", "AEGIS_SESSION_ID", "AEGIS_IDENTITY", "AEGIS_AGENT_TOKEN"):
        monkeypatch.delenv(v, raising=False)
    _rc, rec = _fire(monkeypatch, tmp_path, READ_README)
    assert rec["agent"] == "claude-code"          # never null
    assert rec["session_id"]                        # never null
    assert rec["session_id"].startswith("claude-code-")


def test_agent_label_from_policy_fills_agent_and_identity(monkeypatch, tmp_path):
    # A repo's .aegis policy declaring `agent_label` labels records with zero env.
    for v in ("AEGIS_AGENT_NAME", "AEGIS_IDENTITY", "AEGIS_SESSION_ID", "AEGIS_AGENT_TOKEN"):
        monkeypatch.delenv(v, raising=False)
    pol_dir = tmp_path / "pol"
    pol_dir.mkdir()
    (pol_dir / "p.yaml").write_text("agent_label: ci-bot\n", encoding="utf-8")
    monkeypatch.setenv("AEGIS_POLICIES", str(pol_dir))
    monkeypatch.setenv("AEGIS_AUDIT", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr("sys.stdin", _FakeStdin(READ_README))
    cli._cmd_hook(_Args("PreToolUse"))
    rec = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert rec["agent"] == "ci-bot"
    assert rec["identity"] == "ci-bot"


def test_unparseable_payload_fails_open_visibly(monkeypatch, tmp_path, capsys):
    # A malformed payload must NOT silently allow: it warns (stderr) and writes a
    # payload-parse-error audit row. Default direction is fail-open (rc 0).
    monkeypatch.delenv("AEGIS_FAIL_CLOSED", raising=False)
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AEGIS_AUDIT", str(audit))
    monkeypatch.setenv("AEGIS_POLICIES", str(tmp_path))
    monkeypatch.setattr("sys.stdin", _FakeStdin(b"{ this is not valid json"))
    rc = cli._cmd_hook(_Args("PreToolUse"))
    assert rc == 0
    assert "could not parse" in capsys.readouterr().err.lower()
    rec = json.loads(audit.read_text(encoding="utf-8").splitlines()[-1])
    assert rec["rule"] == "payload-parse-error"
    assert rec["decision"] == "allow"


def test_unparseable_payload_fail_closed_blocks(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_FAIL_CLOSED", "1")
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AEGIS_AUDIT", str(audit))
    monkeypatch.setenv("AEGIS_POLICIES", str(tmp_path))
    monkeypatch.setattr("sys.stdin", _FakeStdin(b"{ bad json"))
    rc = cli._cmd_hook(_Args("PreToolUse"))
    assert rc == 2
    rec = json.loads(audit.read_text(encoding="utf-8").splitlines()[-1])
    assert rec["rule"] == "payload-parse-error"
    assert rec["decision"] == "deny"


def test_unparseable_payload_honors_on_error_deny(monkeypatch, tmp_path):
    monkeypatch.delenv("AEGIS_FAIL_CLOSED", raising=False)
    pol_dir = tmp_path / "pol"
    pol_dir.mkdir()
    (pol_dir / "p.yaml").write_text("on_error: deny\n", encoding="utf-8")
    monkeypatch.setenv("AEGIS_POLICIES", str(pol_dir))
    monkeypatch.setenv("AEGIS_AUDIT", str(tmp_path / "a.jsonl"))
    monkeypatch.setattr("sys.stdin", _FakeStdin(b"not json at all"))
    assert cli._cmd_hook(_Args("PreToolUse")) == 2
