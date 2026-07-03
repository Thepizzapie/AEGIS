"""Evasion resistance — see through obfuscation/indirection; no agent self-escape."""
import base64

from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Policy


def _sh(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def test_interpreter_wrapping_seen_through():
    assert evaluate(_sh('bash -c "rm -rf /tmp/x"'), Policy()).blocked
    assert evaluate(_sh('sh -c "cat ~/.ssh/id_rsa"'), Policy()).blocked


def test_quote_splitting_seen_through():
    assert evaluate(_sh('r"m" -rf /tmp/x'), Policy()).blocked


def test_powershell_encoded_command_blocked():
    b64 = base64.b64encode("rm -rf /".encode("utf-16-le")).decode()
    assert evaluate(_sh(f"powershell -EncodedCommand {b64}"), Policy()).blocked


def test_base64_pipe_to_shell_blocked():
    b64 = base64.b64encode(b"rm -rf /").decode()
    assert evaluate(_sh(f"echo {b64} | base64 -d | sh"), Policy()).blocked


def test_alt_delete_tools_blocked():
    assert evaluate(_sh("find . -name '*.py' -delete"), Policy()).blocked
    assert evaluate(_sh("shred -u secret.key"), Policy()).blocked


def test_sql_hidden_in_interpreter_blocked():
    assert evaluate(_sh('bash -c "psql -c \'DROP TABLE users\'"'), Policy()).blocked


def test_normal_commands_allowed():
    assert not evaluate(_sh("ls -la"), Policy()).blocked
    assert not evaluate(_sh("git status"), Policy()).blocked
    assert not evaluate(_sh("cat README.md"), Policy()).blocked


def test_human_can_override(monkeypatch):
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)
    assert not evaluate(_sh("rm -rf /tmp/x  # aegis-allow"), Policy()).blocked


def test_agent_cannot_self_escape(monkeypatch):
    # a spawned agent appending the override token is ignored
    monkeypatch.setenv("AEGIS_AGENT_NAME", "scout")
    assert evaluate(_sh("rm -rf /tmp/x  # aegis-allow"), Policy()).blocked


def test_evasion_rule_flags_encoded_blob(monkeypatch):
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)
    b64 = base64.b64encode(b"harmless").decode()
    assert evaluate(_sh(f"powershell -enc {b64}"), Policy()).blocked


def test_scan_surface_joins_parts_with_a_statement_boundary():
    """scan_surface's alternate readings (raw / quote-stripped / decoded) are
    independent parts, never a real sequence — joining them with a bare space
    let the tail of one run into the head of the next with no boundary, so a
    guard that scopes a check to 'the same shell statement' (splitting on
    ;/&/|) could see two unrelated parts fuse into one fake statement at that
    seam. Confirms the join now leaves a real separator there."""
    from aegis import normalize

    surface = normalize.scan_surface("echo 'hi' > /tmp/x.txt && cat aegis/rules.py")
    # the quote-stripped duplicate's own head must not run on into the raw
    # part's tail with nothing but a space between them
    assert "rules.py echo" not in surface
    assert "rules.py; echo" in surface or "rules.py;echo" in surface
