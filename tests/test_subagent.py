"""Sub-agent spawn governance — configurable."""
from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Policy


def _task():
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Task", args={})


def test_human_or_orchestrator_may_spawn(monkeypatch):
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)
    assert not evaluate(_task(), Policy()).blocked


def test_spawned_agent_is_blocked(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "scout")
    monkeypatch.delenv("AEGIS_ALLOW_SUBAGENTS", raising=False)
    d = evaluate(_task(), Policy())
    assert d.blocked and d.rule == "subagent-spawn"


def test_explicit_allow_env(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "scout")
    monkeypatch.setenv("AEGIS_ALLOW_SUBAGENTS", "1")
    assert not evaluate(_task(), Policy()).blocked


def test_mcp_named_task_or_agent_still_governed(monkeypatch):
    # QA round 10: aegis.mcp.check now defaults every call to ActionClass.MCP
    # unconditionally (round 9 fix) — a genuine sub-agent-spawning MCP tool
    # literally named "task"/"agent" no longer auto-classifies as SUBAGENT,
    # so this rule's `ev.action != ActionClass.SUBAGENT` check alone silently
    # stopped firing for it (verified via the REAL aegis.mcp.check entry
    # point, which is where this regression actually surfaced). Checked by
    # tool NAME as a second condition (deliberately not by changing the
    # Event's action, which would reopen the round-9 containment bypass for
    # those same names).
    from aegis import mcp
    monkeypatch.setenv("AEGIS_AGENT_NAME", "scout")
    monkeypatch.delenv("AEGIS_ALLOW_SUBAGENTS", raising=False)
    for tool in ("task", "agent"):
        d = mcp.check(tool, {"prompt": "do work"})
        assert d.blocked and d.rule == "subagent-spawn", tool
    # the mcp__server__task / mcp__server__agent shape (classify() already
    # returns MCP for any mcp__-prefixed name, before this fix existed)
    for tool in ("mcp__orchestrator__task", "mcp__team__agent"):
        ev = Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args={"prompt": "do work"})
        d = evaluate(ev, Policy())
        assert d.blocked and d.rule == "subagent-spawn", tool


def test_mcp_named_task_or_agent_containment_unaffected(monkeypatch):
    # The fix above must not reopen round 9's bypass: through the real
    # aegis.mcp.check entry point (which defaults every call's ActionClass
    # to MCP, unlike a raw Event.make(tool="agent") which would still
    # auto-classify via events.classify() to SUBAGENT), containment scanning
    # for these same tool names has to keep working.
    from aegis import mcp
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)
    d = mcp.check("agent", {"path": "/home/user/.ssh/id_rsa"})
    assert d.blocked and d.rule == "containment-credentials"
