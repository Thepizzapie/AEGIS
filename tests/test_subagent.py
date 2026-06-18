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
