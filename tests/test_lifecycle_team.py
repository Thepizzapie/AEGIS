"""Tests for sub-agent & team governance lifecycle rules (aegis.lifecycle.team)."""
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy
from aegis.lifecycle.team import (
    rule_subagent_spawn_depth,
    rule_task_completion_gate,
    RULES,
)


def _spawn():
    return Event(event=HookEvent.SUBAGENT_START, agent_id="a1", agent_type="worker")


def _completed(verified=None):
    raw = {} if verified is None else {"verified": verified}
    return Event(event=HookEvent.TASK_COMPLETED, agent_id="a1", raw=raw)


def _team_policy(require_verification=True):
    p = Policy()
    p.team = {"require_verification": require_verification}  # set dynamically
    return p


# ---- rule_subagent_spawn_depth -------------------------------------------------

def test_spawn_depth_denies_for_agent(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "claude-1")
    monkeypatch.delenv("AEGIS_ALLOW_SUBAGENTS", raising=False)
    d = rule_subagent_spawn_depth(_spawn())
    assert d is not None and d.action == Action.DENY
    assert d.rule == "subagent-spawn-depth"


def test_spawn_depth_abstains_for_human(monkeypatch):
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)
    monkeypatch.delenv("AEGIS_ALLOW_SUBAGENTS", raising=False)
    assert rule_subagent_spawn_depth(_spawn()) is None


def test_spawn_depth_honors_allow_override(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "claude-1")
    monkeypatch.setenv("AEGIS_ALLOW_SUBAGENTS", "1")
    assert rule_subagent_spawn_depth(_spawn()) is None


def test_spawn_depth_ignores_other_events(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "claude-1")
    monkeypatch.delenv("AEGIS_ALLOW_SUBAGENTS", raising=False)
    ev = Event(event=HookEvent.SUBAGENT_STOP, agent_id="a1")
    assert rule_subagent_spawn_depth(ev) is None


def test_spawn_depth_fail_open(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "claude-1")
    monkeypatch.delenv("AEGIS_ALLOW_SUBAGENTS", raising=False)

    class Boom:
        @property
        def event(self):
            raise RuntimeError("boom")

    assert rule_subagent_spawn_depth(Boom()) is None


# ---- rule_task_completion_gate -------------------------------------------------

def test_completion_gate_denies_unverified_when_required():
    d = rule_task_completion_gate(_completed(verified=False), _team_policy(True))
    assert d is not None and d.action == Action.DENY
    assert d.rule == "task-completion-gate"


def test_completion_gate_denies_when_verified_field_absent():
    d = rule_task_completion_gate(_completed(verified=None), _team_policy(True))
    assert d is not None and d.action == Action.DENY


def test_completion_gate_allows_verified():
    assert rule_task_completion_gate(_completed(verified=True), _team_policy(True)) is None


def test_completion_gate_abstains_without_opt_in():
    assert rule_task_completion_gate(_completed(verified=False), _team_policy(False)) is None


def test_completion_gate_abstains_with_no_team_config():
    # Policy has no `team` attribute at all -> getattr default -> None.
    assert rule_task_completion_gate(_completed(verified=False), Policy()) is None


def test_completion_gate_abstains_with_no_policy():
    assert rule_task_completion_gate(_completed(verified=False), None) is None


def test_completion_gate_ignores_other_events():
    ev = Event(event=HookEvent.TASK_CREATED, agent_id="a1", raw={"verified": False})
    assert rule_task_completion_gate(ev, _team_policy(True)) is None


def test_completion_gate_fail_open():
    class Boom:
        @property
        def event(self):
            raise RuntimeError("boom")

    assert rule_task_completion_gate(Boom(), _team_policy(True)) is None


# ---- RULES tuple ---------------------------------------------------------------

def test_rules_tuple_contents():
    assert RULES == (rule_subagent_spawn_depth, rule_task_completion_gate)


def test_all_rules_can_return_a_decision():
    # Contract: no always-None rules registered. Each rule must be able to DENY.
    import os

    os.environ["AEGIS_AGENT_NAME"] = "claude-1"
    os.environ.pop("AEGIS_ALLOW_SUBAGENTS", None)
    try:
        assert rule_subagent_spawn_depth(_spawn()) is not None
    finally:
        os.environ.pop("AEGIS_AGENT_NAME", None)
    assert rule_task_completion_gate(_completed(verified=False), _team_policy(True)) is not None
