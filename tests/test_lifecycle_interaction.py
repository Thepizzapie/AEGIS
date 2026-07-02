"""AEGI lifecycle: interaction & MCP-input governance rules.

Covers rule_permission_escalation (PermissionRequest) and
rule_elicitation_governance (Elicitation / ElicitationResult): deny only when a
spawned agent escalates AND policy opts in; abstain otherwise; fail-open.
"""
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy
from aegis.lifecycle import interaction
from aegis.lifecycle.interaction import (
    rule_permission_escalation,
    rule_elicitation_governance,
    RULES,
)


def _agent(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "spawned-bot")


def _human(monkeypatch):
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)


# ---- RULES wiring -------------------------------------------------------------

def test_rules_tuple_is_the_two_enforcement_points():
    assert RULES == (rule_permission_escalation, rule_elicitation_governance)


def test_no_post_tool_use_failure_rule():
    # PostToolUseFailure is audit-only: no rule references it.
    src = interaction.__doc__ or ""
    assert "PostToolUseFailure" in src  # documented as audit-only
    for rule in RULES:
        assert rule(Event(event=HookEvent.POST_TOOL_USE_FAILURE, tool="Bash"), Policy()) is None


# ---- rule_permission_escalation ----------------------------------------------

def test_permission_denies_for_spawned_agent_with_opt_in(monkeypatch):
    _agent(monkeypatch)
    p = Policy()
    p.permission = {"deny_escalation": True}
    ev = Event(event=HookEvent.PERMISSION_REQUEST, tool="Bash")
    d = rule_permission_escalation(ev, p)
    assert d is not None and d.action == Action.DENY
    assert d.rule == "permission-escalation"


def test_permission_abstains_without_opt_in(monkeypatch):
    _agent(monkeypatch)
    ev = Event(event=HookEvent.PERMISSION_REQUEST, tool="Bash")
    assert rule_permission_escalation(ev, Policy()) is None


def test_permission_abstains_for_human_even_with_opt_in(monkeypatch):
    _human(monkeypatch)
    p = Policy()
    p.permission = {"deny_escalation": True}
    ev = Event(event=HookEvent.PERMISSION_REQUEST, tool="Bash")
    assert rule_permission_escalation(ev, p) is None


def test_permission_ignores_other_events(monkeypatch):
    _agent(monkeypatch)
    p = Policy()
    p.permission = {"deny_escalation": True}
    ev = Event(event=HookEvent.ELICITATION, tool="mcp__srv__ask")
    assert rule_permission_escalation(ev, p) is None


def test_permission_fail_open_on_bad_policy(monkeypatch):
    _agent(monkeypatch)

    class Boom:
        @property
        def permission(self):
            raise RuntimeError("boom")

    ev = Event(event=HookEvent.PERMISSION_REQUEST, tool="Bash")
    assert rule_permission_escalation(ev, Boom()) is None


# ---- rule_elicitation_governance ---------------------------------------------

def test_elicitation_denies_for_spawned_agent_with_opt_in(monkeypatch):
    _agent(monkeypatch)
    p = Policy()
    p.mcp = {"block_elicitation": True}
    ev = Event(event=HookEvent.ELICITATION, tool="mcp__srv__ask")
    d = rule_elicitation_governance(ev, p)
    assert d is not None and d.action == Action.DENY
    assert d.rule == "elicitation-governance"


def test_elicitation_result_also_denied_with_opt_in(monkeypatch):
    _agent(monkeypatch)
    p = Policy()
    p.mcp = {"block_elicitation": True}
    ev = Event(event=HookEvent.ELICITATION_RESULT, tool="mcp__srv__ask")
    d = rule_elicitation_governance(ev, p)
    assert d is not None and d.action == Action.DENY


def test_elicitation_abstains_without_opt_in(monkeypatch):
    _agent(monkeypatch)
    ev = Event(event=HookEvent.ELICITATION, tool="mcp__srv__ask")
    assert rule_elicitation_governance(ev, Policy()) is None


def test_elicitation_abstains_for_human_even_with_opt_in(monkeypatch):
    _human(monkeypatch)
    p = Policy()
    p.mcp = {"block_elicitation": True}
    ev = Event(event=HookEvent.ELICITATION, tool="mcp__srv__ask")
    assert rule_elicitation_governance(ev, p) is None


def test_elicitation_ignores_other_events(monkeypatch):
    _agent(monkeypatch)
    p = Policy()
    p.mcp = {"block_elicitation": True}
    ev = Event(event=HookEvent.PERMISSION_REQUEST, tool="Bash")
    assert rule_elicitation_governance(ev, p) is None


def test_elicitation_fail_open_on_bad_policy(monkeypatch):
    _agent(monkeypatch)

    class Boom:
        @property
        def mcp(self):
            raise RuntimeError("boom")

    ev = Event(event=HookEvent.ELICITATION, tool="mcp__srv__ask")
    assert rule_elicitation_governance(ev, Boom()) is None
