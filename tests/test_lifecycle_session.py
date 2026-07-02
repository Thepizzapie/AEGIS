"""Tests for session & compaction lifecycle rules (aegis.lifecycle.session)."""
from aegis.events import BLOCKABLE, Event, HookEvent
from aegis.policy import Action, Policy
from aegis.lifecycle.session import RULES, rule_precompact_gate


def _precompact(matcher):
    return Event(event=HookEvent.PRE_COMPACT, matcher=matcher)


def test_precompact_is_blockable():
    # The gate only makes sense because PreCompact is actually enforceable.
    assert HookEvent.PRE_COMPACT in BLOCKABLE


def test_deny_auto_compaction_when_opted_in():
    p = Policy()
    p.compaction = {"block_auto": True}
    d = rule_precompact_gate(_precompact("auto"), p)
    assert d is not None
    assert d.action == Action.DENY
    assert d.blocked is True
    assert d.rule == "precompact-gate"


def test_manual_compaction_allowed_even_when_opted_in():
    p = Policy()
    p.compaction = {"block_auto": True}
    assert rule_precompact_gate(_precompact("manual"), p) is None


def test_abstain_without_opt_in():
    assert rule_precompact_gate(_precompact("auto"), Policy()) is None


def test_abstain_when_compaction_cfg_lacks_block_auto():
    p = Policy()
    p.compaction = {"block_auto": False}
    assert rule_precompact_gate(_precompact("auto"), p) is None


def test_abstain_on_non_precompact_event():
    ev = Event(event=HookEvent.SESSION_END, matcher="auto")
    p = Policy()
    p.compaction = {"block_auto": True}
    assert rule_precompact_gate(ev, p) is None


def test_fail_open_on_bad_policy():
    # getattr returns a non-dict -> rule must abstain, not raise.
    class Boom:
        @property
        def compaction(self):
            raise RuntimeError("boom")

    assert rule_precompact_gate(_precompact("auto"), Boom()) is None
    # Non-dict compaction value is also tolerated.
    p = Policy()
    p.compaction = "nope"
    assert rule_precompact_gate(_precompact("auto"), p) is None


def test_observational_events_not_blocked_by_rules():
    # Every RULES function must abstain on the audit-only events in this domain.
    p = Policy()
    p.compaction = {"block_auto": True}
    for ev_name in (HookEvent.SESSION_END, HookEvent.POST_COMPACT,
                    HookEvent.STOP_FAILURE, HookEvent.NOTIFICATION):
        ev = Event(event=ev_name, matcher="auto")
        for rule in RULES:
            assert rule(ev, p) is None, f"{rule.__name__} blocked {ev_name}"
