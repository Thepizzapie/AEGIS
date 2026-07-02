"""Failure-loop guard tests (aegis.failures ledger + rules.rule_failure_loop).

The reliability property under test: the Nth identical retry of a call that
already failed N times is denied at PreToolUse (blockable), with human-only
escapes; anything about the call changing — args, tool, or an eventual
success — re-arms cleanly.
"""
import pytest

from aegis import failures
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy
from aegis.rules import rule_failure_loop


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    monkeypatch.setenv("AEGIS_AUDIT", str(tmp_path / "audit.jsonl"))
    monkeypatch.delenv("AEGIS_ALLOW_RETRY", raising=False)
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)
    monkeypatch.delenv("AEGIS_SESSION_ID", raising=False)


def _pre(tool="Bash", args=None, session="s1"):
    return Event(event=HookEvent.PRE_TOOL_USE, tool=tool,
                 action=ActionClass.SHELL, args=args or {"command": "make"},
                 session_id=session)


def _fail(tool="Bash", args=None, session="s1"):
    return Event(event=HookEvent.POST_TOOL_USE_FAILURE, tool=tool,
                 action=ActionClass.SHELL, args=args or {"command": "make"},
                 session_id=session)


def _ok(tool="Bash", args=None, session="s1"):
    return Event(event=HookEvent.POST_TOOL_USE, tool=tool,
                 action=ActionClass.SHELL, args=args or {"command": "make"},
                 session_id=session)


def _fail_n(n, **kw):
    for _ in range(n):
        failures.observe(_fail(**kw))


# ---- ledger ---------------------------------------------------------------------

def test_signature_is_stable_and_arg_sensitive():
    a = failures.signature("Bash", {"command": "make"})
    assert a == failures.signature("Bash", {"command": "make"})
    assert a != failures.signature("Bash", {"command": "make test"})
    assert a != failures.signature("Edit", {"command": "make"})


def test_failure_count_counts_consecutive_fails():
    _fail_n(2)
    sig = failures.signature("Bash", {"command": "make"})
    assert failures.failure_count("s1", sig) == 2


def test_success_clears_the_streak():
    _fail_n(3)
    failures.observe(_ok())
    sig = failures.signature("Bash", {"command": "make"})
    assert failures.failure_count("s1", sig) == 0


def test_success_of_unseen_signature_writes_nothing(tmp_path):
    failures.observe(_ok())
    assert not (tmp_path / "failures").exists()


def test_sessions_are_isolated():
    _fail_n(3, session="s1")
    sig = failures.signature("Bash", {"command": "make"})
    assert failures.failure_count("s2", sig) == 0


def test_observe_ignores_other_events():
    failures.observe(Event(event=HookEvent.PRE_TOOL_USE, tool="Bash",
                           args={"command": "make"}, session_id="s1"))
    sig = failures.signature("Bash", {"command": "make"})
    assert failures.failure_count("s1", sig) == 0


# ---- rule -----------------------------------------------------------------------

def test_abstains_below_threshold():
    _fail_n(2)
    assert rule_failure_loop(_pre(), Policy()) is None


def test_denies_at_threshold():
    _fail_n(3)
    d = rule_failure_loop(_pre(), Policy())
    assert d is not None
    assert d.action == Action.DENY
    assert d.rule == "failure-loop"
    assert "failed 3" in d.message


def test_changed_args_start_fresh():
    _fail_n(3)
    d = rule_failure_loop(_pre(args={"command": "make -j4"}), Policy())
    assert d is None


def test_success_rearms():
    _fail_n(3)
    failures.observe(_ok())
    assert rule_failure_loop(_pre(), Policy()) is None


def test_max_repeats_configurable():
    _fail_n(1)
    p = Policy()
    p.failures = {"max_repeats": 1}
    d = rule_failure_loop(_pre(), p)
    assert d is not None and d.action == Action.DENY


def test_ask_mode():
    _fail_n(3)
    p = Policy()
    p.failures = {"mode": "ask"}
    d = rule_failure_loop(_pre(), p)
    assert d is not None and d.action == Action.ASK


def test_off_mode_and_yaml_false():
    _fail_n(5)
    for mode in ("off", False):
        p = Policy()
        p.failures = {"mode": mode}
        assert rule_failure_loop(_pre(), p) is None


def test_monitor_mode_allows_but_audits(tmp_path):
    _fail_n(3)
    p = Policy()
    p.failures = {"mode": "monitor"}
    assert rule_failure_loop(_pre(), p) is None
    audit = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "failure-loop-monitor" in audit


def test_env_override(monkeypatch):
    _fail_n(3)
    monkeypatch.setenv("AEGIS_ALLOW_RETRY", "1")
    assert rule_failure_loop(_pre(), Policy()) is None


def test_human_shell_override_allowed_agent_not(monkeypatch):
    _fail_n(3, args={"command": "make # aegis-allow"})
    ev = _pre(args={"command": "make # aegis-allow"})
    assert rule_failure_loop(ev, Policy()) is None  # human may wave past
    monkeypatch.setenv("AEGIS_AGENT_NAME", "bot")
    d = rule_failure_loop(ev, Policy())
    assert d is not None and d.action == Action.DENY  # spawned agent may not


def test_abstains_on_non_pre_tool_use():
    _fail_n(5)
    assert rule_failure_loop(_fail(), Policy()) is None


def test_loader_roundtrips_failures_knob(tmp_path):
    from aegis.loader import load_policy
    (tmp_path / "policy.yaml").write_text(
        "failures:\n  mode: ask\n  max_repeats: 5\n", encoding="utf-8")
    p = load_policy(tmp_path)
    assert p.failures == {"mode": "ask", "max_repeats": 5}


def test_fires_end_to_end_through_engine():
    from aegis.engine import evaluate
    _fail_n(3)
    d = evaluate(_pre(), Policy())
    assert d.action == Action.DENY
    assert d.rule == "failure-loop"
