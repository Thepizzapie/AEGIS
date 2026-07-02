"""Stop verification-gate tests (lifecycle.session.rule_stop_verification_gate).

The accountability property under test: with ``completion.require_tests`` on, a
session that mutated files cannot stop until the audit trail shows a test run
AFTER the last mutation — evidence, not self-report. And it can never wedge a
turn: stop_hook_active, no session id, or no mutations all abstain.
"""
import json

import pytest

from aegis.events import BLOCKABLE, Event, HookEvent
from aegis.lifecycle.session import rule_stop_verification_gate
from aegis.policy import Action, Policy


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_AUDIT", str(tmp_path / "audit.jsonl"))


def _policy(**cfg):
    p = Policy()
    p.completion = cfg or {"require_tests": True}
    return p


def _stop(session="s1", raw=None):
    return Event(event=HookEvent.STOP, session_id=session, raw=raw or {})


def _write_audit(tmp_path, records):
    lines = [json.dumps(r) for r in records]
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n",
                                          encoding="utf-8")


def _edit(session="s1"):
    return {"session_id": session, "event": "PostToolUse", "action": "edit",
            "decision": "allow", "tool": "Edit", "args": {"file_path": "a.py"}}


def _shell(cmd, session="s1", event="PostToolUse"):
    return {"session_id": session, "event": event, "action": "shell",
            "decision": "allow", "tool": "Bash", "args": {"command": cmd}}


def test_stop_is_blockable():
    assert HookEvent.STOP in BLOCKABLE


def test_denies_edits_without_any_test_run(tmp_path):
    _write_audit(tmp_path, [_edit()])
    d = rule_stop_verification_gate(_stop(), _policy())
    assert d is not None
    assert d.action == Action.DENY
    assert d.rule == "stop-verification-gate"


def test_allows_when_tests_ran_after_last_edit(tmp_path):
    _write_audit(tmp_path, [_edit(), _shell("python -m pytest -q")])
    assert rule_stop_verification_gate(_stop(), _policy()) is None


def test_denies_when_tests_ran_before_last_edit(tmp_path):
    # tests, THEN another edit: the final state is unverified.
    _write_audit(tmp_path, [_shell("pytest"), _edit()])
    d = rule_stop_verification_gate(_stop(), _policy())
    assert d is not None and d.action == Action.DENY


def test_failed_test_run_does_not_satisfy(tmp_path):
    # the runner blew up -> PostToolUseFailure, not PostToolUse: still unverified.
    _write_audit(tmp_path, [_edit(),
                            _shell("pytest", event="PostToolUseFailure")])
    d = rule_stop_verification_gate(_stop(), _policy())
    assert d is not None and d.action == Action.DENY


def test_abstains_without_opt_in(tmp_path):
    _write_audit(tmp_path, [_edit()])
    assert rule_stop_verification_gate(_stop(), Policy()) is None


def test_abstains_when_session_made_no_mutations(tmp_path):
    _write_audit(tmp_path, [_shell("ls")])
    assert rule_stop_verification_gate(_stop(), _policy()) is None


def test_abstains_on_stop_hook_active(tmp_path):
    # the runtime is already continuing from a gate deny — never loop the turn.
    _write_audit(tmp_path, [_edit()])
    ev = _stop(raw={"stop_hook_active": True})
    assert rule_stop_verification_gate(ev, _policy()) is None


def test_abstains_without_session_id(tmp_path):
    _write_audit(tmp_path, [_edit()])
    assert rule_stop_verification_gate(_stop(session=None), _policy()) is None


def test_other_sessions_edits_do_not_gate_this_one(tmp_path):
    _write_audit(tmp_path, [_edit(session="other")])
    assert rule_stop_verification_gate(_stop(), _policy()) is None


def test_custom_patterns_override_builtin(tmp_path):
    _write_audit(tmp_path, [_edit(), _shell("./run-my-checks.sh")])
    p = _policy(require_tests=True, patterns=[r"run-my-checks\.sh"])
    assert rule_stop_verification_gate(_stop(), p) is None
    # and the builtin pytest pattern no longer satisfies a custom policy
    _write_audit(tmp_path, [_edit(), _shell("pytest")])
    d = rule_stop_verification_gate(_stop(), p)
    assert d is not None and d.action == Action.DENY


def test_bad_custom_pattern_falls_back_to_builtin(tmp_path):
    _write_audit(tmp_path, [_edit(), _shell("pytest")])
    p = _policy(require_tests=True, patterns=["("])  # invalid regex
    assert rule_stop_verification_gate(_stop(), p) is None


def test_denied_mutation_does_not_arm_the_gate(tmp_path):
    _write_audit(tmp_path, [{"session_id": "s1", "event": "PostToolUse",
                             "action": "edit", "decision": "deny",
                             "tool": "Edit", "args": {}}])
    assert rule_stop_verification_gate(_stop(), _policy()) is None


def test_abstains_on_non_stop_event(tmp_path):
    _write_audit(tmp_path, [_edit()])
    ev = Event(event=HookEvent.SESSION_END, session_id="s1")
    assert rule_stop_verification_gate(ev, _policy()) is None


def test_fail_open_on_missing_audit():
    # no audit file at all -> no evidence of mutations -> abstain, don't brick.
    assert rule_stop_verification_gate(_stop(), _policy()) is None


def test_loader_roundtrips_completion_knob(tmp_path):
    from aegis.loader import load_policy
    (tmp_path / "policy.yaml").write_text(
        "completion:\n  require_tests: true\n", encoding="utf-8")
    p = load_policy(tmp_path)
    assert p.completion == {"require_tests": True}


def test_fires_end_to_end_through_engine(tmp_path):
    from aegis.engine import evaluate
    _write_audit(tmp_path, [_edit()])
    d = evaluate(_stop(), _policy())
    assert d.action == Action.DENY
    assert d.rule == "stop-verification-gate"
