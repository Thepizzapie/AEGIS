"""AEGI-3: YAML policy loader + validation + eval semantics."""
import pathlib

from aegis.events import Event, HookEvent
from aegis.engine import evaluate
from aegis.policy import Action
from aegis.loader import load_policy, validate_policy

GOOD = """
default_action: deny
on_error: deny
rules:
  - name: allow-reads
    action: allow
    actions: [read]
    priority: 10
  - name: deny-shell
    action: deny
    actions: [shell]
    message: no shell
"""


def _write(tmp_path, text, name="p.yaml"):
    d = tmp_path / "policies"
    d.mkdir(exist_ok=True)
    (d / name).write_text(text, encoding="utf-8")
    return d


def test_load_and_evaluate(tmp_path):
    pol = load_policy(_write(tmp_path, GOOD))
    assert pol.default_action == Action.DENY
    assert pol.on_error == Action.DENY
    assert len(pol.rules) == 2

    rd = evaluate(Event.make(HookEvent.PRE_TOOL_USE, tool="Read"), pol)
    sh = evaluate(Event.make(HookEvent.PRE_TOOL_USE, tool="Bash"), pol)
    other = evaluate(Event.make(HookEvent.PRE_TOOL_USE, tool="Weird"), pol)
    assert rd.action == Action.ALLOW
    assert sh.blocked and sh.message == "no shell"
    assert other.blocked  # no rule matched -> default deny


LIFECYCLE = """
team:
  require_verification: true
compaction:
  block_auto: true
permission:
  deny_escalation: true
mcp:
  block_elicitation: true
"""


def test_load_lifecycle_knobs(tmp_path):
    """The opt-in lifecycle knobs (team/compaction/permission/mcp) must round-trip
    from YAML onto the Policy so the lifecycle rules that read them can be enabled —
    regression for them silently defaulting to None (dead opt-in)."""
    pol = load_policy(_write(tmp_path, LIFECYCLE))
    assert pol.team == {"require_verification": True}
    assert pol.compaction == {"block_auto": True}
    assert pol.permission == {"deny_escalation": True}
    assert pol.mcp == {"block_elicitation": True}


def test_lifecycle_knobs_enable_rules(tmp_path, monkeypatch):
    """End-to-end: with the knobs set and a spawned agent, the opt-in lifecycle
    rules actually DENY through the engine."""
    monkeypatch.setenv("AEGIS_AGENT_NAME", "spawned")
    pol = load_policy(_write(tmp_path, LIFECYCLE))
    cases = {
        HookEvent.TASK_COMPLETED: "task-completion-gate",
        HookEvent.PRE_COMPACT: "precompact-gate",
        HookEvent.PERMISSION_REQUEST: "permission-escalation",
        HookEvent.ELICITATION: "elicitation-governance",
    }
    matcher = {HookEvent.PRE_COMPACT: "auto"}
    for ev, rule in cases.items():
        d = evaluate(Event.make(ev.value, matcher=matcher.get(ev)), pol)
        assert d.blocked and d.rule == rule, (ev, d)


def test_lifecycle_knobs_absent_by_default(tmp_path):
    """No knobs in YAML -> empty dicts -> opt-in rules abstain (default ALLOW)."""
    pol = load_policy(_write(tmp_path, GOOD))
    assert pol.team == {} and pol.compaction == {}
    assert pol.permission == {} and pol.mcp == {}


def test_validate_ok(tmp_path):
    assert validate_policy(_write(tmp_path, GOOD)) == []
    assert validate_policy(_write(tmp_path, LIFECYCLE)) == []


def test_validate_catches_bad_action(tmp_path):
    d = _write(tmp_path, "rules:\n  - name: x\n    action: nope\n    actions: [shell]\n")
    assert any("action 'nope' invalid" in e for e in validate_policy(d))


def test_validate_catches_unknown_event_and_missing_name(tmp_path):
    d = _write(tmp_path, "rules:\n  - action: deny\n    events: [Nope]\n")
    errs = validate_policy(d)
    assert any("missing 'name'" in e for e in errs)
    assert any("unknown event 'Nope'" in e for e in errs)


def test_validate_catches_duplicate_name(tmp_path):
    d = _write(tmp_path, "rules:\n  - {name: a, action: deny}\n  - {name: a, action: allow}\n")
    assert any("duplicate name 'a'" in e for e in validate_policy(d))


def test_validate_empty_dir(tmp_path):
    d = tmp_path / "empty"
    d.mkdir()
    errs = validate_policy(d)
    assert errs and "no policy files" in errs[0]


def test_repo_example_policy_is_valid():
    # the example shipped in the repo must always validate
    root = pathlib.Path(__file__).resolve().parent.parent
    errs = validate_policy(root / "policies")
    assert errs == [], errs
