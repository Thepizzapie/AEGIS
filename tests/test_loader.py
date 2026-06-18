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


def test_validate_ok(tmp_path):
    assert validate_policy(_write(tmp_path, GOOD)) == []


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
