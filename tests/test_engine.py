"""AEGI-1: engine + event model + policy matching."""
from aegis.events import Event, HookEvent, ActionClass, classify
from aegis.policy import Policy, Rule, Action
from aegis.engine import evaluate, safe_evaluate


def _ev(tool="Bash", **kw):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, **kw)


def test_classify_taxonomy():
    assert classify("Bash") == ActionClass.SHELL
    assert classify("Edit") == ActionClass.EDIT
    assert classify("Write") == ActionClass.WRITE
    assert classify("Task") == ActionClass.SUBAGENT
    assert classify("mcp__myserver__git_commit") == ActionClass.MCP
    assert classify(None) == ActionClass.OTHER
    assert classify("SomethingUnknown") == ActionClass.OTHER


def test_default_allow_when_no_rules():
    d = evaluate(_ev(), Policy())
    assert d.action == Action.ALLOW
    assert not d.blocked


def test_default_deny():
    assert evaluate(_ev(), Policy(default_action=Action.DENY)).blocked


def test_deny_by_action_class():
    pol = Policy(rules=[Rule(name="no-shell", action=Action.DENY,
                             actions=[ActionClass.SHELL], message="no shell")])
    d = evaluate(_ev(tool="Bash"), pol)
    assert d.blocked and d.rule == "no-shell" and d.message == "no shell"
    # a non-shell action is unaffected
    assert not evaluate(_ev(tool="Read"), pol).blocked


def test_tool_glob_match():
    pol = Policy(rules=[Rule(name="no-git-mcp", action=Action.DENY,
                             tools=["mcp__*__git_*"])])
    assert evaluate(_ev(tool="mcp__myserver__git_push"), pol).blocked
    assert not evaluate(_ev(tool="mcp__myserver__search"), pol).blocked


def test_priority_wins():
    pol = Policy(rules=[
        Rule(name="allow-shell", action=Action.ALLOW,
             actions=[ActionClass.SHELL], priority=10),
        Rule(name="deny-shell", action=Action.DENY,
             actions=[ActionClass.SHELL], priority=5),
    ])
    assert evaluate(_ev(tool="Bash"), pol).action == Action.ALLOW
    assert evaluate(_ev(tool="Bash"), pol).rule == "allow-shell"


def test_argument_pattern():
    pol = Policy(rules=[Rule(name="no-shadow", action=Action.DENY, tools=["Read"],
                             argument_patterns={"file_path": "*/etc/shadow*"})])
    blocked = evaluate(Event.make(HookEvent.PRE_TOOL_USE, tool="Read",
                                  args={"file_path": "/etc/shadow"}), pol)
    ok = evaluate(Event.make(HookEvent.PRE_TOOL_USE, tool="Read",
                             args={"file_path": "/home/x"}), pol)
    assert blocked.blocked and not ok.blocked


def test_argument_pattern_list_matches_any():
    pol = Policy(rules=[Rule(name="del", action=Action.DENY, actions=[ActionClass.SHELL],
        argument_patterns={"command": ["*rm -rf*", "*remove-item*-recurse*-force*"]})])

    def ev(cmd):
        return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})

    assert evaluate(ev("sudo rm -rf /"), pol).blocked
    assert evaluate(ev("Remove-Item -Recurse -Force x"), pol).blocked  # other shell
    assert not evaluate(ev("ls -la"), pol).blocked


def test_event_scope():
    pol = Policy(rules=[Rule(name="stop-only", action=Action.DENY,
                             events=[HookEvent.STOP])])
    assert not evaluate(_ev(tool="Bash"), pol).blocked
    assert evaluate(Event.make(HookEvent.STOP), pol).blocked


def test_roles_scope():
    pol = Policy(rules=[
        Rule(name="admin-shell", action=Action.ALLOW, actions=[ActionClass.SHELL],
             roles=["admin"], priority=100),
        Rule(name="deny-shell", action=Action.DENY, actions=[ActionClass.SHELL]),
    ])
    assert not evaluate(_ev(tool="Bash", roles=["admin"]), pol).blocked
    assert evaluate(_ev(tool="Bash", roles=["dev"]), pol).blocked


def test_safe_evaluate_never_raises():
    # Every rule fails OPEN, so a malformed event never raises and never bricks
    # the agent — it falls through to the default action.
    pol = Policy(rules=[Rule(name="bad", action=Action.DENY, tools=["*"])])
    d = safe_evaluate("not-an-event", pol)  # must not raise
    assert d.action == Action.ALLOW
