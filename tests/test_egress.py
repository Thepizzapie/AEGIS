"""Network egress governance — policy.egress allow/deny host lists."""
from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Policy


def _fetch(url):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="WebFetch", args={"url": url})


def _curl(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def test_no_config_no_opinion():
    assert not evaluate(_fetch("https://anywhere.test/x"), Policy()).blocked


def test_deny_list():
    pol = Policy(egress={"deny": ["*.evil.test", "evil.test"]})
    assert evaluate(_fetch("https://api.evil.test/x"), pol).blocked
    assert not evaluate(_fetch("https://good.test/x"), pol).blocked


def test_default_deny_with_allowlist():
    pol = Policy(egress={"default": "deny", "allow": ["api.github.com", "*.internal"]})
    assert not evaluate(_fetch("https://api.github.com/x"), pol).blocked
    assert not evaluate(_fetch("https://svc.internal/y"), pol).blocked
    assert evaluate(_fetch("https://random.test/z"), pol).blocked


def test_egress_from_shell_url():
    pol = Policy(egress={"deny": ["evil.test"]})
    d = evaluate(_curl("curl https://evil.test/x -o out.txt"), pol)
    assert d.blocked and d.rule == "egress"
