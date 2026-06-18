"""Custom guard plugins — orgs / MCP providers register their own rules."""
from aegis import plugins
from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Policy, Action, Decision


def setup_function():
    plugins.reset()


def teardown_function():
    plugins.reset()


def _cmd(c):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": c})


def test_registered_rule_runs_in_engine():
    def block_foo(ev, policy):
        if (ev.args or {}).get("command") == "foo":
            return Decision(Action.DENY, "no-foo", "no foo")
        return None
    plugins.register_rule(block_foo)
    assert evaluate(_cmd("foo"), Policy()).rule == "no-foo"
    assert not evaluate(_cmd("bar"), Policy()).blocked


def test_load_modules_exposing_RULES(tmp_path, monkeypatch):
    (tmp_path / "myplugin.py").write_text(
        "from aegis.policy import Decision, Action\n"
        "def r(ev, policy):\n"
        "    if (ev.args or {}).get('command') == 'zap':\n"
        "        return Decision(Action.DENY, 'zap', 'no zap')\n"
        "    return None\n"
        "RULES = [r]\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    plugins.load_modules(["myplugin"])
    assert evaluate(_cmd("zap"), Policy()).blocked


def test_broken_plugin_is_ignored():
    plugins.load_modules(["this_module_does_not_exist_xyz"])  # must not raise
    assert plugins.active_rules() == []
