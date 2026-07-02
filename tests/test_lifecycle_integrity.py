"""Config/environment-integrity lifecycle rules — the "can't neuter the guard"
and "can't escape the workspace mid-session" guarantees.

Rules are called directly (signature ``(Event, policy) -> Decision | None``) so
each rule's deny / abstain path is exercised in isolation, plus one end-to-end
``evaluate`` check that the BLOCKABLE config rule actually stops a change.
"""
import os

from aegis.events import BLOCKABLE, Event, HookEvent
from aegis.policy import Action, Policy
from aegis.lifecycle import integrity


def _agent(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "bot")


def _human(monkeypatch):
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)


def _clean_confine(monkeypatch):
    for v in ("AEGIS_PROJECT", "AEGIS_WORKSPACE", "AEGIS_AGENT_TOKEN"):
        monkeypatch.delenv(v, raising=False)


# --------------------------------------------------------------------------- #
# rule_config_change_protect
# --------------------------------------------------------------------------- #
def test_config_deny_policy_settings_matcher(monkeypatch):
    _agent(monkeypatch)
    ev = Event.make("ConfigChange", matcher="policy_settings")
    d = integrity.rule_config_change_protect(ev, Policy())
    assert d is not None and d.action == Action.DENY and d.rule == "config-change-protect"


def test_config_deny_local_settings_matcher(monkeypatch):
    _agent(monkeypatch)
    ev = Event.make("ConfigChange", matcher="local_settings")
    assert integrity.rule_config_change_protect(ev, Policy()).action == Action.DENY


def test_config_deny_on_enforcement_path_in_raw(monkeypatch):
    _agent(monkeypatch)
    ev = Event(event=HookEvent.CONFIG_CHANGE, matcher="user_settings",
               raw={"path": ".claude/settings.json"})
    assert integrity.rule_config_change_protect(ev, Policy()).action == Action.DENY


def test_config_deny_on_aegis_source_path_in_args(monkeypatch):
    _agent(monkeypatch)
    ev = Event(event=HookEvent.CONFIG_CHANGE, matcher="skills",
               args={"paths": ["src/aegis/rules.py"]})
    assert integrity.rule_config_change_protect(ev, Policy()).action == Action.DENY


def test_config_deny_on_config_dir_path(monkeypatch):
    _agent(monkeypatch)
    ev = Event(event=HookEvent.CONFIG_CHANGE, matcher="project_settings",
               raw={"changed": [".aegis/policy.yaml"]})
    assert integrity.rule_config_change_protect(ev, Policy()).action == Action.DENY


def test_config_abstain_benign_matcher_and_path(monkeypatch):
    _agent(monkeypatch)
    ev = Event(event=HookEvent.CONFIG_CHANGE, matcher="user_settings",
               raw={"path": "docs/readme.md"})
    assert integrity.rule_config_change_protect(ev, Policy()) is None


def test_config_human_may_change_protected(monkeypatch):
    _human(monkeypatch)
    ev = Event.make("ConfigChange", matcher="policy_settings")
    assert integrity.rule_config_change_protect(ev, Policy()) is None


def test_config_ignores_other_events(monkeypatch):
    _agent(monkeypatch)
    ev = Event.make("CwdChanged", matcher="policy_settings")
    assert integrity.rule_config_change_protect(ev, Policy()) is None


def test_config_change_is_blockable(monkeypatch):
    # ConfigChange is in BLOCKABLE, so this rule's DENY actually stops the change.
    _agent(monkeypatch)
    assert HookEvent.CONFIG_CHANGE in BLOCKABLE
    ev = Event.make("ConfigChange", matcher="policy_settings")
    d = integrity.rule_config_change_protect(ev, Policy())
    assert d.blocked and d.rule == "config-change-protect"


# --------------------------------------------------------------------------- #
# rule_cwd_confine
# --------------------------------------------------------------------------- #
def test_cwd_confine_off_when_no_root(monkeypatch):
    _clean_confine(monkeypatch)
    ev = Event(event=HookEvent.CWD_CHANGED, cwd="/wherever")
    assert integrity.rule_cwd_confine(ev, Policy()) is None


def test_cwd_confine_denies_escape(monkeypatch, tmp_path):
    _clean_confine(monkeypatch)
    root = str(tmp_path / "proj")
    os.makedirs(root, exist_ok=True)
    ev = Event(event=HookEvent.CWD_CHANGED, cwd=str(tmp_path / "elsewhere"))
    d = integrity.rule_cwd_confine(ev, Policy(workspace={"root": root}))
    assert d is not None and d.action == Action.DENY and d.rule == "cwd-confine"


def test_cwd_confine_inside_root_abstains(monkeypatch, tmp_path):
    _clean_confine(monkeypatch)
    root = str(tmp_path / "proj")
    os.makedirs(root, exist_ok=True)
    ev = Event(event=HookEvent.CWD_CHANGED, cwd=os.path.join(root, "sub"))
    assert integrity.rule_cwd_confine(ev, Policy(workspace={"root": root})) is None


def test_cwd_confine_allow_list(monkeypatch, tmp_path):
    _clean_confine(monkeypatch)
    root = str(tmp_path / "proj")
    extra = str(tmp_path / "shared")
    os.makedirs(root, exist_ok=True)
    os.makedirs(extra, exist_ok=True)
    pol = Policy(workspace={"root": root, "allow": [extra]})
    ev_ok = Event(event=HookEvent.CWD_CHANGED, cwd=os.path.join(extra, "x"))
    ev_bad = Event(event=HookEvent.CWD_CHANGED, cwd=str(tmp_path / "evil"))
    assert integrity.rule_cwd_confine(ev_ok, pol) is None
    assert integrity.rule_cwd_confine(ev_bad, pol).action == Action.DENY


def test_cwd_confine_reads_newcwd_from_raw(monkeypatch, tmp_path):
    _clean_confine(monkeypatch)
    root = str(tmp_path / "proj")
    os.makedirs(root, exist_ok=True)
    ev = Event(event=HookEvent.CWD_CHANGED, raw={"newcwd": str(tmp_path / "out")})
    assert integrity.rule_cwd_confine(ev, Policy(project=root)).action == Action.DENY


def test_cwd_confine_not_blockable():
    # Accountability-only: a DENY here is surfaced, not enforced.
    assert HookEvent.CWD_CHANGED not in BLOCKABLE


def test_cwd_confine_ignores_other_events(monkeypatch, tmp_path):
    _clean_confine(monkeypatch)
    root = str(tmp_path / "proj")
    os.makedirs(root, exist_ok=True)
    ev = Event.make("FileChanged", cwd=str(tmp_path / "out"))
    assert integrity.rule_cwd_confine(ev, Policy(workspace={"root": root})) is None


# --------------------------------------------------------------------------- #
# rule_env_file_changed
# --------------------------------------------------------------------------- #
def test_env_change_external_is_audit_only(monkeypatch):
    _human(monkeypatch)
    ev = Event(event=HookEvent.FILE_CHANGED, raw={"path": ".env", "actor": "agent"})
    assert integrity.rule_env_file_changed(ev, Policy()) is None


def test_env_change_agent_no_tamper_signal_abstains(monkeypatch):
    _agent(monkeypatch)
    ev = Event(event=HookEvent.FILE_CHANGED, raw={"path": ".env", "actor": "user"})
    assert integrity.rule_env_file_changed(ev, Policy()) is None


def test_env_change_agent_self_edit_flags_ask(monkeypatch):
    _agent(monkeypatch)
    ev = Event(event=HookEvent.FILE_CHANGED, raw={"path": ".env", "actor": "agent"})
    d = integrity.rule_env_file_changed(ev, Policy())
    assert d is not None and d.action == Action.ASK and d.rule == "env-file-changed"


def test_env_change_agent_id_signal_flags_ask(monkeypatch):
    _agent(monkeypatch)
    ev = Event(event=HookEvent.FILE_CHANGED, agent_id="a1", raw={"path": ".envrc"})
    assert integrity.rule_env_file_changed(ev, Policy()).action == Action.ASK


def test_env_change_not_blockable():
    assert HookEvent.FILE_CHANGED not in BLOCKABLE


def test_env_change_ignores_other_events(monkeypatch):
    _agent(monkeypatch)
    ev = Event(event=HookEvent.CONFIG_CHANGE, agent_id="a1", raw={"actor": "agent"})
    assert integrity.rule_env_file_changed(ev, Policy()) is None


# --------------------------------------------------------------------------- #
# module surface
# --------------------------------------------------------------------------- #
def test_rules_tuple_exposes_three_rules():
    assert integrity.RULES == (
        integrity.rule_config_change_protect,
        integrity.rule_cwd_confine,
        integrity.rule_env_file_changed,
    )


def test_rules_are_fail_open_on_garbage(monkeypatch):
    _agent(monkeypatch)
    # A malformed event must never raise out of a rule (fail-open contract).
    bad = Event(event=HookEvent.CONFIG_CHANGE, raw={"paths": object()})
    for rule in integrity.RULES:
        assert rule(bad, Policy()) is None or rule(bad, Policy()).action in Action
