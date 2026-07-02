"""AEGI lifecycle: git-worktree confinement (rule_worktree_confine)."""
import os

import pytest

from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy
from aegis.lifecycle.worktree import RULES, rule_worktree_confine


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    """Confinement reads AEGIS_PROJECT / AEGIS_WORKSPACE — clear them so each
    test drives confinement explicitly."""
    monkeypatch.delenv("AEGIS_PROJECT", raising=False)
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)


def _ev(worktree=None, cwd="/repo", **kw):
    return Event(event=HookEvent.WORKTREE_CREATE, worktree=worktree, cwd=cwd, **kw)


def test_rules_tuple_is_just_confine():
    assert RULES == (rule_worktree_confine,)


def test_confine_off_returns_none():
    # No policy root and no env -> confinement off.
    ev = _ev(worktree="/anywhere/else")
    assert rule_worktree_confine(ev, Policy()) is None


def test_worktree_inside_root_allows():
    pol = Policy(project="/repo")
    ev = _ev(worktree="/repo/wt/feature")
    assert rule_worktree_confine(ev, pol) is None


def test_root_itself_allows():
    pol = Policy(project="/repo")
    ev = _ev(worktree="/repo")
    assert rule_worktree_confine(ev, pol) is None


def test_worktree_outside_root_denies():
    pol = Policy(project="/repo")
    ev = _ev(worktree="/escape/here")
    dec = rule_worktree_confine(ev, pol)
    assert dec is not None and dec.action == Action.DENY
    assert dec.rule == "worktree-confine"


def test_sibling_escape_denies():
    # `git worktree add ../escape` resolves outside the root.
    pol = Policy(project="/repo")
    ev = _ev(worktree="../escape", cwd="/repo")
    dec = rule_worktree_confine(ev, pol)
    assert dec is not None and dec.action == Action.DENY


def test_worktree_in_workspace_allow_allows():
    pol = Policy(workspace={"root": "/repo", "allow": ["/extra/wt"]})
    ev = _ev(worktree="/extra/wt/feature")
    assert rule_worktree_confine(ev, pol) is None


def test_relative_path_resolved_against_cwd():
    pol = Policy(project="/repo")
    ev = _ev(worktree="wt/inside", cwd="/repo")
    assert rule_worktree_confine(ev, pol) is None


def test_missing_path_returns_none():
    pol = Policy(project="/repo")
    ev = _ev(worktree=None)
    assert rule_worktree_confine(ev, pol) is None


def test_worktree_path_from_raw_fallback():
    pol = Policy(project="/repo")
    ev = Event(event=HookEvent.WORKTREE_CREATE, cwd="/repo",
               raw={"worktree_path": "/escape/here"})
    dec = rule_worktree_confine(ev, pol)
    assert dec is not None and dec.action == Action.DENY


def test_env_project_drives_confinement(monkeypatch):
    monkeypatch.setenv("AEGIS_PROJECT", "/repo")
    ev = _ev(worktree="/escape/here")
    dec = rule_worktree_confine(ev, Policy())
    assert dec is not None and dec.action == Action.DENY


def test_env_workspace_drives_confinement(monkeypatch):
    monkeypatch.setenv("AEGIS_WORKSPACE", "/repo")
    ev = _ev(worktree="/repo/wt")
    assert rule_worktree_confine(ev, Policy()) is None


def test_wrong_event_returns_none():
    pol = Policy(project="/repo")
    ev = Event(event=HookEvent.WORKTREE_REMOVE, worktree="/escape/here", cwd="/repo")
    assert rule_worktree_confine(ev, pol) is None


def test_fail_open_on_bad_event(monkeypatch):
    # An exception inside the rule must fail OPEN (return None), never raise.
    monkeypatch.setenv("AEGIS_PROJECT", "/repo")

    class Boom:
        event = HookEvent.WORKTREE_CREATE
        @property
        def worktree(self):
            raise RuntimeError("boom")

    assert rule_worktree_confine(Boom(), Policy()) is None
