"""Shipped-skills tests (aegis.skills + install wiring + deny-hint + self-protect).

The contract under test mirrors the hook installer's: merge, never clobber — a
user's same-named skill is untouchable; only marker-tagged files are ours to
overwrite or remove. Plus the two integration points: deny messages hint at
aegis-explain-block only when it is actually installed, and self-protect keeps
agents from rewriting the guidance.
"""
from aegis import skills
from aegis.adapters import claude_code
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Decision, Policy
from aegis.rules import rule_self_protect


EXPECTED = {"aegis-explain-block", "aegis-status", "aegis-report", "aegis-policy"}


# ---- install / uninstall ---------------------------------------------------------

def test_install_writes_all_skills(tmp_path):
    n = skills.install_skills(tmp_path)
    assert n == len(skills.SKILLS)
    assert set(skills.SKILLS) == EXPECTED
    for name in EXPECTED:
        f = tmp_path / "skills" / name / "SKILL.md"
        text = f.read_text(encoding="utf-8")
        assert skills.MARKER in text
        assert text.startswith("---\n")
        assert f"name: {name}" in text


def test_install_is_idempotent(tmp_path):
    skills.install_skills(tmp_path)
    assert skills.install_skills(tmp_path) == 0


def test_install_never_clobbers_a_user_skill(tmp_path):
    target = tmp_path / "skills" / "aegis-status" / "SKILL.md"
    target.parent.mkdir(parents=True)
    target.write_text("my own skill", encoding="utf-8")
    skills.install_skills(tmp_path)
    assert target.read_text(encoding="utf-8") == "my own skill"


def test_install_refreshes_a_stale_managed_skill(tmp_path):
    skills.install_skills(tmp_path)
    target = tmp_path / "skills" / "aegis-status" / "SKILL.md"
    target.write_text(f"{skills.MARKER}\nold content", encoding="utf-8")
    n = skills.install_skills(tmp_path)
    assert n == 1
    assert "old content" not in target.read_text(encoding="utf-8")


def test_uninstall_removes_only_managed_files(tmp_path):
    skills.install_skills(tmp_path)
    user = tmp_path / "skills" / "aegis-report" / "SKILL.md"
    user.write_text("mine now (no marker)", encoding="utf-8")
    removed = skills.uninstall_skills(tmp_path)
    assert removed == len(skills.SKILLS) - 1
    assert user.exists()
    assert not (tmp_path / "skills" / "aegis-status").exists()


def test_explain_block_covers_the_builtin_rules():
    text = skills.SKILLS["aegis-explain-block"]
    for rule in ("self-protect", "failure-loop", "install-review",
                 "stop-verification-gate", "workspace-confine",
                 "destructive-git", "mcp-config-protect"):
        assert rule in text, rule


# ---- CLI wiring -------------------------------------------------------------------

def test_cli_install_writes_skills_next_to_settings(tmp_path, capsys):
    from aegis.cli import main
    rc = main(["install", "--project", str(tmp_path)])
    assert rc == 0
    assert (tmp_path / ".claude" / "skills" / "aegis-status" / "SKILL.md").exists()
    assert "skill(s)" in capsys.readouterr().out


def test_cli_install_no_skills_flag(tmp_path):
    from aegis.cli import main
    rc = main(["install", "--project", str(tmp_path), "--no-skills"])
    assert rc == 0
    assert not (tmp_path / ".claude" / "skills").exists()


def test_cli_uninstall_removes_skills(tmp_path):
    from aegis.cli import main
    main(["install", "--project", str(tmp_path)])
    rc = main(["uninstall", "--project", str(tmp_path)])
    assert rc == 0
    assert not (tmp_path / ".claude" / "skills" / "aegis-status").exists()


# ---- deny-hint in the adapter ------------------------------------------------------

def _deny(cwd):
    ev = Event(event=HookEvent.PRE_TOOL_USE, tool="Bash",
               action=ActionClass.SHELL, args={"command": "x"}, cwd=cwd)
    code, _out, err = claude_code.render_decision(
        ev, Decision(Action.DENY, "some-rule", "Blocked."))
    assert code == 2
    return err


def test_deny_hints_at_skill_when_installed(tmp_path):
    skills.install_skills(tmp_path / ".claude")
    err = _deny(str(tmp_path))
    assert "aegis-explain-block" in err


def test_deny_has_no_hint_when_not_installed(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))          # posix expanduser
    monkeypatch.setenv("USERPROFILE", str(tmp_path))   # windows expanduser
    err = _deny(str(tmp_path))
    assert "aegis-explain-block" not in err


# ---- self-protect covers the shipped skills ----------------------------------------

def test_agents_cannot_edit_aegis_skills():
    ev = Event(event=HookEvent.PRE_TOOL_USE, tool="Edit",
               action=ActionClass.EDIT,
               args={"file_path": ".claude/skills/aegis-explain-block/SKILL.md"})
    d = rule_self_protect(ev, Policy())
    assert d is not None
    assert d.action == Action.DENY
    assert d.rule == "self-protect"


def test_user_skills_remain_editable():
    ev = Event(event=HookEvent.PRE_TOOL_USE, tool="Edit",
               action=ActionClass.EDIT,
               args={"file_path": ".claude/skills/my-skill/SKILL.md"})
    assert rule_self_protect(ev, Policy()) is None
