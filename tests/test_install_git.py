"""install-git must write an ABSOLUTE aegis command, not bare `aegis`.

Git runs hooks in a bare /bin/sh without the venv's Scripts/bin on PATH, so a
bare `aegis` fails with 'command not found' and blocks every commit for the
wrong reason. The hook must invoke aegis by absolute path (or an explicit override).
"""
import sys

from aegis import cli


def _mk_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    return repo


def test_default_command_is_absolute(monkeypatch, tmp_path):
    fake = tmp_path / "venv" / "Scripts" / "aegis.exe"
    fake.parent.mkdir(parents=True)
    fake.write_text("x", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [str(fake), "install-git"])
    repo = _mk_repo(tmp_path)
    cli.install_git_hooks(str(repo))
    hook = (repo / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
    assert "git-hook commit" in hook
    assert "/aegis.exe" in hook
    assert "\naegis git-hook" not in hook


def test_explicit_command_override(tmp_path):
    repo = _mk_repo(tmp_path)
    cli.install_git_hooks(str(repo), command="/opt/aegis/bin/aegis")
    pre_push = (repo / ".git" / "hooks" / "pre-push").read_text(encoding="utf-8")
    assert "/opt/aegis/bin/aegis git-hook push" in pre_push


def test_resolver_last_resort_is_bare(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", [str(tmp_path / "pytest")])
    monkeypatch.setattr(sys, "executable", str(tmp_path / "py" / "python.exe"))
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert cli._resolve_aegis_command() == "aegis"
