"""AEGI-2: `aegis install` / `uninstall` — merge into settings.json, never clobber."""
import json

from aegis.events import HookEvent
from aegis import cli


def test_install_merges_without_clobbering(tmp_path):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({
        "model": "opus",
        "hooks": {"PreToolUse": [
            {"matcher": "Write", "hooks": [{"type": "command", "command": "my-own-hook"}]}
        ]},
    }), encoding="utf-8")

    added = cli.install_hooks(settings)
    data = json.loads(settings.read_text())

    assert data["model"] == "opus"  # unrelated keys preserved
    cmds = [h["command"] for e in data["hooks"]["PreToolUse"] for h in e["hooks"]]
    assert "my-own-hook" in cmds                       # user hook not clobbered
    assert "aegis hook PreToolUse" in cmds             # ours added alongside
    assert added == len(list(HookEvent))
    for ev in HookEvent:                               # every event wired
        assert ev.value in data["hooks"]


def test_install_is_idempotent(tmp_path):
    settings = tmp_path / ".claude" / "settings.json"
    cli.install_hooks(settings)
    first = settings.read_text()
    cli.install_hooks(settings)
    assert settings.read_text() == first              # no duplicate entries


def test_uninstall_removes_absolute_path_command(tmp_path):
    # regression: install with an absolute-path command must still uninstall
    settings = tmp_path / ".claude" / "settings.json"
    cli.install_hooks(settings, command="C:/x/.venv/Scripts/aegis.exe hook")
    assert cli.uninstall_hooks(settings) >= 1
    data = json.loads(settings.read_text())
    cmds = [h["command"] for e in data.get("hooks", {}).get("PreToolUse", []) for h in e["hooks"]]
    assert not any("aegis" in c.lower() for c in cmds)


def test_uninstall_removes_only_aegis(tmp_path):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({
        "hooks": {"PreToolUse": [
            {"matcher": "Write", "hooks": [{"type": "command", "command": "my-own-hook"}]}
        ]},
    }), encoding="utf-8")

    cli.install_hooks(settings)
    removed = cli.uninstall_hooks(settings)
    data = json.loads(settings.read_text())

    cmds = [h["command"] for e in data["hooks"].get("PreToolUse", []) for h in e["hooks"]]
    assert "my-own-hook" in cmds                       # user hook survived
    assert "aegis hook PreToolUse" not in cmds         # only ours removed
    assert removed >= 1
