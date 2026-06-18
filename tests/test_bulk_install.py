"""Bulk dependency install guard — blocks blind installs (supply-chain defense)."""
from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Policy

EMPTY = Policy()


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def test_npm_install_blocked():
    assert evaluate(_shell("npm install"), EMPTY).blocked
    assert evaluate(_shell("npm i"), EMPTY).blocked
    assert evaluate(_shell("npm ci"), EMPTY).blocked


def test_yarn_install_blocked():
    assert evaluate(_shell("yarn install"), EMPTY).blocked
    assert evaluate(_shell("yarn"), EMPTY).blocked  # bare yarn = yarn install


def test_pip_requirements_blocked():
    assert evaluate(_shell("pip install -r requirements.txt"), EMPTY).blocked
    assert evaluate(_shell("pip3 install --requirement reqs.txt"), EMPTY).blocked
    assert evaluate(_shell("python -m pip install -r requirements.txt"), EMPTY).blocked


def test_poetry_bundle_blocked():
    assert evaluate(_shell("poetry install"), EMPTY).blocked
    assert evaluate(_shell("bundle install"), EMPTY).blocked


def test_cargo_go_blocked():
    assert evaluate(_shell("cargo build"), EMPTY).blocked
    assert evaluate(_shell("cargo test"), EMPTY).blocked
    assert evaluate(_shell("go mod download"), EMPTY).blocked
    assert evaluate(_shell("go mod tidy"), EMPTY).blocked


def test_pnpm_bun_blocked():
    assert evaluate(_shell("pnpm install"), EMPTY).blocked
    assert evaluate(_shell("bun install"), EMPTY).blocked


def test_targeted_install_allowed():
    """Single-package installs are fine — the dev knows what they're adding."""
    assert not evaluate(_shell("npm install lodash"), EMPTY).blocked
    assert not evaluate(_shell("pip install requests"), EMPTY).blocked
    assert not evaluate(_shell("yarn add express"), EMPTY).blocked


def test_escapable_with_override():
    assert not evaluate(_shell("npm install  # aegis-allow"), EMPTY).blocked


def test_escapable_with_env(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_INSTALL", "1")
    assert not evaluate(_shell("npm install"), EMPTY).blocked


def test_agent_cannot_self_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "builder")
    assert evaluate(_shell("npm install  # aegis-allow"), EMPTY).blocked


def test_powershell_tool():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="PowerShell",
                    args={"command": "npm install"})
    assert evaluate(ev, EMPTY).blocked


def test_pipenv_blocked():
    assert evaluate(_shell("pipenv install"), EMPTY).blocked


def test_pipenv_targeted_allowed():
    assert not evaluate(_shell("pipenv install flask"), EMPTY).blocked


def test_non_shell_ignored():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Read",
                    args={"file_path": "package.json"})
    assert not evaluate(ev, EMPTY).blocked


def test_rule_name():
    d = evaluate(_shell("npm install"), EMPTY)
    assert d.rule == "bulk-install"
