"""YAML policy loader + validation (AEGI-2 minimal, hardened in AEGI-3).

Builds a :class:`~aegis.policy.Policy` from a directory of YAML files (or a single
file), and validates authored policy against the documented schema. ``yaml`` is
imported lazily so importing the CLI (install / uninstall) doesn't require PyYAML.
"""
from __future__ import annotations

from pathlib import Path

from .events import ActionClass, HookEvent
from .policy import Action, Policy, Rule

_VALID_ACTIONS = {a.value for a in Action}
_VALID_EVENTS = {e.value for e in HookEvent}
_VALID_CLASSES = {c.value for c in ActionClass}


def _rule_from_dict(d: dict) -> Rule:
    return Rule(
        name=d.get("name", "<unnamed>"),
        action=Action(d.get("action", "deny")),
        events=list(d.get("events", []) or []),
        tools=list(d.get("tools", []) or []),
        actions=list(d.get("actions", []) or []),
        roles=list(d.get("roles", []) or []),
        argument_patterns=dict(d.get("argument_patterns", {}) or {}),
        regex=dict(d.get("regex", {}) or {}),
        message=d.get("message"),
        priority=int(d.get("priority", 0) or 0),
        description=d.get("description"),
    )


def _yaml_files(path: Path):
    if path.is_dir():
        return sorted(path.glob("*.y*ml"))
    if path.is_file():
        return [path]
    return []


def load_policy(path) -> Policy:
    import yaml  # lazy: only needed when a policy is actually loaded

    path = Path(path)
    rules, default, on_error = [], Action.ALLOW, Action.ALLOW
    egress: dict = {}
    plugins: list = []
    workspace: dict = {}
    project = None
    agent_label = None
    install_review: dict = {}
    mcp_config: dict = {}
    metadata_ssrf: dict = {}
    for f in _yaml_files(path):
        data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        if "default_action" in data:
            default = Action(data["default_action"])
        if "on_error" in data:
            on_error = Action(data["on_error"])
        if data.get("egress"):
            egress = dict(data["egress"])
        if data.get("workspace"):
            workspace = dict(data["workspace"])
        if data.get("project"):
            project = str(data["project"])
        if data.get("agent_label"):
            agent_label = str(data["agent_label"])
        if data.get("install_review"):
            install_review = dict(data["install_review"])
        if data.get("mcp_config"):
            mcp_config = dict(data["mcp_config"])
        if data.get("metadata_ssrf"):
            metadata_ssrf = dict(data["metadata_ssrf"])
        plugins.extend(data.get("plugins") or [])
        for rd in (data.get("rules") or []):
            rules.append(_rule_from_dict(rd))
    return Policy(rules=rules, default_action=default, on_error=on_error,
                  egress=egress, plugins=plugins, workspace=workspace,
                  project=project, agent_label=agent_label,
                  install_review=install_review, mcp_config=mcp_config,
                  metadata_ssrf=metadata_ssrf)


def validate_file(path) -> list:
    """Human-readable errors for one policy file ([] = valid)."""
    import yaml

    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001
        return [f"{path.name}: YAML parse error: {exc}"]
    if not isinstance(data, dict):
        return [f"{path.name}: top-level must be a mapping"]

    errors: list = []
    for key in ("default_action", "on_error"):
        val = data.get(key)
        if val is not None and val not in _VALID_ACTIONS:
            errors.append(f"{path.name}: {key} '{val}' invalid (allow|deny|ask)")

    rules = data.get("rules")
    if rules is not None and not isinstance(rules, list):
        return errors + [f"{path.name}: 'rules' must be a list"]

    seen = set()
    for i, rd in enumerate(rules or []):
        loc = f"{path.name} rule[{i}]"
        if not isinstance(rd, dict):
            errors.append(f"{loc}: must be a mapping")
            continue
        name = rd.get("name")
        if not name:
            errors.append(f"{loc}: missing 'name'")
        elif name in seen:
            errors.append(f"{loc}: duplicate name '{name}'")
        else:
            seen.add(name)
        if rd.get("action", "deny") not in _VALID_ACTIONS:
            errors.append(f"{loc}: action '{rd.get('action')}' invalid (allow|deny|ask)")
        for ev in (rd.get("events") or []):
            if ev not in _VALID_EVENTS:
                errors.append(f"{loc}: unknown event '{ev}'")
        for ac in (rd.get("actions") or []):
            if ac not in _VALID_CLASSES:
                errors.append(f"{loc}: unknown action-class '{ac}'")
        ap = rd.get("argument_patterns")
        if ap is not None and not isinstance(ap, dict):
            errors.append(f"{loc}: argument_patterns must be a mapping")
    return errors


def validate_policy(path) -> list:
    """Validate every policy file under ``path``. [] = all valid."""
    path = Path(path)
    files = _yaml_files(path)
    if not files:
        return [f"{path}: no policy files found (*.yaml / *.yml)"]
    errors: list = []
    for f in files:
        errors.extend(validate_file(f))
    return errors
