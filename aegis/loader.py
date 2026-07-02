"""YAML policy loader + validation (AEGI-2 minimal, hardened in AEGI-3).

Builds a :class:`~aegis.policy.Policy` from a directory of YAML files (or a single
file), and validates authored policy against the documented schema. ``yaml`` is
imported lazily so importing the CLI (install / uninstall) doesn't require PyYAML.
"""
from __future__ import annotations

import sys
from pathlib import Path

from .events import ActionClass, HookEvent
from .policy import Action, Policy, Rule


def _warn(msg: str) -> None:
    print(f"aegis: {msg}", file=sys.stderr)

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
    st = {
        "rules": [], "default": Action.ALLOW, "on_error": Action.ALLOW,
        "egress": {}, "plugins": [], "workspace": {}, "project": None,
        "agent_label": None, "install_review": {}, "mcp_config": {},
        "inject": {}, "failures": {}, "completion": {},
        "lifecycle": {"team": {}, "compaction": {}, "permission": {}, "mcp": {}},
    }
    for f in _yaml_files(path):
        # One malformed file must NOT crash the whole load — that would discard
        # every other file's default_action/rules and silently fail the hook OPEN.
        # Skip the bad file (loudly) and keep the rest of the policy intact.
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except Exception as exc:  # noqa: BLE001
            _warn(f"skipping unparseable policy file {f.name}: {exc}")
            continue
        if not isinstance(data, dict):
            _warn(f"skipping policy file {f.name}: top-level must be a mapping, "
                  f"got {type(data).__name__}")
            continue
        try:
            _merge_file(data, f.name, st)
        except Exception as exc:  # noqa: BLE001
            _warn(f"skipping policy file {f.name} (invalid field): {exc}")
            continue
    lc = st["lifecycle"]
    return Policy(rules=st["rules"], default_action=st["default"],
                  on_error=st["on_error"], egress=st["egress"],
                  plugins=st["plugins"], workspace=st["workspace"],
                  project=st["project"], agent_label=st["agent_label"],
                  install_review=st["install_review"], mcp_config=st["mcp_config"],
                  inject=st["inject"], failures=st["failures"],
                  completion=st["completion"],
                  team=lc["team"], compaction=lc["compaction"],
                  permission=lc["permission"], mcp=lc["mcp"])


def _merge_file(data: dict, fname: str, st: dict) -> None:
    """Fold one parsed policy dict into the accumulators in ``st``. Raises on an
    invalid scalar field (e.g. a bad action enum) so the caller skips just this
    file — fail-safe, never fail-open."""
    if "default_action" in data:
        st["default"] = Action(data["default_action"])
    if "on_error" in data:
        st["on_error"] = Action(data["on_error"])
    if isinstance(data.get("egress"), dict):
        st["egress"] = dict(data["egress"])
    elif data.get("egress"):
        _warn(f"policy in {fname}: 'egress' must be a mapping; ignoring it")
    if isinstance(data.get("workspace"), dict):
        st["workspace"] = dict(data["workspace"])
    elif data.get("workspace"):
        _warn(f"policy in {fname}: 'workspace' must be a mapping; ignoring it")
    if data.get("project"):
        st["project"] = str(data["project"])
    if data.get("agent_label"):
        st["agent_label"] = str(data["agent_label"])
    # Guard-config knobs (install review, MCP-config protection, context
    # injection, failure-loop, completion verification) — small dicts.
    for key in ("install_review", "mcp_config", "inject", "failures", "completion"):
        if isinstance(data.get(key), dict):
            st[key] = dict(data[key])
        elif data.get(key):
            _warn(f"policy in {fname}: '{key}' must be a mapping; ignoring it")
    # opt-in lifecycle knobs — each a small dict (last file wins per key). A
    # malformed knob (not a mapping) is skipped, not crashed on.
    for key in st["lifecycle"]:
        val = data.get(key)
        if isinstance(val, dict):
            st["lifecycle"][key] = dict(val)
        elif val:
            _warn(f"policy in {fname}: '{key}' must be a mapping; ignoring it")
    st["plugins"].extend(data.get("plugins") or [])
    for rd in (data.get("rules") or []):
        st["rules"].append(_rule_from_dict(rd))


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
