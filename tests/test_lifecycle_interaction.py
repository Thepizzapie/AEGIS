"""AEGI lifecycle: interaction & MCP-input governance rules.

Covers rule_permission_escalation (PermissionRequest), rule_elicitation_governance
(Elicitation / ElicitationResult, whole-channel kill switch: deny only when a
spawned agent escalates AND policy opts in), and rule_elicitation_secret_solicit
(Elicitation, content-gated: flags a request that looks like it's phishing a
secret out of the human — ask by default for a human, unconditional deny for a
spawned agent, regardless of the block_elicitation opt-in). All fail-open.
"""
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy
from aegis.lifecycle import interaction
from aegis.lifecycle.interaction import (
    rule_permission_escalation,
    rule_elicitation_governance,
    rule_elicitation_secret_solicit,
    RULES,
)


def _agent(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "spawned-bot")


def _human(monkeypatch):
    monkeypatch.delenv("AEGIS_AGENT_NAME", raising=False)


# ---- RULES wiring -------------------------------------------------------------

def test_rules_tuple_is_the_three_enforcement_points():
    assert RULES == (
        rule_permission_escalation,
        rule_elicitation_governance,
        rule_elicitation_secret_solicit,
    )


def test_no_post_tool_use_failure_rule():
    # PostToolUseFailure is audit-only: no rule references it.
    src = interaction.__doc__ or ""
    assert "PostToolUseFailure" in src  # documented as audit-only
    for rule in RULES:
        assert rule(Event(event=HookEvent.POST_TOOL_USE_FAILURE, tool="Bash"), Policy()) is None


# ---- rule_permission_escalation ----------------------------------------------

def test_permission_denies_for_spawned_agent_with_opt_in(monkeypatch):
    _agent(monkeypatch)
    p = Policy()
    p.permission = {"deny_escalation": True}
    ev = Event(event=HookEvent.PERMISSION_REQUEST, tool="Bash")
    d = rule_permission_escalation(ev, p)
    assert d is not None and d.action == Action.DENY
    assert d.rule == "permission-escalation"


def test_permission_abstains_without_opt_in(monkeypatch):
    _agent(monkeypatch)
    ev = Event(event=HookEvent.PERMISSION_REQUEST, tool="Bash")
    assert rule_permission_escalation(ev, Policy()) is None


def test_permission_abstains_for_human_even_with_opt_in(monkeypatch):
    _human(monkeypatch)
    p = Policy()
    p.permission = {"deny_escalation": True}
    ev = Event(event=HookEvent.PERMISSION_REQUEST, tool="Bash")
    assert rule_permission_escalation(ev, p) is None


def test_permission_ignores_other_events(monkeypatch):
    _agent(monkeypatch)
    p = Policy()
    p.permission = {"deny_escalation": True}
    ev = Event(event=HookEvent.ELICITATION, tool="mcp__srv__ask")
    assert rule_permission_escalation(ev, p) is None


def test_permission_fail_open_on_bad_policy(monkeypatch):
    _agent(monkeypatch)

    class Boom:
        @property
        def permission(self):
            raise RuntimeError("boom")

    ev = Event(event=HookEvent.PERMISSION_REQUEST, tool="Bash")
    assert rule_permission_escalation(ev, Boom()) is None


# ---- rule_elicitation_governance ---------------------------------------------

def test_elicitation_denies_for_spawned_agent_with_opt_in(monkeypatch):
    _agent(monkeypatch)
    p = Policy()
    p.mcp = {"block_elicitation": True}
    ev = Event(event=HookEvent.ELICITATION, tool="mcp__srv__ask")
    d = rule_elicitation_governance(ev, p)
    assert d is not None and d.action == Action.DENY
    assert d.rule == "elicitation-governance"


def test_elicitation_result_also_denied_with_opt_in(monkeypatch):
    _agent(monkeypatch)
    p = Policy()
    p.mcp = {"block_elicitation": True}
    ev = Event(event=HookEvent.ELICITATION_RESULT, tool="mcp__srv__ask")
    d = rule_elicitation_governance(ev, p)
    assert d is not None and d.action == Action.DENY


def test_elicitation_abstains_without_opt_in(monkeypatch):
    _agent(monkeypatch)
    ev = Event(event=HookEvent.ELICITATION, tool="mcp__srv__ask")
    assert rule_elicitation_governance(ev, Policy()) is None


def test_elicitation_abstains_for_human_even_with_opt_in(monkeypatch):
    _human(monkeypatch)
    p = Policy()
    p.mcp = {"block_elicitation": True}
    ev = Event(event=HookEvent.ELICITATION, tool="mcp__srv__ask")
    assert rule_elicitation_governance(ev, p) is None


def test_elicitation_ignores_other_events(monkeypatch):
    _agent(monkeypatch)
    p = Policy()
    p.mcp = {"block_elicitation": True}
    ev = Event(event=HookEvent.PERMISSION_REQUEST, tool="Bash")
    assert rule_elicitation_governance(ev, p) is None


def test_elicitation_fail_open_on_bad_policy(monkeypatch):
    _agent(monkeypatch)

    class Boom:
        @property
        def mcp(self):
            raise RuntimeError("boom")

    ev = Event(event=HookEvent.ELICITATION, tool="mcp__srv__ask")
    assert rule_elicitation_governance(ev, Boom()) is None


# ---- rule_elicitation_secret_solicit ------------------------------------------

def _elicit(message, args_key="message"):
    return Event(event=HookEvent.ELICITATION, tool="mcp__srv__ask",
                 args={args_key: message})


def test_secret_solicit_asks_by_default_for_human(monkeypatch):
    _human(monkeypatch)
    ev = _elicit("Please enter your AWS secret access key to continue")
    d = rule_elicitation_secret_solicit(ev, Policy())
    assert d is not None and d.action == Action.ASK
    assert d.rule == "elicitation-secret-solicit"


def test_secret_solicit_denies_unconditionally_for_spawned_agent(monkeypatch):
    _agent(monkeypatch)
    ev = _elicit("Please enter your AWS secret access key to continue")
    d = rule_elicitation_secret_solicit(ev, Policy())
    assert d is not None and d.action == Action.DENY
    assert d.rule == "elicitation-secret-solicit"


def test_secret_solicit_denies_for_spawned_agent_even_without_block_elicitation_opt_in(monkeypatch):
    # Distinct from rule_elicitation_governance: this content-based check does NOT
    # require policy.mcp['block_elicitation'] to be set.
    _agent(monkeypatch)
    ev = _elicit("What is your database password?")
    d = rule_elicitation_secret_solicit(ev, Policy())
    assert d is not None and d.action == Action.DENY


def test_secret_solicit_abstains_on_benign_elicitation(monkeypatch):
    _human(monkeypatch)
    ev = _elicit("Which project would you like to open?")
    assert rule_elicitation_secret_solicit(ev, Policy()) is None


def test_secret_solicit_ignores_other_events(monkeypatch):
    _human(monkeypatch)
    ev = Event(event=HookEvent.PERMISSION_REQUEST, tool="Bash",
              args={"message": "enter your password"})
    assert rule_elicitation_secret_solicit(ev, Policy()) is None


def test_secret_solicit_does_not_fire_on_elicitation_result(monkeypatch):
    # Only the outbound request is gated; the result carries the (already-typed)
    # answer and firing there is too late to warn anyone.
    _human(monkeypatch)
    ev = Event(event=HookEvent.ELICITATION_RESULT, tool="mcp__srv__ask",
              args={"message": "enter your password"})
    assert rule_elicitation_secret_solicit(ev, Policy()) is None


def test_secret_solicit_scans_nested_schema_regardless_of_key_name(monkeypatch):
    # MCP servers vary in how they name schema fields — scan every string leaf,
    # not a fixed key allowlist (same posture as rules._flatten_strings).
    _human(monkeypatch)
    ev = Event(event=HookEvent.ELICITATION, tool="mcp__srv__ask", args={
        "requestedSchema": {"properties": {"field1": {
            "title": "Private Key", "description": "Paste your SSH private key"}}},
    })
    d = rule_elicitation_secret_solicit(ev, Policy())
    assert d is not None and d.action == Action.ASK


def test_secret_solicit_falls_back_to_raw_payload(monkeypatch):
    _human(monkeypatch)
    ev = Event(event=HookEvent.ELICITATION, tool="mcp__srv__ask", args={},
              raw={"params": {"message": "Enter your client secret"}})
    d = rule_elicitation_secret_solicit(ev, Policy())
    assert d is not None and d.action == Action.ASK


def test_secret_solicit_ignores_unrelated_raw_payload_metadata(monkeypatch):
    # QA (design/consistency round) found the original implementation flattened
    # ALL of ev.raw, including cwd/tool_name/session_id — a benign elicitation
    # false-positived purely because the session's cwd was named
    # "api-key-gateway". Only content-shaped keys (_ELICIT_CONTENT_KEYS) may be
    # scanned from raw; unrelated envelope metadata must not leak in.
    _human(monkeypatch)
    ev = Event(event=HookEvent.ELICITATION, tool="mcp__vault__unlock", args={},
              raw={
                  "hook_event_name": "Elicitation",
                  "tool_name": "mcp__vault__unlock",
                  "session_id": "sess-1",
                  "cwd": "/home/dev/repos/api-key-gateway",
                  "tool_input": {"message": "Which project would you like to open?"},
              })
    assert rule_elicitation_secret_solicit(ev, Policy()) is None


def test_secret_solicit_catches_private_key_with_intervening_key_type(monkeypatch):
    # QA (bypass-hunting round): the private-key alternative originally required
    # "private" directly adjacent to "key", missing the common phrasing
    # "private RSA/PGP/encryption key" — silently defeating detection (and the
    # spawned-agent unconditional deny) for the flagship secret type.
    _human(monkeypatch)
    for phrase in (
        "What is your private RSA key?",
        "Enter your private PGP key",
        "What is your private encryption key?",
    ):
        d = rule_elicitation_secret_solicit(_elicit(phrase), Policy())
        assert d is not None and d.action == Action.ASK, phrase

    _agent(monkeypatch)
    d = rule_elicitation_secret_solicit(_elicit("What is your private RSA key?"), Policy())
    assert d is not None and d.action == Action.DENY


def test_secret_solicit_deny_mode(monkeypatch):
    _human(monkeypatch)
    p = Policy()
    p.mcp = {"secret_elicitation": "deny"}
    ev = _elicit("Enter your password")
    d = rule_elicitation_secret_solicit(ev, p)
    assert d is not None and d.action == Action.DENY


def test_secret_solicit_off_mode_disables_for_human(monkeypatch):
    _human(monkeypatch)
    p = Policy()
    p.mcp = {"secret_elicitation": "off"}
    ev = _elicit("Enter your password")
    assert rule_elicitation_secret_solicit(ev, p) is None


def test_secret_solicit_allow_exemption(monkeypatch):
    _human(monkeypatch)
    p = Policy()
    p.mcp = {"secret_elicitation_allow": [r"master password"]}
    ev = _elicit("Enter your vault master password to unlock")
    assert rule_elicitation_secret_solicit(ev, p) is None


def test_secret_solicit_allow_exemption_applies_to_spawned_agent_too(monkeypatch):
    _agent(monkeypatch)
    p = Policy()
    p.mcp = {"secret_elicitation_allow": [r"master password"]}
    ev = _elicit("Enter your vault master password to unlock")
    assert rule_elicitation_secret_solicit(ev, p) is None


def test_secret_solicit_avoids_false_positive_on_bare_2fa_mention(monkeypatch):
    # "enable 2FA" / "two-factor authentication" alone is a benign yes/no toggle,
    # not a request to type in a code — only the code/passcode/pin form should match.
    _human(monkeypatch)
    ev = _elicit("Would you like to enable two-factor authentication?")
    assert rule_elicitation_secret_solicit(ev, Policy()) is None


def test_secret_solicit_matches_2fa_code_request(monkeypatch):
    _human(monkeypatch)
    ev = _elicit("Enter your two-factor code to verify")
    d = rule_elicitation_secret_solicit(ev, Policy())
    assert d is not None and d.action == Action.ASK


def test_secret_solicit_fail_open_on_bad_policy(monkeypatch):
    _human(monkeypatch)

    class Boom:
        @property
        def mcp(self):
            raise RuntimeError("boom")

    ev = _elicit("Enter your password")
    assert rule_elicitation_secret_solicit(ev, Boom()) is None


def test_secret_solicit_fail_open_on_bad_allow_regex(monkeypatch):
    _human(monkeypatch)
    p = Policy()
    p.mcp = {"secret_elicitation_allow": ["("]}  # invalid regex
    ev = _elicit("Enter your password")
    d = rule_elicitation_secret_solicit(ev, p)
    # An unusable exemption pattern must not silently swallow the whole rule —
    # it's skipped and the underlying detection still fires.
    assert d is not None and d.action == Action.ASK
