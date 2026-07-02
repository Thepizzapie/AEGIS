"""Interaction & MCP-input governance for spawned/unattended agents.

Covers the human-in-the-loop and MCP side-channel lifecycle events:
PostToolUseFailure / PermissionRequest / Elicitation / ElicitationResult.

The governing idea: a SPAWNED agent (``is_agent()`` — AEGIS_AGENT_NAME set) runs
unattended. Any event whose normal resolution is "a human answers a prompt" is
suspect for such an agent: there is no human at the keyboard, so an interactive
escalation either hangs forever or is a sign the agent is reaching past its
allowlist. Both enforcing rules below are opt-in (policy must ask for them) and
fail-open per the project contract.

Two enforcing rules live here:

- ``rule_permission_escalation`` (PermissionRequest, BLOCKABLE) — a permission
  dialog would appear, i.e. the action was NOT pre-approved. For a spawned agent
  nobody can answer that dialog, so under ``policy.permission['deny_escalation']``
  we auto-DENY rather than hang on (or implicitly grant) a human-only prompt.
- ``rule_elicitation_governance`` (Elicitation / ElicitationResult, BLOCKABLE) —
  an MCP server is requesting user input (Elicitation) or returning a result
  (ElicitationResult). For an unattended agent this is an untrusted side channel
  for injecting input; under ``policy.mcp['block_elicitation']`` we DENY it.

Intentionally OMITTED (audit-only — no enforcing rule):

- PostToolUseFailure: observational accountability only. PostToolUseFailure is
  NOT in BLOCKABLE, so a Decision could not stop anything; the audit record is
  written automatically by the caller. Repeated tool failures are a meaningful
  signal (an agent flailing / probing), but acting on that is a cross-event
  pattern the accountability layer can flag later (sessions with high failure
  rates) — out of scope for a single-event, Decision-returning rule. Per the
  project contract we do NOT register an always-None rule, so PostToolUseFailure
  has no entry in RULES.
"""
from __future__ import annotations

from typing import Optional

from ..events import Event, HookEvent
from ..policy import Action, Decision
from ._common import is_agent


def rule_permission_escalation(ev: Event, policy=None) -> Optional[Decision]:
    """Auto-deny human-only permission prompts for unattended agents.

    A PermissionRequest fires only when the action was NOT pre-approved — an
    interactive permission dialog would appear. A SPAWNED agent (``is_agent()``)
    has no human to answer it, so an escalation either hangs forever or signals
    the agent trying something outside its allowlist. When policy opts in via
    ``policy.permission['deny_escalation']`` we DENY (PermissionRequest is
    blockable, so this resolves the prompt as a deny instead of leaving it to
    hang on nobody). No opt-in, or a human/orchestrator session (not
    ``is_agent()``) -> None. Fail-open: any error -> None."""
    try:
        if ev.event != HookEvent.PERMISSION_REQUEST:
            return None
        if not is_agent():
            return None  # a human can answer the prompt -> let it surface
        perm = getattr(policy, "permission", None) or {}
        if not perm.get("deny_escalation"):
            return None  # policy hasn't opted in -> no opinion
        return Decision(Action.DENY, "permission-escalation",
                        "Permission prompt auto-denied: a spawned/unattended agent cannot "
                        "answer a human-only permission dialog. The action was not "
                        "pre-approved (it escalated past the allowlist). Pre-approve it in "
                        "policy or run interactively; do not rely on a prompt nobody will "
                        "answer.")
    except Exception:
        return None


def rule_elicitation_governance(ev: Event, policy=None) -> Optional[Decision]:
    """Block MCP elicitation as an untrusted side channel for unattended agents.

    Elicitation is an MCP server requesting user input; ElicitationResult carries
    the answer back. For a SPAWNED agent (``is_agent()``) there is no user to
    prompt, and the channel becomes a way for an MCP server to inject untrusted
    input into the run out-of-band. When policy opts in via
    ``policy.mcp['block_elicitation']`` we DENY both the request and its result
    (both events are blockable). No opt-in, or a human/orchestrator session -> None.
    Fail-open: any error -> None."""
    try:
        if ev.event not in (HookEvent.ELICITATION, HookEvent.ELICITATION_RESULT):
            return None
        if not is_agent():
            return None  # a human is present to vet the elicitation -> allow
        mcp = getattr(policy, "mcp", None) or {}
        if not mcp.get("block_elicitation"):
            return None  # policy hasn't opted in -> no opinion
        return Decision(Action.DENY, "elicitation-governance",
                        "MCP elicitation blocked: a spawned/unattended agent has no user to "
                        "answer it, and the channel is an untrusted side path for injecting "
                        "input into the run. Disable the server's elicitation, or run "
                        "interactively where a human can vet the prompt.")
    except Exception:
        return None


# Only enforcement points (rules that can return a Decision) are registered.
# PostToolUseFailure is audit-only and intentionally has no rule here.
RULES = (
    rule_permission_escalation,
    rule_elicitation_governance,
)
