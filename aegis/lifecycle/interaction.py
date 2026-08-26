"""Interaction & MCP-input governance for spawned/unattended agents.

Covers the human-in-the-loop and MCP side-channel lifecycle events:
PostToolUseFailure / PermissionRequest / Elicitation / ElicitationResult.

The governing idea: a SPAWNED agent (``is_agent()`` — AEGIS_AGENT_NAME set) runs
unattended. Any event whose normal resolution is "a human answers a prompt" is
suspect for such an agent: there is no human at the keyboard, so an interactive
escalation either hangs forever or is a sign the agent is reaching past its
allowlist. The first two enforcing rules below are opt-in (policy must ask for
them); the third is content-gated and ships secure-by-default (no config
needed) for the reason explained in its own docstring. All three fail-open per
the project contract.

Three enforcing rules live here:

- ``rule_permission_escalation`` (PermissionRequest, BLOCKABLE) — a permission
  dialog would appear, i.e. the action was NOT pre-approved. For a spawned agent
  nobody can answer that dialog, so under ``policy.permission['deny_escalation']``
  we auto-DENY rather than hang on (or implicitly grant) a human-only prompt.
- ``rule_elicitation_governance`` (Elicitation / ElicitationResult, BLOCKABLE) —
  an MCP server is requesting user input (Elicitation) or returning a result
  (ElicitationResult). For an unattended agent this is an untrusted side channel
  for injecting input; under ``policy.mcp['block_elicitation']`` we DENY it.
- ``rule_elicitation_secret_solicit`` (Elicitation, BLOCKABLE) — the channel-level
  guard above is an all-or-nothing kill switch that never fires at all once a
  human is present (see its own "a human is present to vet the elicitation ->
  allow" branch). Nothing else in this codebase inspects WHAT an elicitation
  request is actually asking for: a connected MCP server can reuse the same
  legitimate protocol feature to pop a form phishing the human directly for a
  password/API key/private key/seed phrase/OTP/... — a real secret handed
  straight to the (possibly malicious or later rug-pulled) server, with no tool
  call, file write, or network request for any other guard in this file to catch.
  This rule scans the elicitation content for that secret-solicitation shape and
  forces a human confirmation (``policy.mcp['secret_elicitation']``, default
  ``ask``); for a spawned/unattended agent it denies outright, unconditionally,
  since there is no human anywhere in that path to give informed consent to a
  secret disclosure.

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

import re
from typing import Optional

from .. import patterns
from ..events import Event, HookEvent
from ..policy import Action, Decision
from ._common import flatten_strings, is_agent


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


def _elicitation_text(ev: Event) -> str:
    """Every string/number leaf of the elicitation payload, args first then raw
    (deduped isn't needed — a regex search over a slightly redundant string is
    cheap and harmless). Schema-agnostic on purpose: neither the exact Claude
    Code Elicitation hook payload shape nor a third-party MCP server's own
    ``message``/``requestedSchema`` field names are fixed enough to key off,
    the same "flatten every leaf" posture ``rules._net_text``/``_flatten_strings``
    already use for MCP tool-arg scanning elsewhere in this codebase."""
    parts = flatten_strings(ev.args or {}) + flatten_strings(ev.raw or {})
    return " ".join(parts)


def rule_elicitation_secret_solicit(ev: Event, policy=None) -> Optional[Decision]:
    """Flag an MCP Elicitation request that is soliciting a secret from the human.

    Threat model: MCP Elicitation lets a connected server pop a form asking the
    user directly for a value (a legitimate protocol feature —
    ``rule_elicitation_governance`` above governs the channel, not the content).
    A malicious server, or one trusted at install time and rug-pulled later,
    can reuse that exact feature to phish a password, API/private key, seed
    phrase, OTP, card number, or similar straight out of a trusting human — the
    value then goes to the server verbatim in the elicitation result. This
    never touches a shell command, a file write, or a tool argument a path/URL
    guard would scan, so it is invisible to every other guard in this file.

    Detection: ``patterns.ELICITATION_SECRET_RE`` against every string/number
    leaf of the request payload (``_elicitation_text`` — schema-agnostic, since
    neither the hook payload's exact shape nor a given server's field-naming
    convention is fixed). A curated vocabulary, not exhaustive — the same
    "known-dangerous shapes" posture disclosed for every guard in this file.

    Response:

    - Spawned/unattended agent (``is_agent()``) — DENY, unconditional, and NOT
      gated behind ``policy.mcp['block_elicitation']`` (a narrower, higher-
      confidence check layered under that blunter kill switch): there is no
      human anywhere in this path who could give informed consent to a secret
      disclosure, so there is no weaker "ask" to fall back to, and no
      '# aegis-allow' escape (a spawned agent can never wave itself past a
      guard, same as every other tier in this codebase).
    - Human present — surfaced via ``policy.mcp['secret_elicitation']``: ``ask``
      (default — ships secure-by-default, no config needed) forces a visible
      confirmation naming what is being solicited before the human can answer
      the form; ``deny`` hard-blocks it; ``off`` disables this rule entirely.
      ``policy.mcp['secret_elicitation_allow']`` (list of regexes) exempts a
      known-legitimate flow (e.g. a password-manager MCP server whose whole
      purpose is asking for a master password) from both tiers.

    Honest scope: Aegis cannot reach into the elicitation UI itself to stop a
    human from typing an answer once allowed through — like ``install-review``'s
    "ask" tier, this is a forced, informative confirmation gate, not a
    technical block on the keystrokes. A secret solicited under vocabulary this
    curated list doesn't happen to name evades detection, the same "denylist,
    not every possible shape" limit every guard here discloses. Fail-open: any
    error -> None."""
    try:
        if ev.event != HookEvent.ELICITATION:
            return None
        text = _elicitation_text(ev)
        if not text or not patterns.ELICITATION_SECRET_RE.search(text):
            return None
        mcp = getattr(policy, "mcp", None) or {}
        for pat in (mcp.get("secret_elicitation_allow") or []):
            try:
                if re.search(str(pat), text, re.IGNORECASE):
                    return None
            except re.error:
                continue
        if is_agent():
            return Decision(Action.DENY, "elicitation-secret-solicit",
                            "MCP elicitation blocked: this request appears to solicit a "
                            "secret (password/key/token/code/...) and a spawned/unattended "
                            "agent has no human present who could knowingly hand one over. "
                            "Run interactively where a human can vet and answer the prompt, "
                            "or add an exemption to policy.mcp['secret_elicitation_allow'] "
                            "if this server is expected to ask for this.")
        mode = str(mcp.get("secret_elicitation", "ask")).lower()
        if mode in ("off", "false") or mcp.get("secret_elicitation") is False:
            return None
        action = Action.DENY if mode == "deny" else Action.ASK
        return Decision(action, "elicitation-secret-solicit",
                        "This MCP server's elicitation request appears to be asking for a "
                        "secret (password/key/token/code/...). Verify you trust this server "
                        "before answering — Aegis can force this confirmation but cannot "
                        "see or stop what you type into the form itself.")
    except Exception:
        return None


# Only enforcement points (rules that can return a Decision) are registered.
# PostToolUseFailure is audit-only and intentionally has no rule here.
RULES = (
    rule_permission_escalation,
    rule_elicitation_governance,
    rule_elicitation_secret_solicit,
)
