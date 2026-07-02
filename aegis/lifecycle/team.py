"""Sub-agent & team (multi-agent) governance + accountability.

Covers the lifecycle events of spawned sub-agents and team tasks:
SubagentStart / SubagentStop / TaskCreated / TaskCompleted / TeammateIdle.

Two enforcing rules live here:

- ``rule_subagent_spawn_depth`` (SubagentStart) — mirrors
  ``rules.rule_subagent_spawn`` but at SPAWN time. SubagentStart is NOT in
  BLOCKABLE, so a DENY here does not actually halt the spawn; it surfaces the
  decision for visibility/audit so uncontrolled programmatic fan-out (a spawned
  agent spawning its own sub-agents — cost / blast-radius) is recorded the
  moment it happens, not only when the inner Agent/Task tool fires.
- ``rule_task_completion_gate`` (TaskCompleted, BLOCKABLE) — the
  "did-it-do-the-task" gate. Only acts when the policy explicitly opts in
  (``team.require_verification``) and the completion looks unverified, so a task
  can't be marked done before its work was actually checked.

Intentionally OMITTED (audit-only — no enforcing rule):

- SubagentStop / token-sync: accountability is handled by the audit layer. The
  caller writes the audit record automatically and the adapter already captures
  per-sub-agent usage, so a Decision-returning rule would add nothing. Per the
  project contract we do NOT register always-None rules; with nothing to enforce
  on SubagentStop, we omit a rule for it entirely.
- TaskCreated: observational here; creation is governed at spawn time by
  ``rule_subagent_spawn_depth`` and by the tool-use ``rule_subagent_spawn``.
- TeammateIdle: idle is an observational signal. There is no conservative,
  generally-meaningful enforcement to define from a single idle event (an idle
  teammate is not itself a violation), so we omit a rule and leave it to audit.
"""
from __future__ import annotations

import os
from typing import Optional

from ..events import Event, HookEvent
from ..policy import Action, Decision
from ._common import is_agent


def rule_subagent_spawn_depth(ev: Event, policy=None) -> Optional[Decision]:
    """Surface programmatic sub-agent fan-out at SPAWN time. When a SPAWNED agent
    (is_agent()) is itself spawning a sub-agent and AEGIS_ALLOW_SUBAGENTS is not
    set, return DENY for visibility/audit — uncontrolled fan-out is unbounded
    cost / blast-radius. SubagentStart is not blockable, so this records the event
    rather than halting it; the matching blockable guard is the tool-use
    ``rules.rule_subagent_spawn`` at Agent/Task time. A human/orchestrator (not
    is_agent()) may delegate -> None. Fail-open: any error -> None."""
    try:
        if ev.event != HookEvent.SUBAGENT_START:
            return None
        if os.environ.get("AEGIS_ALLOW_SUBAGENTS"):
            return None
        if not is_agent():
            return None  # a human/orchestrator session may spawn sub-agents
        return Decision(Action.DENY, "subagent-spawn-depth",
                        "Spawned agent is spawning a sub-agent — programmatic fan-out is "
                        "uncontrolled cost/blast-radius. SubagentStart is observational, so "
                        "this is recorded for audit; set AEGIS_ALLOW_SUBAGENTS=1 to allow.")
    except Exception:
        return None


def _verified(ev: Event) -> bool:
    """Best-effort read of whether the completion was verified. Looks at the raw
    payload's ``verified`` signal (truthy = work was checked). Absent/falsy ->
    unverified."""
    raw = ev.raw or {}
    return bool(raw.get("verified"))


def rule_task_completion_gate(ev: Event, policy=None) -> Optional[Decision]:
    """The "did-it-do-the-task" accountability gate. When policy opts in
    (``policy.team['require_verification']`` truthy) a team task may not be marked
    TaskCompleted until its work is verified — otherwise an agent can self-certify
    completion of work that was never checked. Conservative: DENY only when the
    policy explicitly requires verification AND the completion looks unverified
    (``ev.raw['verified']`` falsy); no opt-in, or already verified -> None.
    TaskCompleted is blockable, so this DENY actually holds the task open.
    Fail-open: any error -> None."""
    try:
        if ev.event != HookEvent.TASK_COMPLETED:
            return None
        team = getattr(policy, "team", None) or {}
        if not team.get("require_verification"):
            return None  # policy hasn't opted in -> no opinion
        if _verified(ev):
            return None  # work was checked -> let it complete
        return Decision(Action.DENY, "task-completion-gate",
                        "Task marked complete without verification. Policy requires "
                        "verification before completion (team.require_verification) — "
                        "verify the work (tests/review) and record it, then mark complete.")
    except Exception:
        return None


# Priority order: spawn governance (recorded earliest) before the completion gate.
RULES = (
    rule_subagent_spawn_depth,
    rule_task_completion_gate,
)
