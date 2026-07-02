"""Session & context-compaction lifecycle accountability.

Domain events: SessionEnd, PreCompact, PostCompact, StopFailure, Notification.

WHY mostly observational: the caller writes an audit record for every hook event
automatically. Accountability for these points is satisfied by that record — there
is nothing to *enforce*. Per the project contract we do NOT add always-None rules,
so only the one genuine enforcement point below is exposed in ``RULES``.

Audit-only events (deliberately NOT given a rule):
  - SessionEnd   — the session is already over; a deny cannot un-end it. The audit
                   record (who ran, how it ended) is the accountability artifact.
  - PostCompact  — context is already compacted; nothing left to block.
  - StopFailure  — the turn died on an API error (ev.matcher: rate_limit /
                   overloaded / authentication_failed). Not agent-caused, not
                   blockable, nothing to enforce; the record is the point.
  - Notification — a runtime notice (idle / permission / auth). Informational only.

The single enforcement point is PreCompact, which is BLOCKABLE: it fires *before*
context is destroyed, so a deny there can actually preserve it.
"""
from __future__ import annotations

from typing import Optional

from ..events import Event, HookEvent
from ..policy import Action, Decision


def rule_precompact_gate(ev: Event, policy=None) -> Optional[Decision]:
    """Opt-in: block AUTO compaction so a human can checkpoint first.

    WHY: PreCompact fires before context is compacted (ev.matcher is 'manual' or
    'auto'). Compaction destroys the in-context record an audit / attestation may
    still need — once it's gone, you cannot reconstruct what the agent saw or did
    before the turn. Auto compaction is silent and unattended, so by default we
    don't lose that record without a human deciding to. When policy opts in via
    ``policy.compaction`` (e.g. ``{block_auto: True}``), DENY auto compaction; the
    human can then checkpoint / snapshot context and trigger a manual compaction.

    Manual compaction is human-initiated (the human already chose to), so it is
    never blocked. Without opt-in this rule abstains. Fail-open on any error.
    """
    try:
        if ev.event != HookEvent.PRE_COMPACT:
            return None
        cfg = getattr(policy, "compaction", None)
        if not isinstance(cfg, dict) or not cfg.get("block_auto"):
            return None
        if ev.matcher != "auto":
            return None  # manual compaction is human-initiated — allow
        return Decision(
            Action.DENY,
            "precompact-gate",
            "Auto context-compaction blocked: compaction destroys the in-context "
            "record an audit/attestation may need. Checkpoint or snapshot context, "
            "then run a manual /compact. Disable by clearing policy.compaction.block_auto.",
        )
    except Exception:
        return None  # fail-open: a broken lifecycle rule must not brick the agent


# Only PreCompact is a real enforcement point; the rest are audited automatically.
RULES = (rule_precompact_gate,)
