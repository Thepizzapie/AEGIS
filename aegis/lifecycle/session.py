"""Session, stop, & context-compaction lifecycle rules.

Domain events: Stop, SessionEnd, PreCompact, PostCompact, StopFailure,
Notification.

WHY mostly observational: the caller writes an audit record for every hook event
automatically. Accountability for these points is satisfied by that record — there
is nothing to *enforce*. Per the project contract we do NOT add always-None rules,
so only the genuine enforcement points below are exposed in ``RULES``.

Audit-only events (deliberately NOT given a rule):
  - SessionEnd   — the session is already over; a deny cannot un-end it. The audit
                   record (who ran, how it ended) is the accountability artifact.
  - PostCompact  — context is already compacted; nothing left to block. It IS the
                   re-injection point for the policy digest (``aegis.context``),
                   but injection is a CLI-hook side effect, not a Decision.
  - StopFailure  — the turn died on an API error (ev.matcher: rate_limit /
                   overloaded / authentication_failed). Not agent-caused, not
                   blockable, nothing to enforce; the record is the point.
  - Notification — a runtime notice (idle / permission / auth). Informational only.

Two enforcement points:
  - PreCompact (BLOCKABLE) — fires *before* context is destroyed, so a deny there
    can actually preserve it (``rule_precompact_gate``, opt-in).
  - Stop (BLOCKABLE) — fires as the turn ends, so a deny there can hold the
    session open until its work is verified (``rule_stop_verification_gate``,
    opt-in): the "did-it-do-the-task" gate, judged against the session's own
    audit trail rather than the agent's self-report.
"""
from __future__ import annotations

import re
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


def _test_regexes(cfg: dict):
    """The regexes that count as "a test run": ``completion.patterns`` when the
    policy supplies them (bad regexes skipped), else the built-in TEST_CMD_RE."""
    pats = cfg.get("patterns") or []
    out = []
    for p in pats:
        try:
            out.append(re.compile(str(p), re.IGNORECASE))
        except re.error:
            continue
    if out:
        return out
    from .. import patterns
    return [patterns.TEST_CMD_RE]


def rule_stop_verification_gate(ev: Event, policy=None) -> Optional[Decision]:
    """Opt-in "did-it-do-the-task" Stop gate: after this session mutated files,
    it may not stop until a test run is recorded AFTER the last mutation.

    WHY the audit trail: an agent's own "done, all tests pass" is a self-report;
    the audit stream is what actually happened. The evidence rule is deliberately
    honest — a successful PostToolUse whose shell command matches a test-runner
    pattern, occurring after the session's last successful edit/write record.
    Presence of the run, not a parse of its output: a runner that exits nonzero
    surfaces as PostToolUseFailure and never satisfies the gate.

    Opt-in via ``policy.completion: {require_tests: true, patterns: [regex]}``.
    Abstains when the session made no file mutations (nothing to verify), and
    when the runtime reports ``stop_hook_active`` (the stop already continued
    once from a gate deny — denying again would loop the turn forever).
    Fail-open on any internal error, per the project contract.
    """
    try:
        if ev.event != HookEvent.STOP:
            return None
        cfg = getattr(policy, "completion", None)
        if not isinstance(cfg, dict) or not cfg.get("require_tests"):
            return None
        raw = ev.raw or {}
        if raw.get("stop_hook_active") or raw.get("stopHookActive"):
            return None  # already continuing from a gate deny — never loop
        session = ev.session_id
        if not session:
            return None  # can't attribute records -> abstain, don't false-deny
        from .. import config
        from ..accountability import load_records
        recs = [r for r in load_records(str(config.audit_path()))
                if r.get("session_id") == session]
        last_mutation = -1
        for i, r in enumerate(recs):
            if (r.get("event") == HookEvent.POST_TOOL_USE.value
                    and r.get("action") in ("edit", "write")
                    and r.get("decision") != Action.DENY.value):
                last_mutation = i
        if last_mutation < 0:
            return None  # nothing changed -> nothing to verify
        regexes = _test_regexes(cfg)
        for r in recs[last_mutation + 1:]:
            if r.get("event") != HookEvent.POST_TOOL_USE.value:
                continue
            cmd = str((r.get("args") or {}).get("command") or "")
            if cmd and any(rx.search(cmd) for rx in regexes):
                return None  # verified after the last change
        return Decision(
            Action.DENY,
            "stop-verification-gate",
            "Stopping blocked: this session changed files but no test run is "
            "recorded after the last change. Run the test suite (so the run "
            "lands in the audit trail), then stop. Configured by "
            "policy.completion.require_tests.",
        )
    except Exception:
        return None  # fail-open: a broken lifecycle rule must not brick the agent


# PreCompact and Stop are the real enforcement points; the rest are audited
# automatically.
RULES = (rule_precompact_gate, rule_stop_verification_gate)
