"""The gate: turn a Ledger + an Answer into a Verdict, and block on failure.

Three rules, applied to every claim:

  1. BINDING       — the claim cites at least one evidence id, and every cited id
                     exists in the ledger. An uncited claim is illegal; it must be
                     moved into the Answer's `assumptions` list instead.

  2. EFFORT HONESTY — for `effort` claims ("I searched / read / reviewed ..."),
                     the cited evidence must be of a kind that matches the verb,
                     and any total-coverage language ("all", "entire", ...)
                     requires machine-checkable `coverage` proof. This is the
                     direct check against fabricated research extent.

  3. SUPPORT       — the cited evidence must actually back the claim, per a
                     pluggable SupportVerifier (heuristic by default).

`audit()` is the same engine without raising — for post-hoc / CI use.
`Gate.finalize()` raises UngroundedAnswerError in hard mode.
"""

from __future__ import annotations

import re

from .errors import UngroundedAnswerError
from .ledger import Ledger
from .models import (
    EFFORT_VERBS,
    OVERCLAIM_PHRASES,
    OVERCLAIM_WORDS,
    Answer,
    Claim,
    ClaimKind,
    ClaimResult,
    Verdict,
)
from .verify import HeuristicVerifier, SupportVerifier

_WORD = re.compile(r"[a-z']+")


def _check_binding(claim: Claim, ledger: Ledger) -> list[str]:
    if not claim.evidence_ids:
        return ["no evidence cited -- move this to assumptions or go gather evidence"]
    missing = [eid for eid in claim.evidence_ids if not ledger.has(eid)]
    if missing:
        return [f"cites evidence not in the ledger: {', '.join(missing)}"]
    return []


def _check_effort(claim: Claim, ledger: Ledger) -> list[str]:
    if claim.kind is not ClaimKind.EFFORT:
        return []
    failures: list[str] = []
    words = set(_WORD.findall(claim.text.lower()))

    # 2a. The verb must be backed by evidence of a compatible kind. Evidence
    # flagged is_error records a *failed* action, so it can't back an effort verb.
    cited = [ledger.get(eid) for eid in claim.evidence_ids if ledger.has(eid)]
    cited_kinds = {
        e.kind for e in cited if e is not None and not e.meta.get("is_error")
    }
    matched_verb = False
    for verb, ok_kinds in EFFORT_VERBS.items():
        if any(w.startswith(verb) for w in words):
            matched_verb = True
            if not (cited_kinds & ok_kinds):
                want = " or ".join(sorted(k.value for k in ok_kinds))
                failures.append(
                    f"claims to have {verb!r} but cites no {want} evidence"
                )
    if not matched_verb and not cited_kinds:
        failures.append("effort claim with no recognizable verb and no evidence")

    # 2b. Total-coverage language requires provable coverage.
    lowered = claim.text.lower()
    overclaims = (OVERCLAIM_WORDS & words) | {
        p for p in OVERCLAIM_PHRASES if p in lowered
    }
    if overclaims:
        cov = claim.coverage or {}
        examined, total = cov.get("examined"), cov.get("total")
        if examined is None or total is None:
            failures.append(
                f"uses total-coverage language ({', '.join(sorted(overclaims))}) "
                f"without coverage proof; provide coverage={{'examined': n, 'total': m}}"
            )
        else:
            try:
                examined_n, total_n = int(examined), int(total)
            except (TypeError, ValueError):
                failures.append(
                    f"coverage proof is not numeric (examined={examined!r}, "
                    f"total={total!r}); provide integer counts"
                )
            else:
                if examined_n < total_n:
                    failures.append(
                        f"claims full coverage but only {examined_n}/{total_n} examined"
                    )
    return failures


def audit(
    answer: Answer,
    ledger: Ledger,
    *,
    verifier: SupportVerifier | None = None,
) -> Verdict:
    """Run all checks. Never raises — returns a Verdict (use for post-hoc/CI)."""
    verifier = verifier or HeuristicVerifier()
    results: list[ClaimResult] = []

    for claim in answer.claims:
        failures: list[str] = []
        failures += _check_binding(claim, ledger)
        failures += _check_effort(claim, ledger)

        # 3. Support — only for fact/conclusion claims. Effort claims describe an
        # action, not content, so they're validated by the verb↔kind rule above,
        # not by content overlap. Only run once binding holds.
        if not failures and claim.evidence_ids and claim.kind is not ClaimKind.EFFORT:
            evs = [ledger.get(e) for e in claim.evidence_ids]
            evs = [e for e in evs if e is not None and not e.meta.get("is_error")]
            ok, reason = verifier.supports(claim, evs)
            if not ok:
                failures.append(f"unsupported: {reason}")

        results.append(ClaimResult(claim=claim, ok=not failures, failures=failures))

    # A non-empty summary with no claims and no declared assumptions is prose
    # the gate can't check -- the trivial bypass. Fail it explicitly.
    if answer.summary.strip() and not answer.claims and not answer.assumptions:
        results.append(
            ClaimResult(
                claim=Claim(text=answer.summary.strip()),
                ok=False,
                failures=[
                    "summary asserts content but carries no claims and declares "
                    "no assumptions -- nothing for the gate to check"
                ],
            )
        )

    claimed_effort = sum(c.kind is ClaimKind.EFFORT for c in answer.claims)
    return Verdict(
        ok=all(r.ok for r in results),
        results=results,
        assumptions=list(answer.assumptions),
        claimed_effort=claimed_effort,
        logged_evidence=len(ledger),
    )


class Gate:
    """A hard gate around an answer. Configure once, finalize many times."""

    def __init__(
        self,
        ledger: Ledger,
        *,
        verifier: SupportVerifier | None = None,
        hard: bool = True,
    ) -> None:
        self.ledger = ledger
        self.verifier = verifier or HeuristicVerifier()
        self.hard = hard

    def check(self, answer: Answer) -> Verdict:
        return audit(answer, self.ledger, verifier=self.verifier)

    def finalize(self, answer: Answer) -> str:
        """Return the rendered answer, or block.

        In hard mode an ungrounded answer raises UngroundedAnswerError carrying
        the Verdict, so the agent gets a precise, machine-readable list of what to
        fix (gather evidence, or demote the claim to an assumption).
        """
        verdict = self.check(answer)
        if not verdict.ok and self.hard:
            raise UngroundedAnswerError(verdict)
        return render(answer, verdict)


def render(answer: Answer, verdict: Verdict) -> str:
    """Human-facing output: the answer plus an explicit assumptions footer."""
    out = [answer.summary.strip()] if answer.summary.strip() else []
    if answer.assumptions:
        out.append("\nAssumptions this answer rests on:")
        for a in answer.assumptions:
            tail = f" (impact: {a.impact})" if a.impact else ""
            out.append(f"  - {a.text} -- {a.reason}{tail}")
    if not verdict.ok:
        out.append("\n[!] This answer did not pass the grounding gate.")
    return "\n".join(out)
