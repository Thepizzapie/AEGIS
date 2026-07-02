"""Support verification: does the cited evidence actually back the claim?

Binding and effort-honesty are purely structural (handled in gate.py). Support is
the one check that is genuinely semantic. We keep it *pluggable* so the core gate
stays deterministic and un-gameable, while production users can swap in a stronger
judge (an LLM, an NLI model, embeddings) without touching the rest.

The default `HeuristicVerifier` is deliberately simple and transparent: it checks
that the claim's significant words actually appear in the cited evidence. It will
not catch sophisticated misquotation — that's what a pluggable judge is for — but
it cheaply catches the common case of a claim citing evidence that says nothing
about it.
"""

from __future__ import annotations

import re
from typing import Protocol

from .models import Claim, Evidence

_WORD = re.compile(r"[a-z0-9]+")
_STOP = frozenset(
    "a an the is are was were be been being of to in on at for and or but if then "
    "this that these those it its with as by from into about i we you they he she "
    "do does did done have has had will would can could should may might must not "
    "so therefore thus hence there here their our your my his her them us me".split()
)


def _tokens(text: str) -> set[str]:
    return {w for w in _WORD.findall(text.lower()) if w not in _STOP and len(w) > 2}


class SupportVerifier(Protocol):
    """Returns (supported, reason) for a claim against its cited evidence."""

    def supports(self, claim: Claim, evidence: list[Evidence]) -> tuple[bool, str]: ...


class HeuristicVerifier:
    """Token-overlap support check. Deterministic, no dependencies."""

    def __init__(self, min_overlap: float = 0.4) -> None:
        self.min_overlap = min_overlap

    def supports(self, claim: Claim, evidence: list[Evidence]) -> tuple[bool, str]:
        claim_tokens = _tokens(claim.text)
        if not claim_tokens:
            return True, "no significant tokens to check"
        haystack = _tokens(" ".join(e.content for e in evidence))
        hit = claim_tokens & haystack
        ratio = len(hit) / len(claim_tokens)
        if ratio >= self.min_overlap:
            return True, f"overlap {ratio:.0%}"
        missing = ", ".join(sorted(claim_tokens - haystack)[:6])
        return False, (
            f"cited evidence covers only {ratio:.0%} of the claim; "
            f"unsupported terms: {missing}"
        )


class NullVerifier:
    """Accepts anything. Use when binding + effort checks are enough for you."""

    def supports(self, claim: Claim, evidence: list[Evidence]) -> tuple[bool, str]:
        return True, "support check disabled"


_SUPPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "supported": {"type": "boolean"},
        "reason": {"type": "string"},
    },
    "required": ["supported", "reason"],
    "additionalProperties": False,
}

_SUPPORT_SYSTEM = (
    "You are a strict grounding judge. Given a CLAIM and the EVIDENCE that was "
    "cited for it, decide whether the evidence actually supports the claim. "
    "Be adversarial: a claim is supported only if the evidence directly backs it. "
    "If the evidence is unrelated, contradicts the claim, or only partially "
    "covers it, mark it unsupported. Default to unsupported when uncertain."
)


class LLMSupportVerifier:
    """Semantic support check backed by an LLM (see `receipts.llm`).

    Stronger than the token-overlap heuristic — it catches a claim that cites
    evidence which is topically related but doesn't actually say what the claim
    asserts. Swap it in via `Gate(ledger, verifier=LLMSupportVerifier(llm))`.
    """

    def __init__(self, llm) -> None:  # llm: receipts.llm.LLM
        self.llm = llm

    def supports(self, claim: Claim, evidence: list[Evidence]) -> tuple[bool, str]:
        if not evidence:
            return False, "no evidence to check"
        ev_text = "\n\n".join(
            f"[{e.id} | {e.kind.value} | {e.source}]\n{e.content}" for e in evidence
        )
        user = f"CLAIM:\n{claim.text}\n\nEVIDENCE:\n{ev_text}"
        result = self.llm.complete_json(_SUPPORT_SYSTEM, user, _SUPPORT_SCHEMA)
        return bool(result["supported"]), str(result.get("reason", ""))
