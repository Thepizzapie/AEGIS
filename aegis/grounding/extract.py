"""Free-text claim extraction.

The adoption unlock: an agent writes a normal prose answer, and Receipts turns it
into a structured `Answer` (atomic claims, each bound to evidence ids, plus
declared assumptions) which the gate can then check. The agent doesn't have to
emit structured claims by hand.

Extraction is LLM-driven and therefore advisory — the *checking* of the extracted
claims stays deterministic in the gate, so a sloppy extraction surfaces as gate
failures rather than silently passing. The extractor is told the evidence ids and
their content so it can bind claims; the gate independently re-verifies every
binding it produces.
"""

from __future__ import annotations

from .ledger import Ledger
from .models import Answer, Assumption, Claim, ClaimKind

_SCHEMA = {
    "type": "object",
    "properties": {
        "claims": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "kind": {"type": "string", "enum": ["fact", "effort", "conclusion"]},
                    "evidence_ids": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["text", "kind", "evidence_ids"],
                "additionalProperties": False,
            },
        },
        "assumptions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "reason": {"type": "string"},
                    "impact": {"type": "string"},
                },
                "required": ["text", "reason", "impact"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["claims", "assumptions"],
    "additionalProperties": False,
}

_SYSTEM = (
    "You convert an AI agent's free-text answer into structured, checkable claims.\n"
    "Rules:\n"
    "1. Break the answer into atomic claims — one verifiable assertion each.\n"
    "2. Classify each: 'fact' (a stated fact), 'effort' (a claim about work the "
    "agent did, e.g. 'I searched the docs'), or 'conclusion' (an inference).\n"
    "3. For each claim, cite the evidence ids (from the EVIDENCE list) that back "
    "it. If nothing in the evidence supports a claim, cite NOTHING for it — do "
    "not invent ids.\n"
    "4. If the answer relies on something not backed by evidence, record it as an "
    "assumption with a reason and the impact if it's wrong, instead of forcing it "
    "into a claim.\n"
    "Only use evidence ids that appear in the EVIDENCE list verbatim."
)


def extract_claims(text: str, ledger: Ledger, llm) -> Answer:
    """Turn a free-text answer into a structured `Answer` ready for the gate.

    `llm` is a `receipts.llm.LLM`. The returned Answer keeps `text` as its summary;
    run it through `Gate.finalize()` / `audit()` to actually check the bindings.
    """
    ev_list = "\n".join(
        f"- {e.id} | {e.kind.value} | {e.source}\n    {_snippet(e.content)}"
        for e in ledger.all()
    )
    user = f"EVIDENCE:\n{ev_list or '(none)'}\n\nANSWER:\n{text}"
    result = llm.complete_json(_SYSTEM, user, _SCHEMA)

    claims = [
        Claim(
            text=c["text"],
            kind=ClaimKind(c.get("kind", "fact")),
            evidence_ids=list(c.get("evidence_ids", [])),
        )
        for c in result.get("claims", [])
    ]
    assumptions = [
        Assumption(text=a["text"], reason=a.get("reason", ""), impact=a.get("impact", ""))
        for a in result.get("assumptions", [])
    ]
    return Answer(claims=claims, assumptions=assumptions, summary=text)


def _snippet(content: str, limit: int = 300) -> str:
    content = " ".join(content.split())
    return content if len(content) <= limit else content[:limit] + "..."
