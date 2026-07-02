"""Grounding: force an agent to back every claim with evidence, or declare it.

Vendored from the standalone Receipts engine (formerly the ``receipts-gate``
package) and folded into Aegis. Aegis governs what an agent *does* (the hook
boundary); grounding governs what an agent *claims* (its answers), checked against
a tamper-evident ledger of what actually happened. Deterministic core, zero deps;
the LLM support judge / free-text extractor are optional (need ``anthropic``).

    from aegis.grounding import Ledger, Gate, Answer, Claim, ClaimKind

    ledger = Ledger()
    ev = ledger.record("file_read", "config.py", "PORT = 8080")
    gate = Gate(ledger)  # hard gate by default
    print(gate.finalize(Answer(
        summary="The service listens on port 8080.",
        claims=[Claim("The port is 8080", evidence_ids=[ev.id], kind=ClaimKind.FACT)],
    )))

Aegis integration: ``ledger_from_audit()`` builds a grounding Ledger straight from
Aegis's own audit trail, so an agent's final answer can be gated against the tools
it actually ran — no separate instrumentation.
"""

from .audit_bridge import ledger_from_audit
from .errors import ReceiptsError, UngroundedAnswerError
from .extract import extract_claims
from .gate import Gate, audit, render
from .instrument import ingest_trace, track
from .ledger import Ledger
from .llm import AnthropicLLM, FakeLLM
from .models import (
    Answer,
    Assumption,
    Claim,
    ClaimKind,
    ClaimResult,
    Evidence,
    EvidenceKind,
    Verdict,
)
from .trace import load_trace
from .verify import (
    HeuristicVerifier,
    LLMSupportVerifier,
    NullVerifier,
    SupportVerifier,
)

# Backwards-compatible aliases for code migrating off `receipts-gate`.
ReceiptsError = ReceiptsError
GroundingError = ReceiptsError

__all__ = [
    "Ledger",
    "Gate",
    "audit",
    "render",
    "track",
    "ingest_trace",
    "load_trace",
    "ledger_from_audit",
    "extract_claims",
    "AnthropicLLM",
    "FakeLLM",
    "Answer",
    "Assumption",
    "Claim",
    "ClaimKind",
    "ClaimResult",
    "Evidence",
    "EvidenceKind",
    "Verdict",
    "HeuristicVerifier",
    "LLMSupportVerifier",
    "NullVerifier",
    "SupportVerifier",
    "ReceiptsError",
    "GroundingError",
    "UngroundedAnswerError",
]
