"""Core data model for Receipts.

Everything here is plain data. The ground truth of "what the agent actually did"
lives in `Evidence` records inside the `Ledger`; everything an agent *says* is a
`Claim` that must point back at that ground truth.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class ClaimKind(str, Enum):
    """What flavour of statement a claim is — each is checked differently."""

    FACT = "fact"  # "The config loads from settings.json"
    EFFORT = "effort"  # "I searched the docs", "I read the whole file"
    CONCLUSION = "conclusion"  # "Therefore the bug is in the parser"


class EvidenceKind(str, Enum):
    """The observable action that produced a piece of evidence."""

    FILE_READ = "file_read"
    WEB_FETCH = "web_fetch"
    WEB_SEARCH = "web_search"
    COMMAND = "command"
    TEST_RUN = "test_run"
    TOOL_CALL = "tool_call"  # generic fallback


# Which evidence kinds legitimately back which effort verbs.
# "I searched" is only honest if there's a search in the ledger, etc. Local
# search (grep/rg) is recorded as a command or tool call, so those count too.
EFFORT_VERBS: dict[str, set[EvidenceKind]] = {
    "search": {
        EvidenceKind.WEB_SEARCH,
        EvidenceKind.WEB_FETCH,
        EvidenceKind.COMMAND,
        EvidenceKind.TOOL_CALL,
    },
    "fetch": {EvidenceKind.WEB_FETCH},
    "read": {EvidenceKind.FILE_READ},
    "review": {EvidenceKind.FILE_READ},
    "inspect": {EvidenceKind.FILE_READ, EvidenceKind.COMMAND},
    "test": {EvidenceKind.TEST_RUN},
    "run": {EvidenceKind.COMMAND, EvidenceKind.TEST_RUN},
    "verify": {EvidenceKind.TEST_RUN, EvidenceKind.COMMAND, EvidenceKind.FILE_READ},
}

# Words that assert total coverage. Using one is an overclaim unless the claim
# carries machine-checkable `coverage` proof. This is the "I reviewed the entire
# codebase" detector.
OVERCLAIM_WORDS: frozenset[str] = frozenset(
    {
        "all",
        "every",
        "entire",
        "complete",
        "completely",
        "thoroughly",
        "exhaustive",
        "exhaustively",
        "fully",
        "whole",
        "everything",
        "comprehensive",
        "comprehensively",
        "always",
        "never",
        "none",
    }
)

# Multi-word total-coverage phrases, matched as substrings of the lowercased
# claim text (the single-token set above can't catch these).
OVERCLAIM_PHRASES: tuple[str, ...] = ("no other", "nothing else")


@dataclass(frozen=True)
class Evidence:
    """A tamper-evident record of one thing the agent actually did."""

    id: str
    kind: EvidenceKind
    source: str  # path / url / command string
    content: str  # the payload that was actually returned
    content_hash: str
    ts: float = field(default_factory=time.time)
    meta: dict = field(default_factory=dict)


@dataclass
class Claim:
    """Something the agent asserts. Must point at evidence or be illegal."""

    text: str
    evidence_ids: list[str] = field(default_factory=list)
    kind: ClaimKind = ClaimKind.FACT
    confidence: float | None = None
    # Optional machine-checkable proof of coverage for overclaiming effort
    # claims, e.g. {"examined": 12, "total": 12}.
    coverage: dict | None = None


@dataclass
class Assumption:
    """A gap the agent chose NOT to verify — surfaced, never hidden."""

    text: str
    reason: str  # why it could not be / was not grounded
    impact: str = ""  # what breaks if the assumption is wrong


@dataclass
class Answer:
    """The agent's complete output: claims + the assumptions it's standing on."""

    claims: list[Claim] = field(default_factory=list)
    assumptions: list[Assumption] = field(default_factory=list)
    summary: str = ""  # human-facing prose, assembled from the claims


@dataclass
class ClaimResult:
    """Per-claim verdict from the verifier."""

    claim: Claim
    ok: bool
    failures: list[str] = field(default_factory=list)


@dataclass
class Verdict:
    """The outcome of checking an Answer against a Ledger."""

    ok: bool
    results: list[ClaimResult] = field(default_factory=list)
    assumptions: list[Assumption] = field(default_factory=list)
    # claimed vs. logged effort, the headline anti-fabrication metric
    claimed_effort: int = 0
    logged_evidence: int = 0

    @property
    def failures(self) -> list[ClaimResult]:
        return [r for r in self.results if not r.ok]

    def report(self) -> str:
        lines = [
            f"Verdict: {'PASS' if self.ok else 'BLOCKED'}",
            f"  claims: {len(self.results)}  "
            f"grounded: {sum(r.ok for r in self.results)}  "
            f"failed: {len(self.failures)}",
            f"  effort claimed: {self.claimed_effort}  "
            f"evidence logged: {self.logged_evidence}",
            f"  assumptions declared: {len(self.assumptions)}",
        ]
        for r in self.failures:
            lines.append(f"  x {r.claim.text!r}")
            for f in r.failures:
                lines.append(f"      - {f}")
        return "\n".join(lines)
