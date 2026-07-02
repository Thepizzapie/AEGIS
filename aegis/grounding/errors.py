"""Exceptions raised by the hard gate."""

from __future__ import annotations


class ReceiptsError(Exception):
    """Base class."""


class UngroundedAnswerError(ReceiptsError):
    """Raised by Gate.finalize() when an Answer fails verification.

    Carries the full Verdict so callers can show the agent exactly what to fix.
    """

    def __init__(self, verdict) -> None:  # verdict: Verdict
        self.verdict = verdict
        super().__init__(verdict.report())
