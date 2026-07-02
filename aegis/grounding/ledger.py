"""The Ledger: the single source of truth for what an agent actually did.

Nothing else in Receipts trusts the agent's word. Claims are checked against the
contents of a Ledger, and the Ledger is only ever appended to by the
instrumentation layer that wraps real tool calls.
"""

from __future__ import annotations

import hashlib

from .models import Evidence, EvidenceKind


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Ledger:
    """Append-only log of Evidence, keyed by a short content-derived id."""

    def __init__(self) -> None:
        self._by_id: dict[str, Evidence] = {}
        self._order: list[str] = []

    def record(
        self,
        kind: EvidenceKind | str,
        source: str,
        content: str,
        **meta,
    ) -> Evidence:
        """Append a piece of evidence and return it (with its assigned id)."""
        kind = EvidenceKind(kind)
        chash = _hash(f"{kind.value}|{source}|{content}")
        eid = f"ev_{chash[:8]}"
        ev = Evidence(
            id=eid,
            kind=kind,
            source=source,
            content=content,
            content_hash=chash,
            meta=dict(meta),
        )
        # Idempotent: identical action recorded twice collapses to one record.
        if eid not in self._by_id:
            self._by_id[eid] = ev
            self._order.append(eid)
        return self._by_id[eid]

    def get(self, eid: str) -> Evidence | None:
        return self._by_id.get(eid)

    def has(self, eid: str) -> bool:
        return eid in self._by_id

    def all(self) -> list[Evidence]:
        return [self._by_id[i] for i in self._order]

    def of_kind(self, *kinds: EvidenceKind) -> list[Evidence]:
        wanted = set(kinds)
        return [e for e in self.all() if e.kind in wanted]

    def __len__(self) -> int:
        return len(self._order)
