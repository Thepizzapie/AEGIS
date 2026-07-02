"""Load a portable trace file into a (Ledger, Answer) pair for the auditor/CLI.

Trace format (JSON):

    {
      "evidence": [
        {"id": "e1", "kind": "file_read", "source": "config.py", "content": "..."}
      ],
      "answer": {
        "summary": "...",
        "claims": [
          {"text": "...", "kind": "fact", "evidence_ids": ["e1"], "coverage": null}
        ],
        "assumptions": [{"text": "...", "reason": "...", "impact": ""}]
      }
    }

Evidence ids in the ledger are content-derived, so a hand-written or
framework-exported trace can't know them ahead of time. To keep claims
authorable, each evidence entry may carry a *local label* (`id`), and claims may
reference evidence by that label, by list index ("0", "1", ...), or by the real
ledger id. This loader resolves all three to the real id before auditing.
"""

from __future__ import annotations

from .ledger import Ledger
from .models import Answer, Assumption, Claim, ClaimKind


def load_trace(data: dict) -> tuple[Ledger, Answer]:
    ledger = Ledger()
    label_to_id: dict[str, str] = {}
    records: list[tuple[dict, object]] = []

    for i, ev in enumerate(data.get("evidence", [])):
        rec = ledger.record(ev["kind"], ev.get("source", ""), str(ev.get("content", "")))
        label_to_id[str(i)] = rec.id  # positional alias
        label_to_id[rec.id] = rec.id  # identity
        records.append((ev, rec))

    # Explicit labels are assigned last so they win over positional aliases:
    # a trace using 1-based numeric ids ("1", "2", ...) must resolve "1" to the
    # entry labeled "1", not to the entry at index 1.
    for ev, rec in records:
        if ev.get("id"):
            label_to_id[str(ev["id"])] = rec.id

    ans = data.get("answer", {})
    claims = []
    for c in ans.get("claims", []):
        ids = [label_to_id.get(str(x), str(x)) for x in c.get("evidence_ids", [])]
        claims.append(
            Claim(
                text=c["text"],
                kind=ClaimKind(c.get("kind", "fact")),
                evidence_ids=ids,
                confidence=c.get("confidence"),
                coverage=c.get("coverage"),
            )
        )
    assumptions = [
        Assumption(text=a["text"], reason=a.get("reason", ""), impact=a.get("impact", ""))
        for a in ans.get("assumptions", [])
    ]
    return ledger, Answer(claims=claims, assumptions=assumptions, summary=ans.get("summary", ""))
