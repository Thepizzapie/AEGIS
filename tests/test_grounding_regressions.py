"""Regression tests for the pre-publish review findings (v0.1.0)."""

from aegis.grounding import Answer, Claim, ClaimKind, Ledger, audit, load_trace


# --- trace label resolution --------------------------------------------------

def test_one_based_numeric_labels_resolve_to_explicit_ids():
    # Explicit labels must win over positional aliases: label "1" is the FIRST
    # entry here, but positionally "1" would be the second.
    data = {
        "evidence": [
            {"id": "1", "kind": "file_read", "source": "config.py",
             "content": "PORT = 8080 configured for the service"},
            {"id": "2", "kind": "web_fetch", "source": "https://x/limits",
             "content": "free tier allows 100 requests"},
        ],
        "answer": {
            "summary": "",
            "claims": [
                {"text": "the service PORT is configured 8080", "kind": "fact",
                 "evidence_ids": ["1"]},
                {"text": "free tier allows 100 requests", "kind": "fact",
                 "evidence_ids": ["2"]},
            ],
        },
    }
    ledger, answer = load_trace(data)
    assert ledger.get(answer.claims[0].evidence_ids[0]).source == "config.py"
    assert ledger.get(answer.claims[1].evidence_ids[0]).source == "https://x/limits"
    assert audit(answer, ledger).ok


def test_positional_aliases_still_work_without_explicit_ids():
    data = {
        "evidence": [
            {"kind": "file_read", "source": "a.py", "content": "alpha beta gamma"},
            {"kind": "file_read", "source": "b.py", "content": "delta epsilon zeta"},
        ],
        "answer": {
            "claims": [{"text": "delta epsilon zeta", "evidence_ids": ["1"]}],
        },
    }
    ledger, answer = load_trace(data)
    assert ledger.get(answer.claims[0].evidence_ids[0]).source == "b.py"


# --- coverage proof type validation ------------------------------------------

def _effort_ledger() -> Ledger:
    led = Ledger()
    led.record("file_read", "config.py", "PORT = 8080 and DEBUG is False")
    return led


def test_string_coverage_values_are_compared_numerically():
    led = _effort_ledger()
    ev = led.all()[0]
    claim = Claim(
        "I reviewed every module",
        evidence_ids=[ev.id],
        kind=ClaimKind.EFFORT,
        coverage={"examined": "5", "total": "10"},
    )
    v = audit(Answer(claims=[claim]), led)
    assert not v.ok
    assert "5/10" in v.failures[0].failures[0]


def test_non_numeric_coverage_fails_instead_of_raising():
    led = _effort_ledger()
    ev = led.all()[0]
    claim = Claim(
        "I reviewed every module",
        evidence_ids=[ev.id],
        kind=ClaimKind.EFFORT,
        coverage={"examined": "some", "total": "all of them"},
    )
    v = audit(Answer(claims=[claim]), led)  # must not raise
    assert not v.ok
    assert "not numeric" in v.failures[0].failures[0]


# --- zero-claims summary bypass ----------------------------------------------

def test_summary_with_no_claims_and_no_assumptions_is_blocked():
    v = audit(
        Answer(summary="I exhaustively audited the entire system; zero issues."),
        Ledger(),
    )
    assert not v.ok
    assert "nothing for the gate to check" in v.failures[0].failures[0]


def test_summary_with_declared_assumptions_still_passes():
    from aegis.grounding import Assumption

    v = audit(
        Answer(
            summary="Probably fine, but unverified.",
            assumptions=[Assumption("It is fine", reason="did not check")],
        ),
        Ledger(),
    )
    assert v.ok


def test_empty_answer_passes():
    assert audit(Answer(), Ledger()).ok


# --- effort verb / evidence kind mapping -------------------------------------

def test_search_claim_backed_by_command_evidence_passes():
    led = Ledger()
    ev = led.record("command", "rg 'foo' src/", "src/a.py:3: foo()\nsrc/b.py:9: foo()")
    claim = Claim(
        "I searched the codebase for usages of foo",
        evidence_ids=[ev.id],
        kind=ClaimKind.EFFORT,
    )
    v = audit(Answer(claims=[claim]), led)
    assert v.ok, v.report()


# --- errored evidence cannot back claims -------------------------------------

def test_errored_evidence_does_not_back_effort_claim():
    led = Ledger()
    ev = led.record(
        "web_fetch", "https://x/limits",
        "404 Not Found: could not fetch the limits page", is_error=True,
    )
    claim = Claim(
        "I fetched the limits page", evidence_ids=[ev.id], kind=ClaimKind.EFFORT
    )
    v = audit(Answer(claims=[claim]), led)
    assert not v.ok


# --- multi-word overclaim phrases --------------------------------------------

def test_no_other_phrase_requires_coverage_proof():
    led = _effort_ledger()
    ev = led.all()[0]
    claim = Claim(
        "I read the config; no other files matter",
        evidence_ids=[ev.id],
        kind=ClaimKind.EFFORT,
    )
    v = audit(Answer(claims=[claim]), led)
    assert not v.ok
    assert "no other" in v.failures[0].failures[0]
