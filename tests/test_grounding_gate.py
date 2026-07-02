from aegis.grounding import (
    Answer,
    Assumption,
    Claim,
    ClaimKind,
    Gate,
    Ledger,
    UngroundedAnswerError,
    audit,
    ingest_trace,
)


def fresh_ledger() -> Ledger:
    led = Ledger()
    led.record("file_read", "config.py", "PORT = 8080 and DEBUG is False")
    led.record("web_fetch", "https://x/limits", "free tier allows 100 requests")
    return led


# --- BINDING ---------------------------------------------------------------

def test_uncited_claim_is_blocked():
    led = fresh_ledger()
    v = audit(Answer(claims=[Claim("the port is 8080")]), led)
    assert not v.ok
    assert "no evidence cited" in v.failures[0].failures[0]


def test_claim_citing_unknown_evidence_is_blocked():
    led = fresh_ledger()
    v = audit(Answer(claims=[Claim("x", evidence_ids=["ev_deadbeef"])]), led)
    assert not v.ok
    assert "not in the ledger" in v.failures[0].failures[0]


def test_grounded_supported_claim_passes():
    led = fresh_ledger()
    ev = led.all()[0]
    v = audit(Answer(claims=[Claim("the PORT is 8080", evidence_ids=[ev.id])]), led)
    assert v.ok, v.report()


# --- EFFORT HONESTY --------------------------------------------------------

def test_overclaim_without_coverage_is_blocked():
    led = fresh_ledger()
    ev = led.all()[0]
    v = audit(
        Answer(
            claims=[
                Claim(
                    "I reviewed the entire codebase",
                    evidence_ids=[ev.id],
                    kind=ClaimKind.EFFORT,
                )
            ]
        ),
        led,
    )
    assert not v.ok
    assert any("total-coverage" in f for f in v.failures[0].failures)


def test_overclaim_with_full_coverage_passes():
    led = fresh_ledger()
    ev = led.all()[0]
    v = audit(
        Answer(
            claims=[
                Claim(
                    "I reviewed every file",
                    evidence_ids=[ev.id],
                    kind=ClaimKind.EFFORT,
                    coverage={"examined": 1, "total": 1},
                )
            ]
        ),
        led,
    )
    assert v.ok, v.report()


def test_effort_verb_without_matching_evidence_kind_is_blocked():
    led = fresh_ledger()
    file_ev = led.all()[0]  # file_read, not a search
    v = audit(
        Answer(
            claims=[
                Claim(
                    "I searched the web for the limits",
                    evidence_ids=[file_ev.id],
                    kind=ClaimKind.EFFORT,
                )
            ]
        ),
        led,
    )
    assert not v.ok
    assert any("search" in f for f in v.failures[0].failures)


def test_effort_verb_with_matching_evidence_passes():
    led = fresh_ledger()
    web_ev = led.all()[1]  # web_fetch
    v = audit(
        Answer(
            claims=[
                Claim(
                    "I fetched the limits page",
                    evidence_ids=[web_ev.id],
                    kind=ClaimKind.EFFORT,
                )
            ]
        ),
        led,
    )
    assert v.ok, v.report()


# --- SUPPORT ---------------------------------------------------------------

def test_claim_contradicted_by_evidence_is_blocked():
    led = fresh_ledger()
    web_ev = led.all()[1]  # says "100 requests"
    v = audit(
        Answer(
            claims=[
                Claim(
                    "the quantum flux capacitor melted yesterday",
                    evidence_ids=[web_ev.id],
                )
            ]
        ),
        led,
    )
    assert not v.ok
    assert any("unsupported" in f for f in v.failures[0].failures)


# --- HARD GATE -------------------------------------------------------------

def test_hard_gate_raises():
    led = fresh_ledger()
    gate = Gate(led)
    try:
        gate.finalize(Answer(claims=[Claim("ungrounded")]))
    except UngroundedAnswerError as e:
        assert not e.verdict.ok
    else:
        raise AssertionError("expected UngroundedAnswerError")


def test_soft_gate_renders_with_warning():
    led = fresh_ledger()
    gate = Gate(led, hard=False)
    out = gate.finalize(Answer(summary="hi", claims=[Claim("ungrounded")]))
    assert "did not pass" in out


def test_effort_count_metric():
    led = fresh_ledger()
    ev = led.all()[1]
    v = audit(
        Answer(
            claims=[
                Claim("I fetched the page", evidence_ids=[ev.id], kind=ClaimKind.EFFORT)
            ]
        ),
        led,
    )
    assert v.claimed_effort == 1
    assert v.logged_evidence == 2


# --- POST-HOC INGEST -------------------------------------------------------

def test_ingest_trace_then_audit():
    led = Ledger()
    ingest_trace(
        led,
        [
            {"kind": "file_read", "source": "a.py", "content": "alpha beta gamma"},
            {"kind": "command", "source": "pytest", "content": "5 passed"},
        ],
    )
    assert len(led) == 2
    ev = led.all()[0]
    v = audit(Answer(claims=[Claim("alpha beta gamma found", evidence_ids=[ev.id])]), led)
    assert v.ok, v.report()


def test_assumptions_pass_through_to_verdict():
    led = fresh_ledger()
    v = audit(
        Answer(assumptions=[Assumption("paid tier is higher", reason="not checked")]),
        led,
    )
    assert v.ok
    assert len(v.assumptions) == 1
