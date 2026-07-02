import json

from aegis.grounding import (
    Answer,
    Claim,
    ClaimKind,
    FakeLLM,
    Gate,
    Ledger,
    LLMSupportVerifier,
    audit,
    extract_claims,
    load_trace,
)
from aegis.grounding.adapters import from_openai_messages


# --- LLMSupportVerifier ----------------------------------------------------

def test_llm_support_verifier_blocks_when_unsupported():
    led = Ledger()
    ev = led.record("web_fetch", "https://x", "free tier allows 100 requests")
    llm = FakeLLM(lambda s, u, schema: {"supported": False, "reason": "evidence says 100, not 60"})
    gate = Gate(led, verifier=LLMSupportVerifier(llm))
    v = gate.check(Answer(claims=[Claim("limit is 60", evidence_ids=[ev.id])]))
    assert not v.ok
    assert "unsupported" in v.failures[0].failures[0]
    assert llm.calls  # the judge was actually consulted


def test_llm_support_verifier_passes_when_supported():
    led = Ledger()
    ev = led.record("web_fetch", "https://x", "free tier allows 100 requests")
    llm = FakeLLM(lambda s, u, schema: {"supported": True, "reason": "matches"})
    v = audit(
        Answer(claims=[Claim("limit is 100", evidence_ids=[ev.id])]),
        led,
        verifier=LLMSupportVerifier(llm),
    )
    assert v.ok, v.report()


def test_llm_verifier_not_called_for_effort_claims():
    led = Ledger()
    ev = led.record("web_fetch", "https://x", "data")
    called = {"n": 0}

    def handler(s, u, schema):
        called["n"] += 1
        return {"supported": True, "reason": ""}

    v = audit(
        Answer(claims=[Claim("I fetched the page", evidence_ids=[ev.id], kind=ClaimKind.EFFORT)]),
        led,
        verifier=LLMSupportVerifier(FakeLLM(handler)),
    )
    assert v.ok
    assert called["n"] == 0  # effort claims are checked structurally, not semantically


# --- extract_claims --------------------------------------------------------

def test_extract_claims_builds_answer():
    led = Ledger()
    ev = led.record("file_read", "config.py", "PORT = 8080")
    llm = FakeLLM(
        lambda s, u, schema: {
            "claims": [
                {"text": "The port is 8080", "kind": "fact", "evidence_ids": [ev.id]},
            ],
            "assumptions": [
                {"text": "paid tier differs", "reason": "not checked", "impact": "minor"},
            ],
        }
    )
    answer = extract_claims("The service runs on port 8080.", led, llm)
    assert len(answer.claims) == 1
    assert answer.claims[0].evidence_ids == [ev.id]
    assert len(answer.assumptions) == 1
    # The extracted answer then passes the deterministic gate.
    assert audit(answer, led).ok


def test_extracted_ungrounded_claim_is_caught_by_gate():
    led = Ledger()
    led.record("file_read", "config.py", "PORT = 8080")
    # LLM hallucinates an uncited claim — gate must still catch it.
    llm = FakeLLM(
        lambda s, u, schema: {
            "claims": [{"text": "the sky is green", "kind": "fact", "evidence_ids": []}],
            "assumptions": [],
        }
    )
    answer = extract_claims("...", led, llm)
    assert not audit(answer, led).ok


# --- openai adapter --------------------------------------------------------

def test_from_openai_messages_records_tool_results():
    led = Ledger()
    messages = [
        {"role": "user", "content": "look up the limit"},
        {
            "role": "assistant",
            "tool_calls": [
                {"id": "call_1", "function": {"name": "web_search", "arguments": "{}"}}
            ],
        },
        {"role": "tool", "tool_call_id": "call_1", "content": "the limit is 100"},
    ]
    from_openai_messages(led, messages)
    assert len(led) == 1
    ev = led.all()[0]
    assert ev.kind.value == "web_search"
    assert "100" in ev.content


# --- trace loading ---------------------------------------------------------

def test_load_trace_resolves_labels():
    data = {
        "evidence": [
            {"id": "e1", "kind": "file_read", "source": "config.py", "content": "PORT 8080"}
        ],
        "answer": {
            "summary": "port is 8080",
            "claims": [{"text": "PORT is 8080", "kind": "fact", "evidence_ids": ["e1"]}],
            "assumptions": [],
        },
    }
    ledger, answer = load_trace(data)
    assert len(ledger) == 1
    # label "e1" was resolved to the real content-hash id
    assert answer.claims[0].evidence_ids[0].startswith("ev_")
    assert audit(answer, ledger).ok


def test_load_trace_resolves_by_index():
    data = {
        "evidence": [{"kind": "file_read", "source": "a.py", "content": "alpha beta gamma"}],
        "answer": {"claims": [{"text": "alpha beta gamma", "kind": "fact", "evidence_ids": ["0"]}]},
    }
    ledger, answer = load_trace(data)
    assert audit(answer, ledger).ok


# --- CLI -------------------------------------------------------------------

def test_cli_audit_exit_codes(tmp_path):
    # The grounding CLI is folded into aegis as `aegis grounding audit`.
    from aegis.cli import main

    good = {
        "evidence": [{"id": "e1", "kind": "file_read", "source": "c.py", "content": "PORT 8080"}],
        "answer": {"claims": [{"text": "PORT is 8080", "kind": "fact", "evidence_ids": ["e1"]}]},
    }
    bad = {
        "evidence": [],
        "answer": {"claims": [{"text": "made up", "kind": "fact", "evidence_ids": []}]},
    }
    gp = tmp_path / "good.json"
    bp = tmp_path / "bad.json"
    gp.write_text(json.dumps(good), encoding="utf-8")
    bp.write_text(json.dumps(bad), encoding="utf-8")

    assert main(["grounding", "audit", str(gp)]) == 0
    assert main(["grounding", "audit", str(bp)]) == 1
    assert main(["grounding", "audit", str(bp), "--json"]) == 1
