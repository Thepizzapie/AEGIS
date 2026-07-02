from aegis.grounding import Ledger, audit, Answer, Claim
from aegis.grounding.adapters import from_anthropic_messages, record_tool_end


# --- Anthropic / Claude Agent SDK trace ------------------------------------

def test_from_anthropic_messages_dict_blocks():
    led = Ledger()
    messages = [
        {"role": "user", "content": "what's the limit?"},
        {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "let me check"},
                {"type": "tool_use", "id": "tu_1", "name": "web_search", "input": {}},
            ],
        },
        {
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": "tu_1", "content": "the limit is 100"}
            ],
        },
    ]
    from_anthropic_messages(led, messages)
    assert len(led) == 1
    ev = led.all()[0]
    assert ev.kind.value == "web_search"
    assert "100" in ev.content


def test_from_anthropic_messages_list_content_and_object_blocks():
    led = Ledger()

    class Block:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    messages = [
        {"role": "assistant", "content": [Block(type="tool_use", id="x", name="read_file")]},
        {
            "role": "user",
            "content": [
                Block(
                    type="tool_result",
                    tool_use_id="x",
                    content=[Block(type="text", text="PORT = 8080")],
                    is_error=False,
                )
            ],
        },
    ]
    from_anthropic_messages(led, messages)
    ev = led.all()[0]
    assert ev.kind.value == "file_read"
    assert "8080" in ev.content
    # the recorded evidence is usable end-to-end
    assert audit(Answer(claims=[Claim("PORT is 8080", evidence_ids=[ev.id])]), led).ok


def test_from_anthropic_messages_ignores_plain_text_turns():
    led = Ledger()
    from_anthropic_messages(led, [{"role": "assistant", "content": "just talking"}])
    assert len(led) == 0


# --- LangChain recording logic (no langchain dependency needed) -------------

def test_record_tool_end_infers_kind():
    led = Ledger()
    record_tool_end(led, "web_search", "results here")
    record_tool_end(led, "read_file", "file body")
    kinds = [e.kind.value for e in led.all()]
    assert kinds == ["web_search", "file_read"]


def test_record_tool_end_custom_kind():
    led = Ledger()
    from aegis.grounding.models import EvidenceKind

    record_tool_end(led, "mystery", "x", name_to_kind=lambda n: EvidenceKind.COMMAND)
    assert led.all()[0].kind.value == "command"
