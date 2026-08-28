"""The model seam, SPEC.md §15: recorded and replayed, no API key needed.

The replay path is the one the harness runs, so its failure mode matters more
than its success case. A replay that fell through to a live call would make
"no API key needed" true only until someone edited a prompt; a replay that fell
through to a default would make every edited prompt look like a passing test.
"""

from __future__ import annotations

import json

import pytest

from agent.llm import (
    PRIMARY_MODEL,
    SCRIPTED_MODEL_ID,
    CassetteMiss,
    CassetteModel,
    ScriptedModel,
    Turn,
    build_model,
)

TOOL = {
    "name": "choose_payee",
    "strict": True,
    "input_schema": {
        "type": "object",
        "properties": {"payee": {"type": "string"}},
        "required": ["payee"],
        "additionalProperties": False,
    },
}


def _turn(prose="anything"):
    return Turn(
        step="choose_payee",
        system="frozen",
        messages=[{"role": "user", "content": json.dumps({"facts": {}, "prose": prose})}],
        tool=TOOL,
    )


def test_the_cassette_key_covers_everything_that_could_change_an_answer():
    base = _turn()
    assert base.key(PRIMARY_MODEL) == _turn().key(PRIMARY_MODEL)
    assert base.key(PRIMARY_MODEL) != base.key("claude-sonnet-5")
    assert base.key(PRIMARY_MODEL) != _turn("different prose").key(PRIMARY_MODEL)

    widened = Turn(
        step=base.step,
        system="frozen, but edited",
        messages=base.messages,
        tool=base.tool,
    )
    assert widened.key(PRIMARY_MODEL) != base.key(PRIMARY_MODEL)


def test_a_cassette_replays_exactly_what_was_recorded(tmp_path):
    turn = _turn()
    cassette = tmp_path / "c.jsonl"
    cassette.write_text(
        json.dumps(
            {
                "key": turn.key(PRIMARY_MODEL),
                "step": turn.step,
                "model": PRIMARY_MODEL,
                "output": {"payee": "merchant@upi"},
                "usage": {"cache_read_input_tokens": 4096},
            }
        )
        + "\n"
    )

    reply = CassetteModel(path=cassette).decide(turn)
    assert reply.output == {"payee": "merchant@upi"}
    assert reply.model_id == PRIMARY_MODEL
    assert reply.usage["cache_read_input_tokens"] == 4096


def test_a_changed_prompt_misses_loudly(tmp_path):
    cassette = tmp_path / "c.jsonl"
    cassette.write_text(
        json.dumps({"key": "sha256:" + "0" * 64, "output": {"payee": "x"}}) + "\n"
    )
    with pytest.raises(CassetteMiss, match="re-record"):
        CassetteModel(path=cassette).decide(_turn())


def test_build_model_prefers_a_cassette_over_a_live_call(tmp_path, monkeypatch):
    """A recording is reproducible and a live call is not, so a recording must
    never be silently overtaken by a fresh call."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key")
    cassette = tmp_path / "c.jsonl"
    cassette.write_text("")
    assert isinstance(build_model("auto", cassette), CassetteModel)


def test_build_model_falls_back_to_the_stand_in_with_no_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    model = build_model("auto")
    assert isinstance(model, ScriptedModel)
    assert model.model_id == SCRIPTED_MODEL_ID


def test_an_unknown_model_name_is_refused():
    with pytest.raises(ValueError, match="unknown model"):
        build_model("gpt-9")


def test_the_stand_in_labels_itself_in_every_run_record():
    """No number produced with the stand-in may be quoted as an ASR figure, so
    the run record has to say what produced it — every time, not when someone
    remembers."""
    from harness.runner import run_case

    record = run_case("benign-01", config="undefended", model="scripted")
    assert record.model == SCRIPTED_MODEL_ID
    assert any("not a model measurement" in note for note in record.notes)


def test_the_step_tools_are_strict_in_all_three_ways():
    """``strict`` without ``additionalProperties: false`` and a full
    ``required`` list is a claim about the prompt, not a property of the
    request."""
    from agent.planner import STEP_TOOLS

    for name, tool in STEP_TOOLS.items():
        assert tool["strict"] is True, name
        schema = tool["input_schema"]
        assert schema["additionalProperties"] is False, name
        assert sorted(schema["required"]) == sorted(schema["properties"]), name


def test_the_system_prompt_carries_nothing_case_specific():
    """Caching is a prefix match: one per-case value here costs every case its
    cache hit (SPEC.md §10)."""
    from agent.planner import SYSTEM_PROMPT

    for volatile in ("benign-01", "A1-", "2026-", "seed", "merchant@upi"):
        assert volatile not in SYSTEM_PROMPT
