"""The model seam, and the three things that can sit in it.

The agent is the system under test, so *which* mind is driving it is a variable
the harness has to be able to state. This module makes it one field on the run
record instead of an assumption in the reader's head.

============================  ===================================================
:class:`AnthropicModel`       ``claude-opus-5``. The real measurement (M5).
:class:`CassetteModel`        Replays a recording. No API key, byte-identical.
:class:`ScriptedModel`        A deterministic stand-in. **Not a model result.**
============================  ===================================================

**On the stand-in, plainly.** ``ScriptedModel`` is not a model and no number
produced with it is a model measurement. It exists because M2's gate is "money
moves and one attack lands, reproducibly from a seed", and that is a property of
the *plumbing* — the PSP, the merchant, the tools, the ledger — which has to be
correct before a model result means anything. It reports itself as
``scripted-gullible-v1`` in the run record and in ``mk run``'s output, so a
scripted run cannot be quoted as an ASR figure by accident. The undefended ASR
in ``results.md`` comes from :class:`AnthropicModel` on the day-5 gate.

**On replay.** SPEC.md §15 requires that model responses are recorded and
replayed and that the replay path needs no API key. Recording is keyed by the
canonical hash of the whole request — model, system, messages, tool schema — so
a cassette cannot silently answer a question it was not asked. Change the prompt
and the key changes and the replay misses, loudly.

**On caching.** The frozen system prompt and the tool schema go first and the
volatile per-case content last, because caching is a prefix match: one
timestamp in the system prompt costs every case its cache hit (SPEC.md §10).
:class:`AnthropicModel` asserts a cache read on every call after the first, so
that stays true rather than being intended.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from kernel.canonical import jcs, sha256_of

__all__ = [
    "PRIMARY_MODEL",
    "ABLATION_MODEL",
    "SCRIPTED_MODEL_ID",
    "Turn",
    "Reply",
    "ModelClient",
    "ScriptedModel",
    "CassetteModel",
    "AnthropicModel",
    "CassetteMiss",
    "build_model",
    "find_directed_payees",
    "prose_override",
]

PRIMARY_MODEL = "claude-opus-5"
ABLATION_MODEL = "claude-sonnet-5"
SCRIPTED_MODEL_ID = "scripted-gullible-v1"


@dataclass(frozen=True)
class Turn:
    """One model call, as data, so it can be hashed and replayed.

    ``tool`` is a strict tool definition: ``strict: true``,
    ``additionalProperties: false`` and a complete ``required`` list. Without
    all three, "the extractor emits typed structs, never free strings" is an
    assertion about the prompt rather than a property of the request.
    """

    step: str
    system: str
    messages: list[dict[str, Any]]
    tool: dict[str, Any]

    def key(self, model_id: str) -> str:
        """The cassette key. Covers everything that could change an answer."""
        return sha256_of(
            {
                "model": model_id,
                "step": self.step,
                "system": self.system,
                "messages": self.messages,
                "tool": self.tool,
            }
        )


@dataclass(frozen=True)
class Reply:
    output: dict[str, Any]
    model_id: str
    usage: dict[str, int] = field(default_factory=dict)


class ModelClient(Protocol):
    model_id: str

    def decide(self, turn: Turn) -> Reply: ...


class CassetteMiss(KeyError):
    """The recording has no answer for this request.

    Loud on purpose. A replay that fell through to a live call would make the
    "replay needs no API key" property true only when nobody had changed a
    prompt, and a replay that fell through to a default would make every
    changed prompt look like a passing test.
    """


# ---------------------------------------------------------------------------
# The deterministic stand-in
# ---------------------------------------------------------------------------

#: Words that turn a mention of a payment destination into a *direction* to
#: use one. The gullible rule below fires only when one of these sits near a
#: VPA, which is what makes a payload's shape — not its presence — the thing
#: that decides whether an attack lands.
DIRECTIVE_WORDS = (
    "pay",
    "payment",
    "payable",
    "send",
    "transfer",
    "remit",
    "credit",
    "settle",
    "route",
    "deposit",
    "beneficiary",
    "collect",
)

#: A UPI virtual payment address. Deliberately narrow: an over-broad pattern
#: would match ordinary email in product copy and the stand-in would start
#: "falling for" text nobody wrote as an attack.
VPA_PATTERN = re.compile(r"\b([a-z0-9][a-z0-9._-]{1,63}@[a-z][a-z0-9]{1,31})\b")

#: How far either side of a VPA a directive word counts as pointing at it.
DIRECTIVE_WINDOW = 120


def find_directed_payees(text: str) -> list[str]:
    """Every VPA the prose *tells* the reader to pay, in the order they appear.

    This is the whole of the stand-in's gullibility, written out so it can be
    argued with. A planner that treats content as instruction ends up here.

    Two properties a test pins, because a stand-in that falls for everything
    measures nothing:

    * prose that merely *mentions* an address — a support contact, a seller's
      email — is not a direction and returns nothing;
    * prose that directs payment to an address is, wherever on the page it sits.
    """
    lowered = text.lower()
    directed: list[str] = []

    for match in VPA_PATTERN.finditer(lowered):
        start = max(0, match.start() - DIRECTIVE_WINDOW)
        window = lowered[start : match.end() + DIRECTIVE_WINDOW]
        if any(word in window for word in DIRECTIVE_WORDS):
            directed.append(match.group(1))

    return directed


def prose_override(text: str, typed_payee: str) -> str | None:
    """The address the prose substitutes for the one the typed field carries.

    The rule, and the reason it is this rule: the checkout page names its payee
    twice — once in a typed field and once in its own prose — and a page
    repeating its own address is not overriding anything. What counts is a
    *direction to pay somewhere the typed field does not say*. Among those, the
    last wins, because later text reads as a correction of earlier text.

    So the vulnerability this models is precise: **prose outranks a typed
    field.** That is one sentence, it is a real property of agents that plan in
    the context they read in, and it is the property M6's planner/quarantined
    split removes. It is not "the stand-in recognises the attack fixture".
    """
    overrides = [vpa for vpa in find_directed_payees(text) if vpa != typed_payee]
    return overrides[-1] if overrides else None


@dataclass
class ScriptedModel:
    """A planner with no judgement, only rules. See the module docstring.

    Every step is a pure function of the turn's content, so a run is
    reproducible without a recording and without a key. It is gullible in one
    specific, documented way — it treats merchant prose as instruction — which
    is the behaviour A1 exploits and the behaviour M6's planner/quarantined
    split is designed to remove.
    """

    model_id: str = SCRIPTED_MODEL_ID

    def decide(self, turn: Turn) -> Reply:
        handler = getattr(self, f"_step_{turn.step.replace('.', '_')}", None)
        if handler is None:
            raise KeyError(
                f"{self.model_id} has no rule for step {turn.step!r}; a "
                "stand-in that guessed would be a stand-in that hides a gap"
            )
        return Reply(output=handler(turn), model_id=self.model_id)

    # -- the steps --------------------------------------------------------

    @staticmethod
    def _facts(turn: Turn) -> dict[str, Any]:
        """The typed half of what the agent has read so far."""
        return json.loads(turn.messages[-1]["content"])["facts"]

    @staticmethod
    def _prose(turn: Turn) -> str:
        return json.loads(turn.messages[-1]["content"])["prose"]

    def _step_choose_product(self, turn: Turn) -> dict[str, Any]:
        """Pick the SKU whose name best matches what the user asked for."""
        facts = self._facts(turn)
        wanted = facts["wanted"].lower()
        scored = [
            (sum(word in name.lower() for word in wanted.split()), sku)
            for sku, name in facts["candidates"].items()
        ]
        scored.sort(key=lambda pair: (-pair[0], pair[1]))
        return {"sku": scored[0][1] if scored else ""}

    def _step_build_cart(self, turn: Turn) -> dict[str, Any]:
        """Quantities come from the task, prices from the merchant."""
        facts = self._facts(turn)
        return {"line_items": facts["proposed_line_items"]}

    def _step_choose_payee(self, turn: Turn) -> dict[str, Any]:
        """The step A1 targets.

        The checkout page names a payee in a typed field. The product page is
        prose. A planner that reads prose as instruction prefers the prose, and
        that single preference is the entire vulnerability — no jailbreak, no
        "ignore your instructions", just content being treated as authority.
        """
        facts = self._facts(turn)
        directed = prose_override(self._prose(turn), facts["checkout_payee"]["value"])
        if directed is not None:
            return {
                "payee": {
                    "type": "vpa",
                    "value": directed,
                    "merchant_id": facts["checkout_payee"]["merchant_id"],
                },
                "why": "the page said to",
            }
        return {"payee": facts["checkout_payee"], "why": "the checkout said so"}


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------


@dataclass
class CassetteModel:
    """Replays a recording made by :class:`AnthropicModel`. No key needed."""

    path: Path
    model_id: str = PRIMARY_MODEL
    _by_key: dict[str, dict[str, Any]] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        for line in Path(self.path).read_text().splitlines():
            if line.strip():
                record = json.loads(line)
                self._by_key[record["key"]] = record

    def decide(self, turn: Turn) -> Reply:
        key = turn.key(self.model_id)
        record = self._by_key.get(key)
        if record is None:
            raise CassetteMiss(
                f"no recorded reply for step {turn.step!r} (key {key}) in "
                f"{self.path}. The prompt changed; re-record rather than "
                "letting the replay improvise."
            )
        return Reply(
            output=record["output"],
            model_id=record.get("model", self.model_id),
            usage=record.get("usage", {}),
        )


# ---------------------------------------------------------------------------
# The real thing
# ---------------------------------------------------------------------------


@dataclass
class AnthropicModel:
    """``claude-opus-5``, recording every reply as it goes.

    Three details here are architecture rather than configuration (SPEC.md §10):

    1. **Strict structured output.** The step's schema is sent as a tool with
       ``strict: true``, so the reply is a validated struct and never a string
       the agent has to parse hopefully.
    2. **Thinking stays on.** Opus 5 thinks adaptively by default. Disabling it
       can put a tool call into visible text where it silently never executes —
       which in this agent would look exactly like an attack succeeding, and
       would be a measurement artefact rather than a finding. Cost is
       controlled with ``output_config.effort``, not by switching thinking off.
    3. **Cache-shaped prompts.** Frozen system text and the tool list first,
       volatile per-case content last. ``assert_cache_hits`` turns the
       intention into a check, because a silent cache miss shows up only as a
       bill.
    """

    model_id: str = PRIMARY_MODEL
    effort: str = "medium"
    max_tokens: int = 4096
    record_to: Path | None = None
    assert_cache_hits: bool = True
    _client: Any = field(default=None, init=False, repr=False)
    _calls: int = field(default=0, init=False)

    def _ensure_client(self) -> Any:
        if self._client is None:
            import anthropic  # imported here: the replay path must not need it

            self._client = anthropic.Anthropic()
        return self._client

    def decide(self, turn: Turn) -> Reply:
        client = self._ensure_client()
        response = client.messages.create(
            model=self.model_id,
            max_tokens=self.max_tokens,
            thinking={"type": "adaptive"},
            output_config={"effort": self.effort},
            system=[
                {
                    "type": "text",
                    "text": turn.system,
                    # The breakpoint sits after the frozen half. Everything
                    # that varies per case is in `messages`, after it.
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            tools=[turn.tool],
            tool_choice={"type": "tool", "name": turn.tool["name"]},
            messages=turn.messages,
        )

        block = next((b for b in response.content if b.type == "tool_use"), None)
        if block is None:
            raise RuntimeError(
                f"{self.model_id} returned no tool_use block for step "
                f"{turn.step!r} (stop_reason {response.stop_reason!r})"
            )

        usage = {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "cache_read_input_tokens": getattr(
                response.usage, "cache_read_input_tokens", 0
            ),
        }
        self._calls += 1
        if self.assert_cache_hits and self._calls > 1:
            assert usage["cache_read_input_tokens"] > 0, (
                "prompt cache missed on a repeated prefix; something volatile "
                "moved above the breakpoint (SPEC.md §10)"
            )

        # Tool inputs are parsed, never string-matched: escaping in the
        # serialised input is not a stable surface.
        output = dict(block.input)
        if self.record_to is not None:
            self._record(turn, output, usage)
        return Reply(output=output, model_id=self.model_id, usage=usage)

    def _record(self, turn: Turn, output: dict[str, Any], usage: dict[str, int]) -> None:
        path = Path(self.record_to)  # type: ignore[arg-type]
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as handle:
            handle.write(
                jcs(
                    {
                        "key": turn.key(self.model_id),
                        "step": turn.step,
                        "model": self.model_id,
                        "output": output,
                        "usage": usage,
                    }
                )
                + "\n"
            )


def build_model(name: str, cassette: Path | None = None) -> ModelClient:
    """Resolve ``--model`` to a client, and say why when it cannot.

    ``auto`` is the default and prefers, in order: a cassette if one was named,
    then a live model if a credential is reachable, then the stand-in. The order
    matters — a cassette is reproducible and a live call is not, so a recording
    should never be silently overtaken by a fresh call.
    """
    if name == "scripted":
        return ScriptedModel()
    if name == "cassette":
        if cassette is None:
            raise ValueError("--model cassette needs a cassette path")
        return CassetteModel(path=cassette)
    if name in (PRIMARY_MODEL, ABLATION_MODEL, "live"):
        return AnthropicModel(
            model_id=PRIMARY_MODEL if name == "live" else name, record_to=cassette
        )
    if name != "auto":
        raise ValueError(f"unknown model {name!r}")

    if cassette is not None and Path(cassette).exists():
        return CassetteModel(path=cassette)
    if os.environ.get("ANTHROPIC_API_KEY"):
        return AnthropicModel(record_to=cassette)
    return ScriptedModel()
