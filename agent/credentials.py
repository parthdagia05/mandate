"""The agent's delegated signing key. Untrusted, and that is the point.

The user's signed IntentMandate names ``agent.pubkey`` — the key the user
delegated to when they said the sentence. That delegation lets the agent
assemble a CartMandate on the user's behalf inside an authority the user
already granted, and mark it ``confirmed_by: auto_within_intent_scope``.

**This is not a hole in the design; it is the design being honest.** SPEC.md
§17.7 says the agent is fully untrusted *including the planner*, and every
attack flow is tested with the agent-side taint guard removed. An untrusted
component that holds a signing key will sign whatever it is talked into
signing: a product page says pay ``attacker@upi``, the agent believes it, and
the agent produces a perfectly valid cart naming that address. Check 1 passes.
Check 2 refuses it anyway.

That is the claim worth making. "We caught a forged signature" is a claim any
system can make. "A correctly signed request from a fully compromised agent
still cannot move money outside the sentence the user said" is the one that
distinguishes a mandate kernel from a signature checker — and it is only
demonstrable if the compromised agent can actually sign.

**Determinism.** ECDSA is not deterministic, so these signatures differ between
two runs of the same seed. Nothing downstream notices, because SPEC.md §15's
second rule already covers it: raw ``sig`` bytes never enter an audit payload,
and no hash in the project is taken over a signature. ``cart_hash`` covers
line items, total and payee; the chain covers ids and hashes. Two runs of one
seed therefore produce byte-identical audit chains and different signature
bytes, and ``tests/test_m3_gate.py`` asserts exactly that.

The private key is committed under ``fixtures/keys/``. It signs nothing real,
and reproducing the corpus from a fresh clone matters more than the secrecy of
a key whose whole job is to be compromised in a test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from kernel.crypto import public_key_b64u, sign_object

__all__ = ["FIXTURE_KEYS", "AgentCredentials"]

FIXTURE_KEYS = Path(__file__).resolve().parent.parent / "fixtures" / "keys"


@dataclass
class AgentCredentials:
    """Loads the delegated key and signs carts with it."""

    key_path: Path = field(default_factory=lambda: FIXTURE_KEYS / "agent.key.pem")

    def __post_init__(self) -> None:
        self._private = serialization.load_pem_private_key(
            Path(self.key_path).read_bytes(), password=None
        )
        self.pubkey_b64u = public_key_b64u(self._private)

    def sign(self, body: dict[str, Any]) -> str:
        """Sign ``JCS(body − sig)`` — the same input the kernel verifies over."""
        return sign_object(self._private, body)

    def signed(self, body: dict[str, Any]) -> dict[str, Any]:
        """``body`` with its ``sig`` filled in."""
        unsigned = {key: value for key, value in body.items() if key != "sig"}
        return {**unsigned, "sig": self.sign(unsigned)}
