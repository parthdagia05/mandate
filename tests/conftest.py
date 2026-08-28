import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _load(name):
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def intent_json():
    return _load("mandates/intent_benign_01.json")


@pytest.fixture
def cart_json():
    return _load("mandates/cart_benign_01.json")


@pytest.fixture
def user_pubkey():
    return (FIXTURES / "keys" / "user.pub.b64u").read_text().strip()


@pytest.fixture
def fixtures_dir():
    return FIXTURES
