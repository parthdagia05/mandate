"""Loading tasks and attack cases, and refusing the ones that would lie.

Two refusals matter more than the loading does:

* an attack naming an injection point that does not exist is a **hard error**,
  not a warning. A typo'd point produces a run with no payload in it, which
  looks exactly like a defended run and would be counted as one;
* a task naming a merchant that does not exist is the same mistake wearing a
  different hat.

Both are the general rule this project keeps applying: a mistake that produces a
clean-looking result is worse than one that produces a crash.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sim.merchants.base import Injection, InjectionPoint
from sim.world import MERCHANTS

__all__ = ["HARNESS_ROOT", "Task", "AttackCase", "load_task", "load_attack", "list_tasks", "list_attacks"]

HARNESS_ROOT = Path(__file__).resolve().parent
TASKS_DIR = HARNESS_ROOT / "tasks"
ATTACKS_DIRS = (
    HARNESS_ROOT / "attacks" / "batch_a",
    HARNESS_ROOT / "attacks" / "batch_b",
)


@dataclass(frozen=True)
class Task:
    raw: dict[str, Any]

    @property
    def task_id(self) -> str:
        return self.raw["task_id"]

    @property
    def merchant(self) -> str:
        return self.raw["merchant"]

    @property
    def expect(self) -> dict[str, Any]:
        return self.raw["expect"]


@dataclass(frozen=True)
class AttackCase:
    raw: dict[str, Any]

    @property
    def case_id(self) -> str:
        return self.raw["case_id"]

    @property
    def attack_class(self) -> str:
        return self.raw["class"]

    @property
    def point(self) -> InjectionPoint:
        return InjectionPoint(self.raw["injection_point"])

    @property
    def oracle(self) -> str:
        return self.raw["oracle"]

    def injection(self) -> Injection:
        return Injection(
            point=self.point, payload=self.raw["payload"], case_id=self.case_id
        )


def _read(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def list_tasks() -> list[str]:
    return sorted(_read(p)["task_id"] for p in TASKS_DIR.glob("*.json"))


def list_attacks() -> list[str]:
    found = []
    for directory in ATTACKS_DIRS:
        found += [_read(p)["case_id"] for p in directory.glob("*.json")]
    return sorted(found)


def load_task(task_id: str) -> Task:
    for path in sorted(TASKS_DIR.glob("*.json")):
        raw = _read(path)
        if raw["task_id"] != task_id:
            continue
        if raw["merchant"] not in MERCHANTS:
            raise ValueError(
                f"{path.name} names merchant {raw['merchant']!r}; "
                f"known: {sorted(MERCHANTS)}"
            )
        return Task(raw)
    raise KeyError(f"no task {task_id!r}; known: {list_tasks()}")


def load_attack(case_id: str) -> AttackCase:
    for directory in ATTACKS_DIRS:
        for path in sorted(directory.glob("*.json")):
            raw = _read(path)
            if raw["case_id"] != case_id:
                continue
            try:
                InjectionPoint(raw["injection_point"])
            except ValueError:
                raise ValueError(
                    f"{path.name} injects at {raw['injection_point']!r}, which "
                    "is not one of the eight named points. A payload placed "
                    "nowhere produces a clean run that would be counted as a "
                    f"defended one. Known: {[p.value for p in InjectionPoint]}"
                ) from None
            return AttackCase(raw)
    raise KeyError(f"no attack {case_id!r}; known: {list_attacks()}")
