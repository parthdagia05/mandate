"""Routes over the artifacts. Holds no policy and computes no number.

A thin shell, for the reason ``kernel/api.py`` gives for being one: the same
projection has to be reachable over a socket (``mk web``) and as files
(``mk web --export``), and two paths that could disagree eventually do. So every
handler here returns an :class:`Outcome` — a status and a JSON-serialisable body
— and the transport is somebody else's problem.

**Not FastAPI**, and for the same reason the kernel is not: a project whose
argument is that its dependency list is short does not add Starlette, uvicorn and
their tree so that a request can be routed to one of ten handlers. Issue #82
also says the repo's Python dependency list does not grow, and this is where it
would have.

**Query parameters are validated, not trusted.** Every one is either matched
against a pattern or coerced with a bounded integer parse, and a bad value is a
400 that names the field and echoes nothing back — the same discipline as
``kernel/api.py``'s 422, for the same reason: a page that reflected a query
parameter would be a page that reflected attacker-authored text.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from harness.web import DEFAULT_HOST
from harness.web.index import RUN_ID, PathOutsideRoot, RunIndex

__all__ = ["Outcome", "WebApi", "KERNEL_URL", "MAX_LIMIT", "DEFAULT_LIMIT"]

#: The kernel's own address. Reached as an HTTP client, exactly as the harness
#: does; its loopback peer guard is not widened for a browser (#83).
KERNEL_URL = "http://127.0.0.1:8080"

#: Pagination. The generated corpus is 5775 cases per arm and a list endpoint
#: that returned all of them would be a page that never painted (#83).
DEFAULT_LIMIT = 100
MAX_LIMIT = 1000

#: Filters the run list accepts. A closed set, because an open one is a place to
#: put a key nobody wrote a branch for — the argument ``kernel/enums.py`` makes
#: about reason codes, applied to query strings.
FILTERS = (
    "config",
    "dataset",
    "class",
    "technique",
    "injection_point",
    "batch",
    "outcome",
    "task_id",
    "case_id",
)

#: Columns the run list may be ordered by, prefix ``-`` for descending. Closed,
#: for the reason the filter set is: an open sort key is a lambda over an
#: attribute nobody wrote a branch for.
SORTABLE = frozenset(
    {
        "config",
        "dataset",
        "class",
        "technique",
        "injection_point",
        "batch",
        "outcome",
        "task_id",
        "case_id",
        "net_debit_paise",
        "mandates_opened",
        "chain_entries",
    }
)

#: Every value a filter may carry. Ids, enum members and class names only —
#: there is nowhere in this API to put a sentence.
_TOKEN = re.compile(r"^[A-Za-z0-9_+.:-]{1,64}$")


@dataclass(frozen=True)
class Outcome:
    """An HTTP status and the body that goes with it."""

    status: int
    body: dict[str, Any]


def _error(status: int, message: str, field: str | None = None) -> Outcome:
    body: dict[str, Any] = {"error": message}
    if field:
        body["field"] = field
    return Outcome(status, body)


class WebApi:
    """Read-only routes over ``runs/``, plus the one demo proxy."""

    def __init__(
        self,
        runs_root: Path,
        *,
        kernel_url: str = KERNEL_URL,
        index: RunIndex | None = None,
    ) -> None:
        self.runs_root = Path(runs_root).resolve()
        self.kernel_url = kernel_url
        self.index = index if index is not None else RunIndex.build(self.runs_root)

    # -- dispatch ---------------------------------------------------------

    def get(self, path: str, query: dict[str, list[str]]) -> Outcome:
        routes: dict[str, Callable[[dict[str, list[str]]], Outcome]] = {
            "/api/health": self.health,
            "/api/matrices": self.matrices,
            "/api/results": self.results,
            "/api/ablation": self.ablation,
            "/api/runs": self.runs,
            "/api/facets": self.facets,
            "/api/suites": self.suites,
            "/api/tasks": self.tasks,
            "/api/attacks": self.attacks,
        }
        handler = routes.get(path)
        if handler is not None:
            return handler(query)

        # `(.+?)` rather than `([^/]+)`: a value carrying slashes —
        # `/api/runs/../../mk.py` — must reach the run_id shape check and be
        # refused there, naming the field. Excluding slashes at the route level
        # instead would let it fall through to "no such endpoint", which is a
        # safe answer to the wrong question.
        run_route = re.fullmatch(r"/api/runs/(.+?)(/chain)?", path)
        if run_route:
            return self.run(run_route.group(1), chain=bool(run_route.group(2)))

        raise KeyError(path)

    def post(self, path: str, body: dict[str, Any]) -> Outcome:
        if path == "/api/demo/run":
            return self.demo(body)
        raise KeyError(path)

    # -- health -----------------------------------------------------------

    def health(self, _query: dict[str, list[str]] | None = None) -> Outcome:
        """What is being served, and whether the kernel is up.

        ``kernel.reachable`` is probed per call rather than cached. Issue #89:
        "a demo that invents a decision when its backend is down is worse than
        a demo that is down" — and a cached ``true`` is exactly that lie with a
        timestamp on it.
        """
        return Outcome(
            200,
            {
                "schema": "mandate.web.health/1",
                "ok": True,
                "runs_root": str(self.runs_root),
                "suites": len(self.index.suites),
                "cases": len(self.index.entries),
                "skipped": self.index.skipped,
                "kernel": {
                    "reachable": self._kernel_reachable(),
                    "url": self.kernel_url,
                },
            },
        )

    def _kernel_reachable(self) -> bool:
        try:
            with urllib.request.urlopen(
                f"{self.kernel_url}/v1/healthz", timeout=0.5
            ) as response:
                return 200 <= response.status < 300
        except (urllib.error.URLError, OSError, ValueError):
            return False

    # -- matrices and results --------------------------------------------

    def matrices(self, _query: dict[str, list[str]] | None = None) -> Outcome:
        from harness.matrix import load_matrix

        from harness.web.artifacts import matrix_provenance

        found = []
        for candidate in sorted(self.runs_root.rglob("matrix.json")):
            directory = candidate.parent
            try:
                provenance = matrix_provenance(load_matrix(directory))
            except (OSError, KeyError, ValueError) as exc:
                found.append({"dir": self._rel(directory), "error": str(exc)})
                continue
            provenance["dir"] = self._rel(directory)
            found.append(provenance)

        ablations = []
        for candidate in sorted(self.runs_root.rglob("ablation.json")):
            try:
                body = json.loads(candidate.read_text())
            except (OSError, ValueError):
                continue
            ablations.append(
                {
                    "dir": self._rel(candidate.parent),
                    "dataset": body.get("dataset"),
                    "seed": body.get("seed"),
                    "model": body.get("model"),
                    "rows": len(body.get("rows") or []),
                }
            )

        return Outcome(
            200,
            {
                "schema": "mandate.web.matrices/1",
                "matrices": found,
                "ablations": ablations,
            },
        )

    def results(self, query: dict[str, list[str]]) -> Outcome:
        from harness.matrix import load_matrix

        from harness.web.artifacts import results

        directory = self._directory(query, "matrix")
        if isinstance(directory, Outcome):
            return directory
        dataset = _one(query, "dataset")
        if dataset is not None and not _TOKEN.match(dataset):
            return _error(400, "bad filter value", "dataset")

        try:
            matrix = load_matrix(directory)
        except (OSError, KeyError, ValueError) as exc:
            return _error(404, f"not a matrix directory: {exc}", "matrix")

        if dataset is None:
            dataset = next(
                (d for d in matrix.datasets if d.startswith("batch_")),
                matrix.datasets[0] if matrix.datasets else None,
            )
        if dataset is None:
            return _error(404, "matrix holds no datasets", "dataset")
        try:
            return Outcome(200, results(matrix, dataset))
        except KeyError:
            return _error(
                404,
                f"dataset not in this matrix; it has {list(matrix.datasets)}",
                "dataset",
            )

    def ablation(self, query: dict[str, list[str]]) -> Outcome:
        from harness.matrix import load_ablation

        from harness.web.artifacts import ablation

        directory = self._directory(query, "dir")
        if isinstance(directory, Outcome):
            return directory
        try:
            result = load_ablation(directory)
        except (OSError, KeyError, ValueError) as exc:
            return _error(404, f"not an ablation directory: {exc}", "dir")
        if result is None:
            return _error(404, "no ablation.json in that directory", "dir")
        return Outcome(200, ablation(result))

    # -- runs -------------------------------------------------------------

    def runs(self, query: dict[str, list[str]]) -> Outcome:
        wanted: dict[str, Any] = {}
        for name in FILTERS:
            value = _one(query, name)
            if value is None or value == "":
                continue
            if not _TOKEN.match(value):
                return _error(400, "bad filter value", name)
            wanted[name] = value

        limit = _bounded(query, "limit", DEFAULT_LIMIT, MAX_LIMIT)
        if limit is None:
            return _error(400, "bad query parameter", "limit")
        cursor = _bounded(query, "cursor", 0, 10_000_000)
        if cursor is None:
            return _error(400, "bad query parameter", "cursor")

        sort = _one(query, "sort")
        if sort is not None and sort != "":
            if sort.lstrip("-") not in SORTABLE:
                return _error(400, f"cannot sort by that; try {sorted(SORTABLE)}", "sort")

        matched = list(self.index.filter(**wanted))
        if sort:
            descending = sort.startswith("-")
            key = sort.lstrip("-")
            # Sorted in the service, not the page: the page holds one window of
            # a corpus of thousands, and sorting a window is sorting the wrong
            # set — the top row of a sort over 100 rows is not the top row of
            # the corpus, and nothing on screen would say so.
            matched.sort(key=lambda entry: _sort_key(entry, key), reverse=descending)
        window = matched[cursor : cursor + limit]
        rows = []
        for entry in window:
            row = entry.row()
            row["counterparts"] = self.index.counterparts(entry)
            rows.append(row)

        return Outcome(
            200,
            {
                "schema": "mandate.web.runs/1",
                "total": len(matched),
                "limit": limit,
                "cursor": cursor,
                "next_cursor": (
                    cursor + limit if cursor + limit < len(matched) else None
                ),
                "filters": wanted,
                "sort": sort or None,
                "rows": rows,
            },
        )

    def suites(self, _query: dict[str, list[str]] | None = None) -> Outcome:
        """Every ``*.meta.json`` on disk, as the suite wrote it. Issue #83.

        The suite-level record: seed, model, corpus manifest, host, counts and
        the window it ran in. Served because a run record answers "what happened
        to this case" and only the meta answers "under what, on which machine,
        against which frozen corpus" — and the second question is the one a
        reader has to be able to ask of a number.

        Contents are passed through unchanged, like everything else here.
        """
        rows: list[dict[str, Any]] = []
        for path in sorted(self.runs_root.rglob("*.meta.json")):
            try:
                confined = self.index.confine(path)
                body = json.loads(confined.read_text())
            except (OSError, ValueError, PathOutsideRoot):
                continue
            if not isinstance(body, dict):
                continue
            rows.append({"path": self._rel(confined), "meta": body})
        return Outcome(
            200, {"schema": "mandate.web.suites/1", "suites": rows}
        )

    def facets(self, _query: dict[str, list[str]] | None = None) -> Outcome:
        """Every value each filter can take, with how many runs carry it.

        Served rather than derived in the browser, and the difference matters:
        a frontend building its own dropdowns from the rows it happened to fetch
        would offer the values on page one and hide the rest, so a filter that
        exists in the corpus would look like a filter that does not. The counts
        come from the index, which holds every run.

        This is not a metric. There is no proportion here and no interval — it
        is the corpus, counted, so a reader can see that ``A6`` has as many
        cases as ``A1`` before they compare the two columns.
        """
        dimensions = (
            "config",
            "dataset",
            "class",
            "technique",
            "injection_point",
            "batch",
            "outcome",
        )
        found: dict[str, list[dict[str, Any]]] = {}
        for dimension in dimensions:
            counts: dict[str, int] = {}
            for entry in self.index.entries.values():
                value = entry.row().get(dimension)
                if value is None or value == "":
                    continue
                counts[str(value)] = counts.get(str(value), 0) + 1
            found[dimension] = [
                {"value": value, "runs": count}
                for value, count in sorted(counts.items())
            ]
        return Outcome(
            200, {"schema": "mandate.web.facets/1", "facets": found}
        )

    def run(self, run_id: str, *, chain: bool) -> Outcome:
        if not RUN_ID.match(run_id):
            # Refused on shape before it is used as a key, a path or a log
            # line. Issue #83: a path parameter is not a file opener.
            return _error(400, "run_id must be sha256:<64 hex>", "run_id")
        entry = self.index.get(run_id)
        if entry is None:
            return _error(404, "no such run_id")

        from harness.web import artifacts

        try:
            if chain:
                return Outcome(200, artifacts.chain(self.index, entry))
            return Outcome(200, artifacts.run_detail(self.index, entry))
        except PathOutsideRoot:
            return _error(403, "artifact path is outside the runs directory")
        except (OSError, KeyError, ValueError) as exc:
            return _error(404, f"artifact unreadable: {exc}")

    # -- the demo pickers (#89) -------------------------------------------

    def tasks(self, _query: dict[str, list[str]] | None = None) -> Outcome:
        from harness.corpus import list_tasks, load_task

        rows = []
        for task_id in list_tasks():
            try:
                task = load_task(task_id)
            except (KeyError, ValueError):
                continue
            rows.append(
                {
                    "task_id": task.task_id,
                    "merchant": task.merchant,
                    "utterance": task.raw.get("utterance"),
                    "scope": task.raw.get("scope"),
                }
            )
        return Outcome(
            200,
            {"schema": "mandate.web.tasks/1", "corpus": "handwritten", "tasks": rows},
        )

    def attacks(self, _query: dict[str, list[str]] | None = None) -> Outcome:
        """Batch A only, and the response says so.

        Batch B is not offered. Offering it would invite an opening that no
        line in ``openings.jsonl`` explains, and the demo is an anecdote — the
        held-out set exists for the measurement, not for a form.
        """
        from harness.corpus import list_batch, load_attack

        rows = []
        for case_id in list_batch("a"):
            try:
                case = load_attack(case_id)
            except (KeyError, ValueError):
                continue
            rows.append(
                {
                    "case_id": case.case_id,
                    "class": case.attack_class,
                    "batch": case.batch,
                    "task": case.task_id,
                    "technique": case.technique,
                    "oracle": case.oracle,
                    "injection_point": str(case.point),
                }
            )
        return Outcome(
            200,
            {
                "schema": "mandate.web.attacks/1",
                "batch": "a",
                "note": (
                    "batch A only. Batch B is held out and opening it is logged; "
                    "a demo form is not a reason to open it"
                ),
                "attacks": rows,
            },
        )

    # -- the demo itself (#89) --------------------------------------------

    def demo(self, body: dict[str, Any]) -> Outcome:
        """Post a real intent and a real payment to a running kernel. #89.

        A 503 when the kernel is down, carrying ``kernel_reachable: false`` and
        no steps — the page then renders that fact and nothing else. A 400 when
        the request cannot be built. Never a decision this service invented.
        """
        from harness.web.demo import DemoError, record_demo_run, run_demo

        reachable = self._kernel_reachable()
        try:
            result = run_demo(body, kernel_url=self.kernel_url, reachable=reachable)
        except DemoError as exc:
            return _error(400, str(exc))

        # Written to runs/ so the demo is inspectable in the trace view
        # afterwards (#89). A failure to record must not lose the decision the
        # user is waiting to see, so it is reported beside the result rather
        # than raised over it.
        try:
            record = record_demo_run(result, self.runs_root)
        except OSError as exc:
            result["recorded"] = None
            result["record_error"] = f"the run could not be written to runs/: {exc}"
        else:
            result["recorded"] = record["run_id"] if record else None
            if record is not None and record["run_id"] not in self.index.entries:
                # Make it openable immediately rather than after a restart.
                self.index = type(self.index).build(self.runs_root)

        return Outcome(200 if reachable else 503, result)

    # -- helpers ----------------------------------------------------------

    def _directory(self, query: dict[str, list[str]], field: str) -> Path | Outcome:
        """Resolve a directory parameter, confined to the runs root.

        A directory *is* a path parameter, unlike ``run_id``, so it gets the
        full treatment: resolved, then required to sit under the runs root.
        ``..`` and an absolute path outside the tree both land on 403 rather
        than on a stack trace or, worse, on a file.
        """
        raw = _one(query, field)
        if not raw:
            return _error(400, f"{field} is required", field)
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = self.runs_root.parent / candidate
        try:
            return self.index.confine(candidate)
        except PathOutsideRoot:
            return _error(403, "path is outside the runs directory", field)

    def _rel(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.runs_root.parent))
        except ValueError:  # pragma: no cover
            return str(path)


def _sort_key(entry: Any, key: str) -> tuple[int, Any]:
    """Order one column, with nulls last in both directions.

    ``(1, "")`` for a missing value sorts it after every present one ascending,
    and the tuple keeps it out of the way descending too. A benign run has no
    class and no technique; letting those float to the top of a sort by class
    would bury the rows the sort was asked for.
    """
    value = entry.row().get(key)
    if value is None or value == "":
        return (1, "")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return (0, value)
    return (0, str(value))


def _one(query: dict[str, list[str]], name: str) -> str | None:
    values = query.get(name)
    return values[0] if values else None


def _bounded(
    query: dict[str, list[str]], name: str, default: int, maximum: int
) -> int | None:
    """A non-negative integer no larger than ``maximum``, or ``None`` if bad.

    ``None`` rather than a raise, and a clamp rather than an error on the upper
    bound: a caller asking for a million rows gets ``MAX_LIMIT`` of them, and a
    caller asking for ``limit=drop table`` gets a 400 naming the field.
    """
    raw = _one(query, name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        return None
    if value < 0:
        return None
    return min(value, maximum)
