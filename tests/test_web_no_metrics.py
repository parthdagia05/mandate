"""The frontend computes no metric, checked mechanically. Issue #91.

The reason this is a test rather than a convention: "a frontend that recomputes
will one day disagree with results.md", and when it does, nobody will be able to
say which is wrong. ``harness/metrics.py`` is the single implementation of
Wilson, of every proportion and of the overhead difference; the page formats
what it is given.

The check is drawn at **arithmetic over case arrays**. Scalar formatting
arithmetic is fine and necessary — ``100 * p`` renders a percent, ``/ 100``
turns paise into rupees — so the rules below look for reductions, filters
counted with ``.length``, and the names of the statistics themselves.

Two other properties are asserted here because they are one-line checks that
protect the same claim: the dependency list stays at three packages, exactly
pinned (#82), and nothing is fetched from a CDN at runtime.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "web"
SRC = WEB / "src"

pytestmark = pytest.mark.skipif(not SRC.is_dir(), reason="web/ is not scaffolded")

#: Sources the rules apply to. Tests are excluded: a test may assert on a
#: literal that a component may not compute.
def _sources() -> list[Path]:
    return [
        path
        for path in sorted(SRC.rglob("*"))
        if path.suffix in {".ts", ".tsx"} and not path.name.endswith((".test.ts", ".test.tsx"))
    ]


def _code_only(text: str) -> list[tuple[int, str]]:
    """Line numbers and text, with comments blanked out.

    Block comments are removed by scanning rather than by a per-line prefix
    test: a rule that skipped only lines *starting* with ``*`` would still read
    the first line of a ``/** ... */`` block, and these files carry a great deal
    of prose that names the very things the rules ban.
    """
    without_blocks = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group().count("\n"), text, flags=re.S)
    lines = []
    for number, line in enumerate(without_blocks.splitlines(), 1):
        code = re.sub(r"//.*$", "", line)
        lines.append((number, code))
    return lines


#: Each rule is (name, pattern, why). The "why" is what a failure prints, so it
#: has to say what to do instead rather than only what is banned.
RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "reduction over an array",
        re.compile(r"\.reduce\s*\("),
        "sum it in harness/metrics.py and serve the result; the page formats it",
    ),
    (
        "a filtered count",
        # Greedy, not `[^)]*`: an arrow-function predicate carries its own
        # parentheses — `.filter((r) => r.attacker_win).length` — and a lazy
        # class stops at the first one and misses the count entirely.
        re.compile(r"\.filter\s*\(.*\)\s*\.length"),
        "k and n arrive on the Proportion; counting rows in the browser is a "
        "second implementation of the same number",
    ),
    (
        "an interval computed in TypeScript",
        # Matched as an identifier, not as a word: the page is allowed to *say*
        # "a Wilson 95% confidence interval" — that sentence is the caveat the
        # reader needs. What it may not do is call one.
        re.compile(r"\bwilson\s*\(|\bZ_?95\b|1\.959964|=\s*1\.96\b", re.IGNORECASE),
        "ci95 arrives from harness.metrics.wilson, the one implementation "
        "results.md is rendered from",
    ),
    (
        "a percentile computed in TypeScript",
        re.compile(
            r"\b(?:percentile|quantile)\s*\(|\bp50\s*=[^=]|\bp99\s*=[^=]",
            re.IGNORECASE,
        ),
        "overhead p50/p99 arrive from harness.metrics.overhead, as a difference "
        "over one dataset",
    ),
    (
        "an average or a sum",
        re.compile(r"\b(?:mean|average|median|variance|stddev)\s*\(", re.IGNORECASE),
        "no statistic is derived in the browser",
    ),
    (
        "an estimate rebuilt from k and n",
        re.compile(r"\.k\s*/\s*\w*\.?n\b"),
        "p is carried on the Proportion already",
    ),
)


def test_no_metric_is_computed_in_the_frontend():
    offenders: list[str] = []
    for path in _sources():
        for number, line in _code_only(path.read_text(encoding="utf-8")):
            if "invariant-ok" in line:
                continue
            for name, pattern, why in RULES:
                if pattern.search(line):
                    offenders.append(
                        f"{path.relative_to(REPO)}:{number} {name} — {why}\n"
                        f"    {line.strip()[:110]}"
                    )
    assert not offenders, "the frontend is computing metrics:\n" + "\n".join(offenders)


def test_the_only_percentage_formatter_is_the_one_that_prints_the_interval():
    """``pct`` is not exported, and no second one exists.

    ``harness/metrics.py``: "``Proportion`` has no method that renders the
    estimate alone, which is how that stays true." The TypeScript side mirrors
    that, and this asserts the mirror rather than trusting it.
    """
    module = (SRC / "format" / "proportion.ts").read_text(encoding="utf-8")
    assert "function pct(" in module
    assert "export function pct" not in module
    # A declaration, not the word: the doc comment says "There is no
    # `formatEstimate`", and that sentence is the reason the rule exists.
    assert not re.search(r"(?:function|const|let)\s+formatEstimate\b", module)

    exported = set(re.findall(r"^export function (\w+)", module, re.MULTILINE))
    assert exported == {
        "formatProportion",
        "proportionParts",
        "proportionLabel",
        "formatMicros",
    }, f"proportion.ts exports changed: {sorted(exported)}"

    # Every rendering of a proportion carries the counts.
    for name in ("formatProportion", "proportionLabel"):
        body = module.split(f"export function {name}")[1].split("\nexport ")[0]
        assert "x.k" in body or "formatProportion" in body


def test_only_format_money_divides_by_a_hundred():
    offenders = [
        f"{path.relative_to(REPO)}:{number}"
        for path in _sources()
        if path.name != "money.ts"
        for number, line in _code_only(path.read_text(encoding="utf-8"))
        if re.search(r"/\s*100(?![\d_])", line)
    ]
    assert not offenders, (
        "rupee arithmetic outside src/format/money.ts: " + ", ".join(offenders)
    )


def test_the_hash_chain_is_not_reimplemented_in_javascript():
    """Issue #88, asserted rather than intended.

    "A second implementation that disagrees with the first is a bug factory, and
    the verifier is the artifact the project asks reviewers to trust."
    """
    banned = re.compile(r"crypto\.subtle|createHash|\bsha256\s*\(|canonicaliz", re.IGNORECASE)
    offenders = [
        f"{path.relative_to(REPO)}:{number}: {line.strip()[:80]}"
        for path in _sources()
        for number, line in _code_only(path.read_text(encoding="utf-8"))
        if banned.search(line) and "invariant-ok" not in line
    ]
    assert not offenders, "hashing in the frontend:\n" + "\n".join(offenders)


def test_the_dependency_list_stays_at_three_and_is_pinned_exactly():
    """Issue #82: pinned exactly, no component kit, no animation library."""
    body = json.loads((WEB / "package.json").read_text())
    assert set(body["dependencies"]) == {"react", "react-dom", "zod"}
    for group in ("dependencies", "devDependencies"):
        for name, version in body[group].items():
            assert re.fullmatch(r"\d+\.\d+\.\d+", version), (
                f"{name} is {version!r}; #82 wants dependencies pinned exactly, "
                "so a rebuild months later is the same bundle"
            )


def test_the_lockfile_is_committed():
    """"A frontend nobody can build is a frontend nobody will look at" (#82)."""
    assert (WEB / "package-lock.json").is_file()


def test_nothing_is_fetched_from_a_cdn_at_runtime():
    """No CDN, no remote font, no absolute URL (#82, #90).

    The export has to open from ``file://`` on a machine with no network.
    """
    banned = re.compile(r"https?://(?!127\.0\.0\.1|localhost)")
    offenders = []
    for path in [*_sources(), WEB / "index.html", SRC / "styles.css"]:
        if not path.is_file():
            continue
        for number, line in _code_only(path.read_text(encoding="utf-8")):
            if "invariant-ok" in line:
                continue
            if banned.search(line):
                offenders.append(f"{path.relative_to(REPO)}:{number}: {line.strip()[:80]}")
    assert not offenders, "an external URL in the frontend:\n" + "\n".join(offenders)


def test_the_frontend_never_names_the_kernels_port():
    """#89 proxies through ``mk web``; the peer guard stays loopback-only."""
    offenders = [
        f"{path.relative_to(REPO)}:{number}"
        for path in _sources()
        for number, line in _code_only(path.read_text(encoding="utf-8"))
        if re.search(r"127\.0\.0\.1:8080|localhost:8080", line)
    ]
    assert not offenders, (
        "the kernel's port appears in frontend code: " + ", ".join(offenders)
    )


# ---------------------------------------------------------------------------
# the built bundle, not only the source
# ---------------------------------------------------------------------------

DIST = WEB / "dist"


@pytest.mark.skipif(
    not (DIST / "index.html").is_file(),
    reason="web/dist is absent; run `cd web && npm ci && npm run build`",
)
def test_the_built_bundle_carries_no_statistic():
    """Issue #91 draws the check at *the bundle*, so check the bundle too.

    The source scan above is the precise one — it can see `.reduce` and name the
    line. This is the coarser backstop and it catches the case the source scan
    cannot: a statistic arriving through a dependency, or through a file the
    glob missed. It looks for the constants and names a statistic needs rather
    than for syntax, because minified code has no syntax worth matching.

    **Constants only, not names.** The pages say "every proportion carries a
    Wilson 95% confidence interval and the counts it was computed from" — that
    sentence is the caveat a reader needs, and it is in the bundle as page copy.
    A bundle scan cannot tell that string from an identifier, so banning the
    *word* would force the page to stop explaining itself, which is precisely
    backwards. The source scan above is where names are checked, with comments
    and JSX prose stripped; this one looks for the numeric constants a
    statistic cannot be computed without.

    `Math.sqrt` is not banned here either. React's own scheduler uses it, and a
    rule that fired on a vendored copy would be a rule someone switched off.
    """
    import re

    banned = {
        # The z for a 95% interval, to the precision `harness/metrics.py` uses.
        # No honest reason for it to be in a bundle that computes nothing.
        "the Wilson z-constant": re.compile(r"1\.959964|1\.9599639"),
    }
    offenders = []
    for asset in sorted(DIST.rglob("*.js")):
        text = asset.read_text(encoding="utf-8", errors="replace")
        for what, pattern in banned.items():
            found = pattern.search(text)
            if found:
                start = max(0, found.start() - 60)
                offenders.append(f"{asset.name}: {what} — …{text[start:found.end() + 60]}…")
    assert not offenders, (
        "the bundle appears to compute a statistic:\n" + "\n".join(offenders)
    )


@pytest.mark.skipif(
    not (DIST / "index.html").is_file(),
    reason="web/dist is absent; run `cd web && npm ci && npm run build`",
)
def test_the_bundle_carries_no_hash_implementation():
    """#88, at the bundle level. The chain is verified server-side, once."""
    import re

    banned = re.compile(r"crypto\.subtle|createHash", re.IGNORECASE)
    offenders = [
        asset.name
        for asset in sorted(DIST.rglob("*.js"))
        if banned.search(asset.read_text(encoding="utf-8", errors="replace"))
    ]
    assert not offenders, f"a hash implementation reached the bundle: {offenders}"
