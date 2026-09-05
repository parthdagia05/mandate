#!/usr/bin/env python3
"""The invariants from the frontend-architecture skill, checked mechanically.

Runs as a PostToolUse hook on Write/Edit under ``web/`` and as the body of
``/web-check``. Each rule here corresponds to a numbered invariant in the skill,
and each one exists because breaking it produces a page that renders correctly
and says something false.

Exit codes: 0 clean, 2 violations found (stderr goes back to the model).

The checks are deliberately textual. A real linter would need the web app's own
toolchain installed, and this has to work before ``npm install`` has ever run.
False positives are silenced with a trailing ``// invariant-ok: <reason>``.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

WEB_SRC = re.compile(r"(^|/)web/(src|public)/")
SKIP = re.compile(r"\.(test|spec)\.[jt]sx?$|/node_modules/|/dist/")
ALLOW = re.compile(r"//\s*invariant-ok\b|/\*\s*invariant-ok\b")


@dataclass(frozen=True)
class Rule:
    id: str
    invariant: int
    pattern: re.Pattern[str]
    message: str
    #: Only applies to paths matching this, if given.
    only: re.Pattern[str] | None = None
    #: Never applies to paths matching this.
    unless: re.Pattern[str] | None = None


RULES: tuple[Rule, ...] = (
    # --- invariant 1: the record's own field names -------------------------
    Rule(
        "renamed-field",
        1,
        re.compile(
            r"\b(?:runId|caseId|taskId|attackerWin|taskSuccess|reasonCode|"
            r"reasonCodes|amountPaise|capturedPaise|cartHash|lineItems|"
            r"unitAmount|logHead|chainHead|chainEntries|injectionPoint|"
            r"netDebitPaise|heldOut|matchesChain|utteranceHash)\b"
        ),
        "a camelCased field name. The API returns the record's own snake_case "
        "and nothing renames it on the way through: a field renamed on the way "
        "out is a field the reader cannot grep for in the JSONL (#83). Use "
        "run_id, case_id, attacker_win, reason_code, amount_paise, chain_head.",
        only=re.compile(r"web/src/"),
    ),
    # --- invariant 2: the frontend computes no metric ----------------------
    Rule(
        "metric-in-frontend",
        2,
        re.compile(
            r"\.reduce\s*\(|\.filter\s*\(.*\)\s*\.length|"
            r"\bwilson\b|\bpercentile\b|\bquantile\b|"
            r"\b(?:sum|mean|average|median)\s*\(|"
            r"\bMath\.(?:sqrt|pow)\s*\("
        ),
        "arithmetic over case arrays. Every proportion, percentile and interval "
        "comes from harness/metrics.py through the API; the frontend formats it "
        "and does nothing else (#91). A frontend that recomputes will one day "
        "disagree with results.md, and nobody will be able to say which is "
        "wrong. There is no model/ layer for this reason.",
        only=re.compile(r"web/src/"),
    ),
    Rule(
        "recomputed-estimate",
        2,
        re.compile(r"\.k\s*/\s*\w*\.?n\b|\bk\s*/\s*n\b"),
        "p recomputed from k/n. The API carries p already — it is "
        "Proportion.as_dict() from the one implementation results.md uses.",
        only=re.compile(r"web/src/"),
    ),
    # --- invariant 3: no bare point estimate ------------------------------
    Rule(
        "bare-percentage",
        3,
        re.compile(r"toFixed\s*\(\s*\d*\s*\)\s*(?:\}?\s*%|\+\s*['\"`]\s*%)"),
        "a percentage string built outside src/format/proportion.ts. Every "
        "proportion reaches the screen through formatProportion(), which always "
        "prints the interval and the counts. n is 15 per class on the "
        "hand-written corpus, and the point estimate alone is the exact thing "
        "results.md refuses to print (#85).",
        unless=re.compile(r"web/src/format/proportion\.ts$"),
    ),
    Rule(
        "estimate-alone",
        3,
        re.compile(r"\.p\s*\*\s*100|\bpct\s*\(\s*\w+\.p\s*\)"),
        "reading Proportion.p directly. Use formatProportion() — mirroring "
        "harness/metrics.py, which has no method that renders the estimate "
        "alone, 'and that is the point'.",
        unless=re.compile(r"web/src/format/proportion\.ts$"),
    ),
    # --- invariant 4: integer paise ---------------------------------------
    Rule(
        "float-money",
        4,
        re.compile(r"parseFloat|\/\s*100(?![\d_])"),
        "rupee arithmetic outside src/format/money.ts. Money is integer paise "
        "end to end; a float in the display path is how ₹1357.00 becomes "
        "₹1356.99 on camera.",
        unless=re.compile(r"web/src/format/money\.ts$"),
    ),
    # --- invariant 5: chain verification is server-side only --------------
    Rule(
        "chain-crypto-in-js",
        5,
        re.compile(
            r"crypto\.subtle|\bsha256\b|\bSHA-256\b|createHash|"
            r"\bjcs\b|canonicaliz|\bRFC\s*8785\b",
            re.IGNORECASE,
        ),
        "hashing or canonical JSON in the frontend. The hash chain is NOT "
        "reimplemented in JavaScript (#88): a second implementation that "
        "disagrees with the first is a bug factory, and scripts/verify_chain.py "
        "is the artifact the project asks reviewers to trust. mk web runs it and "
        "the page shows what it said. (A `sha256:` prefix inside a string "
        "literal is fine — mark it `// invariant-ok: display only`.)",
        only=re.compile(r"web/src/"),
    ),
    # --- invariant 6: outcome is not a boolean ----------------------------
    Rule(
        "outcome-as-boolean",
        6,
        re.compile(r"attacker_win\s*\?|!\s*\w*\.?attacker_win|attacker_win\s*&&"),
        "outcome treated as a boolean. It is five-way (#86): attacker_win, "
        "task_success, blocked, error, poisoned. A poisoned run shows as "
        "discarded and never as a defended one; an errored run shows as an "
        "error and not as a zero. Read the API's `outcome` field.",
    ),
    # --- invariant 7: one renderer for tainted text -----------------------
    Rule(
        "html-sink",
        7,
        re.compile(r"dangerouslySetInnerHTML|\.innerHTML\s*="),
        "an HTML sink. The corpus has an evasion family whose entire technique "
        "is markup (`formatting`); one of those reaching innerHTML is stored "
        "XSS in a page whose subject is untrusted text. Tainted text renders as "
        "a text node through ui/Payload.tsx and nowhere else.",
    ),
    # --- invariant 8: held-out payloads are not served --------------------
    Rule(
        "held-out-corpus",
        8,
        re.compile(r"attacks/batch_b|batch_b/"),
        "a reference to the held-out corpus. batch B is sealed, opening it is "
        "logged in harness/attacks/openings.jsonl, and AttackCase.payload "
        "raises BatchBSealed. The web layer reads run records, never the corpus.",
    ),
    # --- invariant 10: no clock, no absolute URL, no model ----------------
    Rule(
        "wall-clock",
        10,
        re.compile(r"Date\.now\s*\(|new\s+Date\s*\(\s*\)|performance\.now\s*\("),
        "the wall clock in the render path. Timestamps come from the record. A "
        "page that renders a relative time cannot be screenshotted twice "
        "identically, and byte-identical reproduction is REQ-3.",
    ),
    Rule(
        "absolute-fetch",
        10,
        re.compile(r"""(?:fetch|axios)\s*\(\s*['\"`]https?://"""),
        "an absolute URL. Requests are same-origin relative (./api/...) so the "
        "static export works from file://. The live page reaches the kernel "
        "through mk web's proxy, never 127.0.0.1:8080 from the browser — the "
        "kernel's loopback peer guard is not widened for a browser (#83, #89).",
    ),
    Rule(
        "kernel-port-in-browser",
        10,
        re.compile(r"127\.0\.0\.1:8080|localhost:8080"),
        "the kernel's port in frontend code. #89 proxies through the web "
        "service; the peer guard stays loopback-only.",
        only=re.compile(r"web/src/"),
    ),
    Rule(
        "external-asset",
        10,
        re.compile(
            r"""(?:src|href)\s*=\s*['\"`]https?://|@import\s+url\(\s*['\"]?https?://"""
        ),
        "an external asset. No CDN at runtime: everything is built into the "
        "assets (#82), and the export must open from file:// with no network.",
    ),
    Rule(
        "inference-in-ui",
        10,
        re.compile(r"anthropic|openai|@ai-sdk|\bllm\b", re.IGNORECASE),
        "a model in the render path. Every verdict on screen was computed by "
        "the kernel or by harness/. The UI has no opinions.",
    ),
    Rule(
        "unparsed-json",
        0,
        re.compile(r":\s*any\b|\bas\s+any\b|JSON\.parse\s*\("),
        "raw or untyped JSON. Every response is validated by a zod schema in "
        "src/api/ and nothing downstream sees any/unknown. The run record has "
        "near-identical sibling fields (payee vs checkout_payee, amount_paise "
        "vs captured_paise) and hand-reading them is how the wrong address ends "
        "up on screen.",
        only=re.compile(r"web/src/"),
    ),
    # --- invariant 12: view state in the URL ------------------------------
    Rule(
        "state-in-component",
        12,
        re.compile(
            r"""(?:const|let)\s*\[\s*(?:arm|config|corpus|dataset|batch|technique|"""
            r"""family|outcome|classFilter|selectedClass|filters?|query)\b[^\]]*\]\s*="""
            r"""\s*useState|useState[<(][^)]{0,40}?"""
            r"""(?:arm|config|corpus|dataset|technique|batch|outcome)""",
            re.IGNORECASE,
        ),
        "a filter in component state. Arm, class, technique, injection point, "
        "batch and outcome live in the URL (#86, invariant 12): the video script "
        "arrives at an exact view with no clicking, and a re-recorded shot has "
        "to land on the identical view.",
    ),
    # --- design rules (#84) -----------------------------------------------
    Rule(
        "transition",
        0,
        # `: none` is the rule being enforced, not broken — the reset in
        # styles.css is the only place it should appear.
        re.compile(
            r"transition\s*:(?!\s*none)|animation\s*:(?!\s*none)|@keyframes|"
            r"transform\s*:\s*scale"
        ),
        "a transition or animation. #84: 'transitions: none. This is stated as "
        "a rule so it survives the second pass.'",
    ),
    Rule(
        "gradient-or-shadow-stack",
        0,
        re.compile(r"linear-gradient|radial-gradient|box-shadow\s*:[^;]*,[^;]*,"),
        "a gradient or a shadow stack — 'none of the look that reads as "
        "generated' (#84). Borders, not gradients.",
    ),
    Rule(
        "emoji",
        0,
        re.compile(
            "[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U0001F000-\U0001F0FF]"
        ),
        "an emoji. #84 rules them out.",
        only=re.compile(r"web/src/"),
    ),
    # --- P8: no per-step duration anywhere near the UI --------------------
    Rule(
        "latency-per-step",
        0,
        re.compile(r"latency_us"),
        "a per-step latency in the UI. latency_us and money_calls are the only "
        "fields P8 found to differ across machines, by more than an order of "
        "magnitude, which is why no duration reaches the event log or the audit "
        "chain. Overhead is a difference between arms over one dataset and it "
        "comes from the API's `overhead` object only.",
        only=re.compile(r"web/src/"),
    ),
    Rule(
        "heavy-dependency",
        0,
        re.compile(
            r"""from\s+['\"](?:recharts|chart\.js|d3|victory|@mui|antd|"""
            r"""@chakra-ui|redux|zustand|jotai|moment|dayjs|date-fns|lodash|"""
            r"""framer-motion|react-spring)"""
        ),
        "a dependency outside the allowed set (react, react-dom, zod). #82: 'no "
        "component kit, no animation library, no icon font: the design rules in "
        "this phase are the deliverable and a kit would overwrite them.'",
    ),
)

def violations(path: str, text: str) -> list[tuple[Rule, int, str]]:
    found: list[tuple[Rule, int, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if ALLOW.search(line):
            continue
        stripped = line.lstrip()
        if stripped.startswith(("//", "*", "/*")):
            continue
        for rule in RULES:
            if rule.only is not None and not rule.only.search(path):
                continue
            if rule.unless is not None and rule.unless.search(path):
                continue
            if rule.pattern.search(line):
                found.append((rule, number, line.strip()))
    return found


def report(path: str, found: list[tuple[Rule, int, str]]) -> None:
    print(f"{path}", file=sys.stderr)
    for rule, number, line in found:
        where = f"invariant {rule.invariant}" if rule.invariant else "architecture"
        print(f"  {path}:{number}  [{rule.id}] {where}", file=sys.stderr)
        print(f"    {line[:120]}", file=sys.stderr)
        print(f"    {rule.message}", file=sys.stderr)
    print(
        "  See the frontend-architecture skill. If a line is a genuine "
        "exception, end it with `// invariant-ok: <reason>`.",
        file=sys.stderr,
    )


def check_paths(paths: list[Path], root: Path) -> int:
    total = 0
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            shown = str(path.relative_to(root))
        except ValueError:
            shown = str(path)
        found = violations(shown, text)
        if found:
            total += len(found)
            report(shown, found)
    return total


def from_hook() -> int:
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0
    tool_input = event.get("tool_input") or {}
    raw = tool_input.get("file_path") or tool_input.get("path") or ""
    if not raw:
        return 0
    normalised = str(raw).replace("\\", "/")
    if not WEB_SRC.search(normalised) or SKIP.search(normalised):
        return 0
    path = Path(raw)
    if not path.is_file():
        return 0
    root = Path(event.get("cwd") or ".")
    return check_paths([path], root)


def from_cli(args: list[str]) -> int:
    root = Path(".").resolve()
    if args:
        targets = [Path(a) for a in args]
    else:
        targets = [root / "web" / "src", root / "web" / "public"]
    files: list[Path] = []
    for target in targets:
        if target.is_file():
            files.append(target)
        elif target.is_dir():
            files.extend(
                p
                for p in sorted(target.rglob("*"))
                if p.is_file()
                and p.suffix in {".ts", ".tsx", ".js", ".jsx", ".css", ".html"}
                and not SKIP.search(str(p).replace("\\", "/"))
            )
    if not files:
        print("no web/ sources to check yet.", file=sys.stderr)
        return 0
    count = check_paths(files, root)
    if count == 0:
        print(f"{len(files)} file(s) checked, no violations.", file=sys.stderr)
    return count


def main() -> int:
    count = from_cli(sys.argv[1:]) if sys.argv[1:] or sys.stdin.isatty() else from_hook()
    return 2 if count else 0


if __name__ == "__main__":
    raise SystemExit(main())
