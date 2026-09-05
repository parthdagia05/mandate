---
description: Scaffold or extend one web page (#85-#89) against the architecture. Pass the issue number or the page name.
allowed-tools: Read, Write, Edit, Grep, Glob, Bash(python3:*)
---

Build the page named by `$ARGUMENTS` — an issue number (`85`…`89`) or a page
name (`results`, `runs`, `trace`, `compare`, `chain`, `live`).

Load the `frontend-architecture` skill and both its references before writing
anything. Then:

1. **Check what the page needs from the export.** If a field it requires is not
   in `references/export-contract.md`, add it to the contract *and* to
   `harness/web/export.py` in the same change — a route that invents a field is
   a route that renders `undefined`.
2. **Work outwards through the layers.** `data/` schema first, then `model/`
   derivations with `vitest` tests, then `format/`, then `ui/`, then the route.
   Never the other way round: a component written first will reach straight into
   raw JSON and the parse boundary is lost.
3. **Put every filter in the URL.** No exceptions; see invariant 7.
4. **Check the page's definition of done** in the skill and satisfy each line.
5. **Run the checks** —
   `python3 "${CLAUDE_PLUGIN_ROOT}/hooks/check_web_invariants.py"` and the
   `vitest` suite — and report both.

Stop and ask before adding any runtime dependency beyond `react`, `react-dom`
and `zod`, or before touching `scripts/reproduce.sh`.
