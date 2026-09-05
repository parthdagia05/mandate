# mandate-web

Frontend architecture for the Mandate web layer — issues #85–#90, the pages the
five-minute cut in [docs/VIDEO.md](../../docs/VIDEO.md) is recorded against.

## Install

From the repository root, in an interactive Claude Code session:

```
/plugin marketplace add .
/plugin install mandate-web@mandate
```

Then `/plugin` to confirm it is enabled. The marketplace manifest is
[.claude-plugin/marketplace.json](../../.claude-plugin/marketplace.json).

## What it provides

| Component | Name | What it does |
|-----------|------|--------------|
| Skill | `frontend-architecture` | The export contract, the layer boundaries, the ten invariants, and a definition of done per page. Loads on any work under `web/`. |
| Agent | `web-reviewer` | Reviews the web layer for claims the data does not support — recomputed proportions, dropped caveats, glossed reason codes, decorative chain verification. |
| Hook | `PostToolUse` | Runs `hooks/check_web_invariants.py` on every Write/Edit under `web/`. Fourteen textual rules, each mapped to a numbered invariant. |
| Command | `/web-check` | The same checks over the whole tree, on demand. |
| Command | `/web-page` | Scaffolds or extends one page against the architecture, outwards through the layers. |

## The stack it prescribes

Vite + React + TypeScript over a frozen JSON export of `runs/`. Runtime
dependencies: `react`, `react-dom`, `zod` — nothing else. No chart library, no
component kit, no state manager, no date library, no CDN asset. The export is
Python and stdlib only, so `npm` never appears on the path
`scripts/reproduce.sh` takes.

## The one sentence

`results.md` prints no proportion without its interval and its `n`, and
[harness/metrics.py](../../harness/metrics.py) makes that structural rather than
a habit — `Proportion` has no method that renders the estimate alone. This
plugin carries the same property into the browser, and the hook is what keeps it
true after the tenth component.

## Checking the hook itself

```
python3 plugins/mandate-web/hooks/check_web_invariants.py [paths...]
```

Exit 0 clean, 2 on violations. With no arguments it walks `web/src` and
`web/public`. A genuine exception is silenced per line with
`// invariant-ok: <reason>`, and the reviewer agent treats every suppression as
a claim to be judged rather than as settled.
