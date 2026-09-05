---
description: Run the frontend-architecture invariant checks over web/ and report violations.
allowed-tools: Bash(python3:*), Read
---

Run the mechanical invariant checks over the web layer:

!`python3 "${CLAUDE_PLUGIN_ROOT}/hooks/check_web_invariants.py" $ARGUMENTS`

Report what came back. For each violation, give the file and line, the invariant
it breaks, and the smallest fix that satisfies it — not a rewrite of the
surrounding component. If the output is clean, say so and say how many files
were checked.

If there are no sources under `web/` yet, say that the web layer has not been
scaffolded and point at the `frontend-architecture` skill for the layout to
create.
