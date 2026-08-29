# Benign tasks

Four of the twenty-five. The other twenty-one arrive in M5; breadth is that
milestone's job, and M2 only needed the money to move correctly at all.

Each task is the *user's* half of a run: what they said, what they wanted, and
what the ledger should show afterwards. Nothing here describes an attack — an
attack is a separate file that names an injection point, so the same task can be
run clean and run under attack with nothing else changed. That is what makes the
two runs comparable.

`benign-01` carries `mandates`, pointing at the signed intent and cart shipped in
`fixtures/`. The undefended configuration never reads them: it has no kernel, so
there is nothing for a mandate to authorise. M3 needs them, and they are named
here so that the task, not the runner, decides which authority a run is under.

`benign-02` and `benign-03` have `mandates: null` until M3 signs a pair for each.
Rebuilding fixtures re-signs everything and moves the published manifest hash
(`scripts/build_fixtures.py --force`), so it happens once, when the kernel path
needs it — not three times because it was convenient.

`benign-03` is priced at ₹809, above the shipped intent's ₹600 per-transaction
cap. That is on purpose: a false-block rate measured against tasks that all fit
comfortably inside the scope is a zero that means nothing.

`benign-04` is `benign-01`'s purchase followed by the user asking for their
money back, and it reuses `benign-01`'s mandates and cart on purpose. A7 has to
be reachable from an authority the user really granted: a refund of a purchase
that was never authorised would be refused by check 8 for the wrong reason, and
the case would pass while measuring nothing. It is the only task with a
`refund` block, so the plain-purchase tasks still run the original five planner
steps unchanged and A1's numbers are not measured against a different agent.
