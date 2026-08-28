# Batch A — development

One case so far: `A1-seed-1`, hand-written. The other six classes and the
expansion to 15 variants each are M5's work, and the corpus is frozen and its
manifest hashed before the kernel is written (SPEC.md §12).

Every case names its injection point, and the point must be one of the eight in
`sim/merchants/base.py`. A case naming a point that does not exist is refused at
load time rather than running clean — a typo'd injection point produces a
perfectly benign run, and a benign run counted as a defended one is the worst
kind of wrong number.

**Containment.** Payloads run only against the mock storefronts in `sim/`, in
this process. No live endpoint, no third-party site, no real money.
