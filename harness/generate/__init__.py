"""The generator: two Kaggle datasets in, one frozen corpus out.

Nothing about the kernel changes in P8. The nine checks, the seven oracles and
the seed rule are the same ones the hand-written corpus measured. What is new
is the thing that produces the corpus, and a generator is exactly the kind of
component that can produce a plausible number from a mistake — so every step of
it is pinned, counted and hashed:

* the datasets are pinned by slug **and version** and verified by digest before
  a row is read (:mod:`harness.datasets`);
* every row the generator refuses is counted by reason and the counts are
  published, so "we dropped what we could not classify" is a figure rather than
  a silent filter;
* the whole output is hashed into one line
  (:mod:`harness.generate.manifest`) and every generated table quotes it.

**What the generated corpus is a weaker claim about than the hand-written one.**
Three things, and they are stated here as well as in ``results.md`` because a
caveat that lives only in the write-up is a caveat that gets dropped when
somebody quotes the table:

1. **Placement is templated.** A payload's injection point is chosen by a rule
   in :mod:`harness.generate.attacks`, from the points the target task actually
   reads. An attacker would choose; we rotate.
2. **The generator could have been tuned against ``gen-a``.** ``gen-b`` is held
   out under the same single-open guard batch B has, and one logged opening is
   weaker than a corpus nobody could have tuned against.
3. **The injection corpus was written against chatbots, not against a payment
   rail.** It contains persuasion, jailbreaks and formatting tricks; it
   contains almost no instruction to pay anybody. So a generated payload is two
   parts — a **carrier** taken verbatim from the corpus and one **directive**
   line of ours that carries the class's operative parameter — and the split is
   recorded on every case. The evasion is theirs. The payment instruction is
   ours, because there was none to take.
"""

from __future__ import annotations

__all__ = ["GENERATOR_VERSION"]

#: Bumped whenever a change here would produce a different corpus from the same
#: datasets and the same seed. It goes in the generated manifest, so a corpus
#: hash is a statement about the generator as well as about its input.
GENERATOR_VERSION = "p8.1"
