/**
 * A proportion, rendered the only way this app renders one.
 *
 * `harness/metrics.py` makes the rule structural on the Python side:
 * "`Proportion` has no method that renders the estimate alone, and that is the
 * point — a point estimate on n of 15 is not a fact, so the type does not offer
 * a way to print one." This module mirrors that exactly. `pct` is not exported.
 * There is no `formatEstimate`. Every caller gets the estimate, the interval and
 * the counts, together, or nothing.
 *
 * Issue #85: "an interval is rendered as an interval. No bare point estimate
 * anywhere on the page, because the point estimate on n of 15 is the exact thing
 * results.md refuses to print alone."
 *
 * The output matches `Proportion.cell()` character for character — an en dash in
 * the interval, a slash in the counts — so a page and `results.md` can be
 * diffed by eye. Nothing here computes a proportion: `p` and `ci95` arrive from
 * `harness.metrics` and are only ever multiplied by 100 for display (#91).
 */
import type { Proportion } from '../api/schemas'

/** Not exported. The whole design rests on that. */
function pct(value: number): string {
  return (100 * value).toFixed(1)
}

/** `80.0% [71.4–86.5] (84/105)`, or `n/a (n=0)`. */
export function formatProportion(x: Proportion): string {
  if (x.n === 0) return 'n/a (n=0)'
  return `${pct(x.p)}% [${pct(x.ci95[0])}–${pct(x.ci95[1])}] (${x.k}/${x.n})`
}

/**
 * The same three parts, kept separate so a table can dim the interval and the
 * counts without ever dropping them.
 *
 * `estimate` is not usable on its own: it carries no `%` and the other two
 * fields are non-optional, so a component cannot render one without the rest
 * without visibly reaching past this type.
 */
export interface ProportionParts {
  readonly estimate: string
  readonly interval: string
  readonly counts: string
}

export function proportionParts(x: Proportion): ProportionParts | null {
  if (x.n === 0) return null
  return {
    estimate: `${pct(x.p)}%`,
    interval: `[${pct(x.ci95[0])}–${pct(x.ci95[1])}]`,
    counts: `(${x.k}/${x.n})`,
  }
}

/**
 * What a bar's accessible label says. Charts are not exempt from the rule, so a
 * bar announces the interval and the n like every other rendering does.
 */
export function proportionLabel(x: Proportion): string {
  return `${x.label}: ${formatProportion(x)}`
}

/** Microseconds as milliseconds, for the overhead column. A duration, not a proportion. */
export function formatMicros(us: number): string {
  const sign = us > 0 ? '+' : ''
  return `${sign}${(us / 1000).toFixed(2)} ms`
}
