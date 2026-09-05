/**
 * The step alignment behind the compare view. Issue #87.
 *
 * Pure, and separated from the component because this is the part that can be
 * wrong in a way nobody notices: the claim on screen is "the two runs agree,
 * step for step, until *here*", and a diff that picked the wrong `here` would
 * be a confident, specific lie.
 *
 * No statistics. Two recorded plans in, an aligned list and an index out.
 */
import type { PlanStep } from '../api/schemas'

export interface Aligned {
  readonly index: number
  readonly leftStep: string | null
  readonly rightStep: string | null
  readonly leftOutput: string
  readonly rightOutput: string
  readonly same: boolean
}

/**
 * Align two plans by position, comparing step name and recorded output.
 *
 * By position rather than by a longest-common-subsequence: the two runs come
 * from one seed and one planner, so step *n* on the left is step *n* on the
 * right by construction. An LCS would quietly re-align a plan that had gained a
 * step and hide the fact that it had — and a plan that gained a step is exactly
 * the kind of divergence worth seeing.
 */
export function align(left: readonly PlanStep[], right: readonly PlanStep[]): Aligned[] {
  const rows: Aligned[] = []
  const count = Math.max(left.length, right.length)
  for (let index = 0; index < count; index += 1) {
    const l = left[index]
    const r = right[index]
    const leftOutput = JSON.stringify(l?.output ?? null)
    const rightOutput = JSON.stringify(r?.output ?? null)
    rows.push({
      index,
      leftStep: l?.step ?? null,
      rightStep: r?.step ?? null,
      leftOutput,
      rightOutput,
      // A step present on one side only is a divergence, not a match against
      // `undefined`.
      same: l !== undefined && r !== undefined && l.step === r.step && leftOutput === rightOutput,
    })
  }
  return rows
}

/** The first index where the two disagree, or `null` if they never do. */
export function firstDivergence(rows: readonly Aligned[]): number | null {
  const found = rows.find((row) => !row.same)
  return found === undefined ? null : found.index
}
