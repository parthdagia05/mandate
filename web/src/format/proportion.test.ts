/**
 * Formatter tests (#91), and one test about the module's shape rather than its
 * output: that there is no way to render a bare point estimate.
 */
import { describe, expect, it } from 'vitest'
import * as proportion from './proportion'
import { formatMicros, formatProportion, proportionLabel, proportionParts } from './proportion'
import type { Proportion } from '../api/schemas'

const p = (
  k: number,
  n: number,
  lo: number,
  hi: number,
  label = 'targeted ASR',
): Proportion => ({ label, k, n, p: n === 0 ? 0 : k / n, ci95: [lo, hi] })

describe('formatProportion', () => {
  it('renders the estimate, the interval and the counts together', () => {
    // The exact string results.md prints for the undefended arm on batch A.
    expect(formatProportion(p(84, 105, 0.7135226289709666, 0.8653009248715675))).toBe(
      '80.0% [71.4–86.5] (84/105)',
    )
  })

  it('never prints a zero-width interval at the edges', () => {
    // 0/15 is not "zero percent"; it is "below 20.4%, at 95% confidence". A
    // kernel arm sitting at this edge is the single most likely place for the
    // page to overclaim.
    expect(formatProportion(p(0, 15, 0.0, 0.20388330103584862, 'A1 ASR'))).toBe(
      '0.0% [0.0–20.4] (0/15)',
    )
    expect(formatProportion(p(15, 15, 0.796, 1.0, 'A1 ASR'))).toBe(
      '100.0% [79.6–100.0] (15/15)',
    )
  })

  it('renders a floating-point interval bound that is not quite zero as 0.0', () => {
    // Wilson at k=0 returns 1.39e-17 rather than 0.0 in float arithmetic, and
    // results.md prints `0.0`. The page must agree with the document.
    expect(formatProportion(p(0, 25, 1.3877787807814457e-17, 0.13319225093904846))).toBe(
      '0.0% [0.0–13.3] (0/25)',
    )
  })

  it('says n/a rather than 0.0% when there are no observations', () => {
    // With no observations the honest interval is the whole line. Printing
    // "0.0%" for n=0 would make an empty column look like a perfect defence —
    // the failure mode the whole harness is arranged to avoid.
    expect(formatProportion(p(0, 0, 0, 1))).toBe('n/a (n=0)')
    expect(proportionParts(p(0, 0, 0, 1))).toBeNull()
  })

  it('uses an en dash in the interval and a slash in the counts, like cell()', () => {
    const rendered = formatProportion(p(3, 25, 0.042, 0.3, 'false block rate'))
    expect(rendered).toBe('12.0% [4.2–30.0] (3/25)')
    expect(rendered).toContain('–') // en dash, not a hyphen
    expect(rendered).not.toContain('--')
  })

  it('keeps the three parts separable but never optional', () => {
    const parts = proportionParts(p(84, 105, 0.7135226289709666, 0.8653009248715675))
    expect(parts).toEqual({
      estimate: '80.0%',
      interval: '[71.4–86.5]',
      counts: '(84/105)',
    })
  })

  it('labels a bar with the interval and the n, because charts are not exempt', () => {
    expect(proportionLabel(p(0, 105, 0, 0.035, 'targeted ASR'))).toBe(
      'targeted ASR: 0.0% [0.0–3.5] (0/105)',
    )
  })
})

describe('the module offers no way to print an estimate alone', () => {
  it('exports no function that renders a bare percentage', () => {
    // Mirrors harness/metrics.py: `Proportion` has no method that renders the
    // estimate alone. If someone adds `formatEstimate` or exports `pct`, this
    // fails — which is the point. The check is on the module's surface rather
    // than on a convention nobody re-reads.
    expect(Object.keys(proportion).sort()).toEqual([
      'formatMicros',
      'formatProportion',
      'proportionLabel',
      'proportionParts',
    ])
  })

  it('every rendering of a non-empty proportion carries its counts', () => {
    const sample = p(12, 15, 0.548, 0.93, 'A1 ASR')
    const renderings = [formatProportion(sample), proportionLabel(sample)]
    for (const rendering of renderings) {
      expect(rendering).toMatch(/\(\d+\/\d+\)/)
      expect(rendering).toMatch(/\[[\d.]+–[\d.]+\]/)
    }
  })
})

describe('formatMicros', () => {
  it('renders a delta in milliseconds with its sign', () => {
    expect(formatMicros(2311)).toBe('+2.31 ms')
    expect(formatMicros(-40)).toBe('-0.04 ms')
    expect(formatMicros(0)).toBe('0.00 ms')
  })
})
