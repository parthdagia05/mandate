import { describe, expect, it } from 'vitest'
import { align, firstDivergence } from './diff'
import type { PlanStep } from '../api/schemas'

const step = (name: string, output: unknown): PlanStep => ({ step: name, output })

/** The A1 plan: choose a product, build a cart, choose who to pay. */
const clean: PlanStep[] = [
  step('choose_product', { sku: 'SK-CABLE-USBC' }),
  step('build_cart', { line_items: [{ sku: 'SK-CABLE-USBC', qty: 2, unit_amount: 2000 }] }),
  step('choose_payee', { payee: { type: 'vpa', value: 'merchant@upi' } }),
]

describe('align', () => {
  it('finds no divergence between two identical plans', () => {
    const rows = align(clean, clean)
    expect(rows.every((row) => row.same)).toBe(true)
    expect(firstDivergence(rows)).toBeNull()
  })

  it('marks the step where the agent was redirected, and not an earlier one', () => {
    // This is Shot 5. The two runs agree on the product and the cart, and part
    // company at the payee — the third step, index 2.
    const redirected: PlanStep[] = [
      clean[0]!,
      clean[1]!,
      step('choose_payee', {
        payee: { type: 'vpa', value: 'shopkart-nodal-01@upi' },
        why: 'the page said to',
      }),
    ]
    const rows = align(clean, redirected)
    expect(firstDivergence(rows)).toBe(2)
    expect(rows[0]!.same).toBe(true)
    expect(rows[1]!.same).toBe(true)
    expect(rows[2]!.same).toBe(false)
  })

  it('treats a step present on one side only as a divergence', () => {
    // A plan that gained a step is exactly the divergence worth seeing, so it
    // must not align away.
    const longer = [...clean, step('confirm', { ok: true })]
    const rows = align(clean, longer)
    expect(rows).toHaveLength(4)
    expect(firstDivergence(rows)).toBe(3)
    expect(rows[3]!.leftStep).toBeNull()
    expect(rows[3]!.rightStep).toBe('confirm')
  })

  it('does not align by name across a differing position', () => {
    // Reordered steps are a divergence at the first position that moved, not a
    // clean match found by searching for the name elsewhere.
    const reordered = [clean[1]!, clean[0]!, clean[2]!]
    expect(firstDivergence(align(clean, reordered))).toBe(0)
  })

  it('compares outputs structurally, not by reference', () => {
    const copy = clean.map((s) => ({ step: s.step, output: JSON.parse(JSON.stringify(s.output)) as unknown }))
    expect(firstDivergence(align(clean, copy))).toBeNull()
  })

  it('handles an empty plan on either side', () => {
    expect(align([], [])).toEqual([])
    expect(firstDivergence(align([], clean))).toBe(0)
    expect(firstDivergence(align(clean, []))).toBe(0)
  })
})
