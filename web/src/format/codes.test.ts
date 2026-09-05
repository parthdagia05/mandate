import { describe, expect, it } from 'vitest'
import { codeGloss, isAllow, outcomeLabel } from './codes'
import { Outcome } from '../api/schemas'

describe('reason codes', () => {
  it('are never rewritten — the gloss is separate from the code', () => {
    // #84: "reason codes in the exact casing the kernel emits". The gloss is a
    // second string a component may show beside the code, never in place of it.
    expect(codeGloss('PAYEE_NOT_ALLOWED')).toBe(
      'this payee is not the one in the signed sentence',
    )
    expect(codeGloss('AMOUNT_EXCEEDS_SCOPE')).toBe('above the cap the human signed')
  })

  it('return no gloss for a code nobody wrote, rather than inventing one', () => {
    expect(codeGloss('NOT_A_REAL_CODE')).toBeNull()
  })

  it('distinguish an allow from a denial', () => {
    expect(isAllow('OK')).toBe(true)
    expect(isAllow('PAYEE_NOT_ALLOWED')).toBe(false)
  })
})

describe('outcomes', () => {
  it('label all five, plus no_result', () => {
    for (const outcome of Outcome.options) {
      expect(outcomeLabel(outcome)).toBeTruthy()
    }
  })

  it('call a poisoned run discarded and never defended', () => {
    // A poisoned run is one whose own chain did not verify. Counting it as a
    // defence would be the most flattering possible bug.
    const label = outcomeLabel('poisoned')
    expect(label).toContain('discarded')
    expect(label).not.toContain('defend')
    expect(label).not.toContain('blocked')
  })

  it('call an errored run an error and not a zero', () => {
    expect(outcomeLabel('error')).toBe('error')
  })
})
