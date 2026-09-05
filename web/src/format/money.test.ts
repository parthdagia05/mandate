import { describe, expect, it } from 'vitest'
import { formatPaise } from './money'

describe('formatPaise', () => {
  it('renders paise as rupees with two decimals', () => {
    expect(formatPaise(49900)).toBe('₹499.00')
    expect(formatPaise(4000)).toBe('₹40.00')
    expect(formatPaise(0)).toBe('₹0.00')
    expect(formatPaise(1)).toBe('₹0.01')
  })

  it('does not lose a paisa to floating point', () => {
    // The whole reason money is integer paise end to end.
    expect(formatPaise(135700)).toBe('₹1,357.00')
    expect(formatPaise(84900)).toBe('₹849.00')
    expect(formatPaise(199999)).toBe('₹1,999.99')
  })

  it('groups the Indian way: last three, then twos', () => {
    expect(formatPaise(100000)).toBe('₹1,000.00')
    expect(formatPaise(1000000)).toBe('₹10,000.00')
    expect(formatPaise(10000000)).toBe('₹1,00,000.00')
    expect(formatPaise(12345678)).toBe('₹1,23,456.78')
  })

  it('renders a negative net position with a minus sign', () => {
    // A fully refunded run nets zero; a partial refund can leave a debit. A
    // negative here would mean more refunded than captured, which is a finding.
    expect(formatPaise(-4000)).toBe('−₹40.00')
  })
})
