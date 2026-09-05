/**
 * Money. The only place in the app that divides by 100.
 *
 * The ledger is integer paise from the PSP simulator out, and it stays integer
 * paise through the API and through every component. A float in the display path
 * is how ₹1357.00 becomes ₹1356.99 in a shot nobody re-records.
 *
 * `formatPaise` is display only: no component sums, scales or compares rupees.
 * Where a total is needed the API carries it, computed once.
 */

/** `4000` -> `₹40.00`. Always two decimals, always grouped, never rounded away. */
export function formatPaise(paise: number): string {
  const negative = paise < 0
  const absolute = Math.abs(Math.trunc(paise))
  const rupees = Math.trunc(absolute / 100)
  const fraction = absolute % 100
  const grouped = groupIndian(rupees)
  return `${negative ? '−' : ''}₹${grouped}.${String(fraction).padStart(2, '0')}`
}

/**
 * Indian digit grouping: last three, then twos. `135700` paise is `₹1,357.00`
 * and `12345678` paise is `₹1,23,456.78`.
 *
 * Done by hand rather than with `Intl.NumberFormat` because the output must not
 * depend on the viewer's locale — a screenshot taken on a machine with a
 * different default would disagree with `results.md`, and every figure in this
 * project is in INR by construction (`CURRENCY_MISMATCH` is a reason code).
 */
function groupIndian(rupees: number): string {
  const digits = String(rupees)
  if (digits.length <= 3) return digits
  const last3 = digits.slice(-3)
  const rest = digits.slice(0, -3)
  const pairs = rest.replace(/\B(?=(\d{2})+(?!\d))/g, ',')
  return `${pairs},${last3}`
}
