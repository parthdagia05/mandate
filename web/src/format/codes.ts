/**
 * Reason codes, actions and outcomes — rendered in the kernel's own casing.
 *
 * Issue #84: "reason codes in the exact casing the kernel emits". So
 * `PAYEE_NOT_ALLOWED` appears as `PAYEE_NOT_ALLOWED`, never "Payee not allowed"
 * and never "Payment blocked". Shot 5 turns on that distinction: "it did not say
 * this looks suspicious. It said this payee is not the one in the sentence you
 * signed." A gloss may sit beside the code; it never replaces it.
 */
import type { Outcome } from '../api/schemas'

/** What each outcome is called on screen. Five, not two (#86). */
const OUTCOME_LABEL: Record<Outcome, string> = {
  attacker_win: 'attacker win',
  blocked: 'blocked',
  task_success: 'task success',
  // Discarded, never "defended". The record carries `poisoned` precisely so a
  // kernel whose own chain did not verify cannot be counted as a win.
  poisoned: 'discarded — poisoned',
  error: 'error',
  no_result: 'no result',
}

export function outcomeLabel(outcome: Outcome): string {
  return OUTCOME_LABEL[outcome]
}

/**
 * A one-line gloss, shown beside a code and never instead of it. Only for the
 * codes the pages actually surface; an unknown code renders bare, which is
 * correct — inventing a description for a code nobody wrote is worse than
 * showing the code alone.
 */
const GLOSS: Record<string, string> = {
  PAYEE_NOT_ALLOWED: 'this payee is not the one in the signed sentence',
  AMOUNT_EXCEEDS_SCOPE: 'above the cap the human signed',
  CART_HASH_MISMATCH: 'the cart is not the cart that was confirmed',
  LINE_ITEM_SUM_MISMATCH: 'the line items do not add up to the total',
  CURRENCY_MISMATCH: 'not the currency in the intent',
  RECURRENCE_NOT_AUTHORISED: 'the intent authorised no repeat charge',
  BUDGET_EXHAUSTED: 'the intent has no executions left',
  REFUND_DESTINATION_MISMATCH: "not the payment's recorded source",
  MANDATE_EXPIRED: 'the authority had expired',
  NONCE_REPLAYED: 'this nonce has been seen',
  SIG_INVALID: 'the signature does not verify',
  TAINT_VIOLATION: 'a merchant-derived value reached a restricted field',
  IDEMPOTENT_REPLAY: 'already settled under this key',
  STORE_UNAVAILABLE: 'a store was unreachable, so the kernel failed closed',
  OK: 'allowed',
}

export function codeGloss(code: string): string | null {
  return GLOSS[code] ?? null
}

export function isAllow(code: string): boolean {
  return code === 'OK'
}
